"""Healthcare Access List Manager (hACL).

hACL validates and applies approved IPv4 allow-list changes using recoverable,
atomic file updates and a structured JSON Lines audit trail.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import sys
import tempfile
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

ALLOW_LIST_PATH = DATA_DIR / "allow_list.txt"
REMOVE_LIST_PATH = DATA_DIR / "remove_list.txt"
ADD_LIST_PATH = DATA_DIR / "add_list.txt"
AUDIT_LOG_PATH = DATA_DIR / "audit_log.jsonl"


class HACLError(Exception):
    """Base exception for hACL failures."""


class InputFileError(HACLError):
    """Raised when an input file cannot be read safely."""


class PersistenceError(HACLError):
    """Raised when hACL cannot persist a consistent transaction."""


class ConflictingRequestError(HACLError):
    """Raised when the same IP is requested for addition and removal."""


@dataclass(frozen=True)
class DuplicateCounts:
    """Duplicate entries removed from each source list."""

    allow: int = 0
    remove: int = 0
    add: int = 0

    @property
    def total(self) -> int:
        return self.allow + self.remove + self.add


@dataclass(frozen=True)
class InvalidEntries:
    """Invalid entries grouped by their source file."""

    allow: tuple[str, ...] = ()
    remove: tuple[str, ...] = ()
    add: tuple[str, ...] = ()

    @property
    def total(self) -> int:
        return len(self.allow) + len(self.remove) + len(self.add)


@dataclass(frozen=True)
class UpdateResult:
    """Structured result returned by the hACL update workflow."""

    original_count: int
    final_count: int
    final_allow_list: tuple[str, ...]
    removed_ips: tuple[str, ...]
    added_ips: tuple[str, ...]
    not_found_removals: tuple[str, ...]
    already_present_additions: tuple[str, ...]
    invalid_entries: InvalidEntries
    duplicate_counts: DuplicateCounts
    allow_list_cleaned: bool
    changed: bool
    before_sha256: str = ""
    after_sha256: str = ""
    audit_event_id: str | None = None
    audit_written: bool = False

    @property
    def has_audit_activity(self) -> bool:
        return any(
            (
                self.changed,
                self.not_found_removals,
                self.already_present_additions,
                self.invalid_entries.total,
                self.duplicate_counts.total,
            )
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "original_count": self.original_count,
            "final_count": self.final_count,
            "final_allow_list": list(self.final_allow_list),
            "removed_ips": list(self.removed_ips),
            "added_ips": list(self.added_ips),
            "not_found_removals": list(self.not_found_removals),
            "already_present_additions": list(
                self.already_present_additions
            ),
            "invalid_entries": {
                "allow": list(self.invalid_entries.allow),
                "remove": list(self.invalid_entries.remove),
                "add": list(self.invalid_entries.add),
                "total": self.invalid_entries.total,
            },
            "duplicate_counts": {
                "allow": self.duplicate_counts.allow,
                "remove": self.duplicate_counts.remove,
                "add": self.duplicate_counts.add,
                "total": self.duplicate_counts.total,
            },
            "allow_list_cleaned": self.allow_list_cleaned,
            "changed": self.changed,
            "before_sha256": self.before_sha256,
            "after_sha256": self.after_sha256,
            "audit_event_id": self.audit_event_id,
            "audit_written": self.audit_written,
        }


def _read_text(file_path: str | Path) -> str:
    path = Path(file_path)
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise InputFileError(f"Required file does not exist: {path}") from exc
    except UnicodeDecodeError as exc:
        raise InputFileError(f"File is not valid UTF-8: {path}") from exc
    except OSError as exc:
        raise InputFileError(f"Unable to read {path}: {exc}") from exc


def read_file(file_path: str | Path) -> list[str]:
    """Read whitespace-separated entries from a UTF-8 file."""

    return _read_text(file_path).split()


def _stage_text(file_path: str | Path, text: str) -> Path:
    """Write and fsync a temporary file in the destination directory."""

    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_name = handle.name
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        assert temp_name is not None
        return Path(temp_name)
    except OSError as exc:
        if temp_name is not None:
            Path(temp_name).unlink(missing_ok=True)
        raise PersistenceError(f"Unable to stage write for {path}: {exc}") from exc


def _atomic_write_text(file_path: str | Path, text: str) -> None:
    """Atomically replace a text file with fully written content."""

    path = Path(file_path)
    staged = _stage_text(path, text)
    try:
        os.replace(staged, path)
    except OSError as exc:
        staged.unlink(missing_ok=True)
        raise PersistenceError(f"Unable to replace {path}: {exc}") from exc


def write_file(file_path: str | Path, updated_list: Sequence[str]) -> None:
    """Write one entry per line using atomic replacement."""

    text = "\n".join(updated_list)
    if text:
        text += "\n"
    _atomic_write_text(file_path, text)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def validate_ip_list(ip_list: Sequence[str]) -> tuple[list[str], list[str]]:
    """Return canonical IPv4 addresses and rejected entries.

    Python's standard-library IPv4Address parser is intentionally used so
    malformed, out-of-range, IPv6, CIDR, and ambiguous leading-zero values are
    rejected consistently.
    """

    valid_ips: list[str] = []
    invalid_ips: list[str] = []

    for raw_ip in ip_list:
        candidate = raw_ip.strip()
        if not candidate:
            continue
        try:
            valid_ips.append(str(ipaddress.IPv4Address(candidate)))
        except ipaddress.AddressValueError:
            invalid_ips.append(candidate)

    return valid_ips, invalid_ips


def remove_duplicate(ip_list: Sequence[str]) -> tuple[list[str], int]:
    """Remove duplicates while preserving first-seen order."""

    unique_ips = list(dict.fromkeys(ip_list))
    return unique_ips, len(ip_list) - len(unique_ips)


def prepare_update(
    original_allow_list: Sequence[str],
    remove_list: Sequence[str],
    add_list: Sequence[str],
) -> UpdateResult:
    """Validate inputs and calculate an update without writing files."""

    valid_allow, invalid_allow = validate_ip_list(original_allow_list)
    valid_remove, invalid_remove = validate_ip_list(remove_list)
    valid_add, invalid_add = validate_ip_list(add_list)

    clean_allow, allow_duplicates = remove_duplicate(valid_allow)
    clean_remove, remove_duplicates = remove_duplicate(valid_remove)
    clean_add, add_duplicates = remove_duplicate(valid_add)

    conflicts = sorted(set(clean_remove).intersection(clean_add))
    if conflicts:
        conflict_text = ", ".join(conflicts)
        raise ConflictingRequestError(
            "The same IP cannot be approved for addition and removal in one "
            f"transaction: {conflict_text}"
        )

    current_allow = list(clean_allow)
    current_set = set(current_allow)

    removed_ips: list[str] = []
    not_found_removals: list[str] = []
    for ip in clean_remove:
        if ip in current_set:
            current_set.remove(ip)
            removed_ips.append(ip)
        else:
            not_found_removals.append(ip)

    current_allow = [ip for ip in current_allow if ip in current_set]

    added_ips: list[str] = []
    already_present_additions: list[str] = []
    for ip in clean_add:
        if ip in current_set:
            already_present_additions.append(ip)
        else:
            current_allow.append(ip)
            current_set.add(ip)
            added_ips.append(ip)

    original_entries = list(original_allow_list)
    invalid_entries = InvalidEntries(
        allow=tuple(invalid_allow),
        remove=tuple(invalid_remove),
        add=tuple(invalid_add),
    )
    duplicate_counts = DuplicateCounts(
        allow=allow_duplicates,
        remove=remove_duplicates,
        add=add_duplicates,
    )

    return UpdateResult(
        original_count=len(original_entries),
        final_count=len(current_allow),
        final_allow_list=tuple(current_allow),
        removed_ips=tuple(removed_ips),
        added_ips=tuple(added_ips),
        not_found_removals=tuple(not_found_removals),
        already_present_additions=tuple(already_present_additions),
        invalid_entries=invalid_entries,
        duplicate_counts=duplicate_counts,
        allow_list_cleaned=clean_allow != original_entries,
        changed=current_allow != original_entries,
    )


def _load_audit_events(audit_path: Path) -> list[dict[str, object]]:
    if not audit_path.exists():
        return []

    text = _read_text(audit_path)
    events: list[dict[str, object]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            raw_event: object = json.loads(line)
        except json.JSONDecodeError as exc:
            raise PersistenceError(
                f"Audit log contains invalid JSON at line {line_number}: "
                f"{audit_path}"
            ) from exc
        if not isinstance(raw_event, dict):
            raise PersistenceError(
                f"Audit log line {line_number} is not a JSON object: {audit_path}"
            )
        event = {str(key): value for key, value in raw_event.items()}
        events.append(event)
    return events


def _write_audit_events(
    audit_path: Path, events: Sequence[dict[str, object]]
) -> None:
    text = "".join(
        json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
        for event in events
    )
    _atomic_write_text(audit_path, text)


def recover_incomplete_transaction(
    allow_path: str | Path, audit_path: str | Path
) -> str | None:
    """Resolve a final prepared audit event using the current allow-list hash.

    Returns the recovery status when recovery occurred, otherwise ``None``.
    """

    allow_file = Path(allow_path)
    audit_file = Path(audit_path)
    events = _load_audit_events(audit_file)
    if not events:
        return None

    event = events[-1]
    if event.get("status") != "prepared":
        return None

    current_hash = _sha256_text(_read_text(allow_file))
    before_hash = event.get("before_sha256")
    after_hash = event.get("after_sha256")

    recovered_at = datetime.now(UTC).isoformat()

    if current_hash == after_hash:
        event["status"] = "committed_recovered"
        event["recovered_at"] = recovered_at
        recovery_status = "committed_recovered"
    elif current_hash == before_hash:
        event["status"] = "aborted_recovered"
        event["recovered_at"] = recovered_at
        recovery_status = "aborted_recovered"
    else:
        raise PersistenceError(
            "The last audit transaction is still prepared, but the current "
            "allow-list hash matches neither its before nor after state. "
            "Manual review is required."
        )

    events[-1] = event
    _write_audit_events(audit_file, events)
    return recovery_status


def _build_audit_event(
    result: UpdateResult,
    allow_path: Path,
    remove_path: Path,
    add_path: Path | None,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "event_id": result.audit_event_id,
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "status": "prepared",
        "files": {
            "allow": allow_path.name,
            "remove": remove_path.name,
            "add": add_path.name if add_path is not None else None,
        },
        "before_sha256": result.before_sha256,
        "after_sha256": result.after_sha256,
        "original_count": result.original_count,
        "final_count": result.final_count,
        "changed": result.changed,
        "allow_list_cleaned": result.allow_list_cleaned,
        "removed_ips": list(result.removed_ips),
        "added_ips": list(result.added_ips),
        "not_found_removals": list(result.not_found_removals),
        "already_present_additions": list(result.already_present_additions),
        "invalid_entries": {
            "allow": list(result.invalid_entries.allow),
            "remove": list(result.invalid_entries.remove),
            "add": list(result.invalid_entries.add),
        },
        "duplicate_counts": {
            "allow": result.duplicate_counts.allow,
            "remove": result.duplicate_counts.remove,
            "add": result.duplicate_counts.add,
            "total": result.duplicate_counts.total,
        },
    }


def update_allow_list(
    allow_file: str | Path,
    remove_file: str | Path,
    add_file: str | Path | None = None,
    audit_file: str | Path | None = None,
) -> UpdateResult:
    """Apply one recoverable allow-list transaction and return its result."""

    allow_path = Path(allow_file)
    remove_path = Path(remove_file)
    add_path = Path(add_file) if add_file is not None else None
    audit_path = Path(audit_file) if audit_file is not None else AUDIT_LOG_PATH

    # A prior process interruption can leave a prepared event. Resolve it
    # before calculating a new transaction.
    recover_incomplete_transaction(allow_path, audit_path)

    original_text = _read_text(allow_path)
    remove_text = _read_text(remove_path)
    add_text = _read_text(add_path) if add_path is not None else ""

    result = prepare_update(
        original_text.split(),
        remove_text.split(),
        add_text.split(),
    )

    updated_text = "\n".join(result.final_allow_list)
    if updated_text:
        updated_text += "\n"

    result = replace(
        result,
        before_sha256=_sha256_text(original_text),
        after_sha256=_sha256_text(updated_text),
    )

    if not result.has_audit_activity:
        return result

    event_id = str(uuid.uuid4())
    result = replace(result, audit_event_id=event_id)

    events = _load_audit_events(audit_path)
    event = _build_audit_event(result, allow_path, remove_path, add_path)
    events.append(event)

    # The prepared event is written first. If the process stops after this
    # point, the next run can determine whether the allow-list replacement
    # occurred by comparing hashes.
    _write_audit_events(audit_path, events)

    try:
        if result.changed:
            _atomic_write_text(allow_path, updated_text)
    except PersistenceError:
        event["status"] = "aborted"
        event["completed_at"] = datetime.now(UTC).isoformat()
        events[-1] = event
        _write_audit_events(audit_path, events)
        raise

    event["status"] = "committed"
    event["completed_at"] = datetime.now(UTC).isoformat()
    events[-1] = event
    _write_audit_events(audit_path, events)

    return replace(result, audit_written=True)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate and apply approved IPv4 allow-list additions and removals."
        )
    )
    parser.add_argument("--allow", type=Path, default=ALLOW_LIST_PATH)
    parser.add_argument("--remove", type=Path, default=REMOVE_LIST_PATH)
    parser.add_argument("--add", dest="add_file", type=Path, default=ADD_LIST_PATH)
    parser.add_argument("--audit", type=Path, default=AUDIT_LOG_PATH)
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the structured result as JSON.",
    )
    return parser


def _print_summary(result: UpdateResult) -> None:
    print(f"Original allow-list count: {result.original_count}")
    print(f"Final allow-list count: {result.final_count}")
    print(f"Removed: {len(result.removed_ips)}")
    print(f"Added: {len(result.added_ips)}")
    print(f"Removal requests not found: {len(result.not_found_removals)}")
    print(
        "Addition requests already present: "
        f"{len(result.already_present_additions)}"
    )
    print(f"Invalid entries: {result.invalid_entries.total}")
    print(f"Duplicates removed: {result.duplicate_counts.total}")
    print(f"Allow list changed: {'yes' if result.changed else 'no'}")
    if result.audit_event_id:
        print(f"Audit event: {result.audit_event_id}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        result = update_allow_list(
            args.allow,
            args.remove,
            args.add_file,
            args.audit,
        )
    except HACLError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        _print_summary(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
