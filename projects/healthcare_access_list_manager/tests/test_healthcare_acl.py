import json
from pathlib import Path

import pytest

import hACL


def write_entries(path: Path, entries: list[str]) -> None:
    text = "\n".join(entries)
    if text:
        text += "\n"
    path.write_text(text, encoding="utf-8")


def read_entries(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").split()


def read_events(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def run_update(
    tmp_path: Path,
    allow_entries: list[str],
    remove_entries: list[str],
    add_entries: list[str],
):
    allow_file = tmp_path / "allow_list.txt"
    remove_file = tmp_path / "remove_list.txt"
    add_file = tmp_path / "add_list.txt"
    audit_file = tmp_path / "audit_log.jsonl"

    write_entries(allow_file, allow_entries)
    write_entries(remove_file, remove_entries)
    write_entries(add_file, add_entries)

    result = hACL.update_allow_list(
        allow_file,
        remove_file,
        add_file,
        audit_file,
    )
    return result, allow_file, audit_file


def test_validate_ip_list_uses_strict_ipv4_validation():
    valid, invalid = hACL.validate_ip_list(
        [
            "192.168.1.1",
            "10.0.0.5",
            "999.1.1.1",
            "not-an-ip",
            "172.16.0",
            "192.168.001.1",
            "2001:db8::1",
            "10.0.0.0/24",
        ]
    )

    assert valid == ["192.168.1.1", "10.0.0.5"]
    assert invalid == [
        "999.1.1.1",
        "not-an-ip",
        "172.16.0",
        "192.168.001.1",
        "2001:db8::1",
        "10.0.0.0/24",
    ]


def test_remove_duplicate_preserves_first_seen_order():
    unique, duplicate_count = hACL.remove_duplicate(
        ["192.168.1.1", "10.0.0.5", "192.168.1.1", "10.0.0.5"]
    )

    assert unique == ["192.168.1.1", "10.0.0.5"]
    assert duplicate_count == 2


def test_prepare_update_rejects_conflicting_requests():
    with pytest.raises(hACL.ConflictingRequestError):
        hACL.prepare_update(
            ["192.168.1.1"],
            ["10.0.0.5"],
            ["10.0.0.5"],
        )


def test_update_applies_additions_and_removals_and_writes_committed_audit(
    tmp_path,
):
    result, allow_file, audit_file = run_update(
        tmp_path,
        ["192.168.1.1", "10.0.0.5"],
        ["10.0.0.5"],
        ["172.16.0.1"],
    )

    assert read_entries(allow_file) == ["192.168.1.1", "172.16.0.1"]
    assert result.removed_ips == ("10.0.0.5",)
    assert result.added_ips == ("172.16.0.1",)
    assert result.changed is True
    assert result.audit_written is True

    events = read_events(audit_file)
    assert len(events) == 1
    assert events[0]["status"] == "committed"
    assert events[0]["removed_ips"] == ["10.0.0.5"]
    assert events[0]["added_ips"] == ["172.16.0.1"]
    assert events[0]["before_sha256"] == result.before_sha256
    assert events[0]["after_sha256"] == result.after_sha256


def test_result_and_audit_distinguish_governance_outcomes(tmp_path):
    result, allow_file, audit_file = run_update(
        tmp_path,
        ["192.168.1.1", "192.168.1.1", "bad-allow"],
        ["10.0.0.99", "10.0.0.99", "bad-remove"],
        ["192.168.1.1", "172.16.0.1", "172.16.0.1", "bad-add"],
    )

    assert read_entries(allow_file) == ["192.168.1.1", "172.16.0.1"]
    assert result.not_found_removals == ("10.0.0.99",)
    assert result.already_present_additions == ("192.168.1.1",)
    assert result.invalid_entries.allow == ("bad-allow",)
    assert result.invalid_entries.remove == ("bad-remove",)
    assert result.invalid_entries.add == ("bad-add",)
    assert result.duplicate_counts.allow == 1
    assert result.duplicate_counts.remove == 1
    assert result.duplicate_counts.add == 1
    assert result.duplicate_counts.total == 3
    assert result.allow_list_cleaned is True

    event = read_events(audit_file)[0]
    assert event["not_found_removals"] == ["10.0.0.99"]
    assert event["already_present_additions"] == ["192.168.1.1"]
    assert event["duplicate_counts"] == {
        "add": 1,
        "allow": 1,
        "remove": 1,
        "total": 3,
    }


def test_empty_clean_transaction_makes_no_write_or_audit(tmp_path):
    result, allow_file, audit_file = run_update(
        tmp_path,
        ["192.168.1.1"],
        [],
        [],
    )

    assert result.changed is False
    assert result.audit_written is False
    assert read_entries(allow_file) == ["192.168.1.1"]
    assert not audit_file.exists()


def test_existing_addition_is_audited_even_when_allow_list_does_not_change(
    tmp_path,
):
    result, allow_file, audit_file = run_update(
        tmp_path,
        ["192.168.1.1"],
        [],
        ["192.168.1.1"],
    )

    assert result.changed is False
    assert result.already_present_additions == ("192.168.1.1",)
    assert read_entries(allow_file) == ["192.168.1.1"]
    assert read_events(audit_file)[0]["status"] == "committed"


def test_missing_input_raises_without_changing_allow_list(tmp_path):
    allow_file = tmp_path / "allow_list.txt"
    missing_remove = tmp_path / "missing_remove.txt"
    add_file = tmp_path / "add_list.txt"
    audit_file = tmp_path / "audit_log.jsonl"
    write_entries(allow_file, ["192.168.1.1"])
    write_entries(add_file, ["10.0.0.5"])
    original = allow_file.read_text(encoding="utf-8")

    with pytest.raises(hACL.InputFileError):
        hACL.update_allow_list(
            allow_file,
            missing_remove,
            add_file,
            audit_file,
        )

    assert allow_file.read_text(encoding="utf-8") == original
    assert not audit_file.exists()


def test_corrupt_audit_log_blocks_new_transaction(tmp_path):
    allow_file = tmp_path / "allow_list.txt"
    remove_file = tmp_path / "remove_list.txt"
    add_file = tmp_path / "add_list.txt"
    audit_file = tmp_path / "audit_log.jsonl"
    write_entries(allow_file, ["192.168.1.1"])
    write_entries(remove_file, [])
    write_entries(add_file, ["10.0.0.5"])
    audit_file.write_text("not-json\n", encoding="utf-8")

    with pytest.raises(hACL.PersistenceError):
        hACL.update_allow_list(
            allow_file,
            remove_file,
            add_file,
            audit_file,
        )

    assert read_entries(allow_file) == ["192.168.1.1"]


def test_allow_write_failure_is_recorded_as_aborted_and_preserves_original(
    tmp_path, monkeypatch
):
    allow_file = tmp_path / "allow_list.txt"
    remove_file = tmp_path / "remove_list.txt"
    add_file = tmp_path / "add_list.txt"
    audit_file = tmp_path / "audit_log.jsonl"
    write_entries(allow_file, ["192.168.1.1"])
    write_entries(remove_file, [])
    write_entries(add_file, ["10.0.0.5"])

    original_atomic_write = hACL._atomic_write_text

    def fail_allow_write(path, text):
        if Path(path) == allow_file:
            raise hACL.PersistenceError("simulated allow write failure")
        return original_atomic_write(path, text)

    monkeypatch.setattr(hACL, "_atomic_write_text", fail_allow_write)

    with pytest.raises(hACL.PersistenceError):
        hACL.update_allow_list(
            allow_file,
            remove_file,
            add_file,
            audit_file,
        )

    assert read_entries(allow_file) == ["192.168.1.1"]
    assert read_events(audit_file)[0]["status"] == "aborted"


def test_prepared_event_is_recovered_after_final_audit_write_failure(
    tmp_path, monkeypatch
):
    allow_file = tmp_path / "allow_list.txt"
    remove_file = tmp_path / "remove_list.txt"
    add_file = tmp_path / "add_list.txt"
    audit_file = tmp_path / "audit_log.jsonl"
    write_entries(allow_file, ["192.168.1.1"])
    write_entries(remove_file, [])
    write_entries(add_file, ["10.0.0.5"])

    original_write_audit = hACL._write_audit_events
    call_count = 0

    def fail_second_audit_write(path, events):
        nonlocal call_count
        call_count += 1
        if call_count == 2:
            raise hACL.PersistenceError("simulated final audit failure")
        return original_write_audit(path, events)

    monkeypatch.setattr(hACL, "_write_audit_events", fail_second_audit_write)

    with pytest.raises(hACL.PersistenceError):
        hACL.update_allow_list(
            allow_file,
            remove_file,
            add_file,
            audit_file,
        )

    assert read_entries(allow_file) == ["192.168.1.1", "10.0.0.5"]
    assert read_events(audit_file)[0]["status"] == "prepared"

    monkeypatch.setattr(hACL, "_write_audit_events", original_write_audit)
    recovery_status = hACL.recover_incomplete_transaction(
        allow_file,
        audit_file,
    )

    assert recovery_status == "committed_recovered"
    assert read_events(audit_file)[0]["status"] == "committed_recovered"


def test_prepared_event_is_recovered_as_aborted_when_allow_file_is_unchanged(
    tmp_path,
):
    allow_file = tmp_path / "allow_list.txt"
    audit_file = tmp_path / "audit_log.jsonl"
    original_text = "192.168.1.1\n"
    updated_text = "192.168.1.1\n10.0.0.5\n"
    allow_file.write_text(original_text, encoding="utf-8")
    event = {
        "event_id": "test-event",
        "status": "prepared",
        "before_sha256": hACL._sha256_text(original_text),
        "after_sha256": hACL._sha256_text(updated_text),
    }
    audit_file.write_text(json.dumps(event) + "\n", encoding="utf-8")

    recovery_status = hACL.recover_incomplete_transaction(
        allow_file,
        audit_file,
    )

    assert recovery_status == "aborted_recovered"
    assert read_events(audit_file)[0]["status"] == "aborted_recovered"


def test_main_returns_nonzero_for_missing_files(tmp_path, capsys):
    exit_code = hACL.main(
        [
            "--allow",
            str(tmp_path / "missing_allow.txt"),
            "--remove",
            str(tmp_path / "missing_remove.txt"),
            "--add",
            str(tmp_path / "missing_add.txt"),
            "--audit",
            str(tmp_path / "audit.jsonl"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "ERROR:" in captured.err


def test_update_without_add_file_is_supported(tmp_path):
    allow_file = tmp_path / "allow_list.txt"
    remove_file = tmp_path / "remove_list.txt"
    audit_file = tmp_path / "audit_log.jsonl"
    write_entries(allow_file, ["192.168.1.1", "10.0.0.5"])
    write_entries(remove_file, ["10.0.0.5"])

    result = hACL.update_allow_list(
        allow_file,
        remove_file,
        add_file=None,
        audit_file=audit_file,
    )

    assert result.removed_ips == ("10.0.0.5",)
    assert read_entries(allow_file) == ["192.168.1.1"]


def test_result_to_dict_includes_aggregate_counts():
    result = hACL.prepare_update(
        ["192.168.1.1", "192.168.1.1"],
        ["10.0.0.5", "10.0.0.5"],
        ["172.16.0.1", "172.16.0.1"],
    )

    payload = result.to_dict()
    assert payload["duplicate_counts"]["total"] == 3
    assert payload["invalid_entries"]["total"] == 0


def test_invalid_utf8_input_raises_input_file_error(tmp_path):
    invalid_file = tmp_path / "invalid.txt"
    invalid_file.write_bytes(b"\xff\xfe")

    with pytest.raises(hACL.InputFileError):
        hACL.read_file(invalid_file)


def test_audit_log_rejects_non_object_json(tmp_path):
    audit_file = tmp_path / "audit.jsonl"
    audit_file.write_text('["not", "an", "object"]\n', encoding="utf-8")

    with pytest.raises(hACL.PersistenceError):
        hACL._load_audit_events(audit_file)


def test_recovery_requires_manual_review_for_unknown_allow_hash(tmp_path):
    allow_file = tmp_path / "allow_list.txt"
    audit_file = tmp_path / "audit_log.jsonl"
    allow_file.write_text("172.16.0.1\n", encoding="utf-8")
    event = {
        "event_id": "test-event",
        "status": "prepared",
        "before_sha256": hACL._sha256_text("192.168.1.1\n"),
        "after_sha256": hACL._sha256_text("192.168.1.1\n10.0.0.5\n"),
    }
    audit_file.write_text(json.dumps(event) + "\n", encoding="utf-8")

    with pytest.raises(hACL.PersistenceError, match="Manual review"):
        hACL.recover_incomplete_transaction(allow_file, audit_file)


def test_main_can_print_json_result(tmp_path, capsys):
    allow_file = tmp_path / "allow_list.txt"
    remove_file = tmp_path / "remove_list.txt"
    add_file = tmp_path / "add_list.txt"
    audit_file = tmp_path / "audit.jsonl"
    write_entries(allow_file, ["192.168.1.1"])
    write_entries(remove_file, [])
    write_entries(add_file, ["10.0.0.5"])

    exit_code = hACL.main(
        [
            "--allow",
            str(allow_file),
            "--remove",
            str(remove_file),
            "--add",
            str(add_file),
            "--audit",
            str(audit_file),
            "--json",
        ]
    )

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["added_ips"] == ["10.0.0.5"]
    assert payload["audit_written"] is True


def test_main_prints_human_readable_summary(tmp_path, capsys):
    allow_file = tmp_path / "allow_list.txt"
    remove_file = tmp_path / "remove_list.txt"
    add_file = tmp_path / "add_list.txt"
    audit_file = tmp_path / "audit.jsonl"
    write_entries(allow_file, ["192.168.1.1"])
    write_entries(remove_file, [])
    write_entries(add_file, [])

    exit_code = hACL.main(
        [
            "--allow",
            str(allow_file),
            "--remove",
            str(remove_file),
            "--add",
            str(add_file),
            "--audit",
            str(audit_file),
        ]
    )

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "Original allow-list count: 1" in output
    assert "Allow list changed: no" in output
