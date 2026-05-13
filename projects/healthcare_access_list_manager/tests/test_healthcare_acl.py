from pathlib import Path
import sys


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

import hACL


def write_ip_file(path, entries):
    path.write_text("\n".join(entries))


def read_ip_file(path):
    return path.read_text().split()


def run_update(tmp_path, monkeypatch, allow_entries, remove_entries, add_entries):
    allow_file = tmp_path / "allow_list.txt"
    remove_file = tmp_path / "remove_list.txt"
    add_file = tmp_path / "add_list.txt"
    audit_file = tmp_path / "audit_log.txt"

    write_ip_file(allow_file, allow_entries)
    write_ip_file(remove_file, remove_entries)
    write_ip_file(add_file, add_entries)
    monkeypatch.setattr(hACL, "AUDIT_LOG_PATH", audit_file)

    hACL.update_allow_list(allow_file, remove_file, add_file)

    audit_text = audit_file.read_text() if audit_file.exists() else ""
    return read_ip_file(allow_file), audit_text, audit_file


def test_validate_ip_list_returns_valid_and_invalid_ips():
    ip_list = [
        "192.168.1.1",
        "10.0.0.5",
        "999.1.1.1",
        "not-an-ip",
        "172.16.0",
    ]

    valid_ips, invalid_ips = hACL.validate_ip_list(ip_list)

    assert valid_ips == ["192.168.1.1", "10.0.0.5"]
    assert invalid_ips == ["999.1.1.1", "not-an-ip", "172.16.0"]


def test_remove_duplicate_returns_cleaned_list_and_duplicate_count():
    unique_ips, duplicate_count = hACL.remove_duplicate(
        ["192.168.1.1", "10.0.0.5", "192.168.1.1", "10.0.0.5"]
    )

    assert unique_ips == ["192.168.1.1", "10.0.0.5"]
    assert duplicate_count == 2


def test_update_allow_list_removes_ips_from_remove_list(tmp_path, monkeypatch):
    allow_ips, audit_text, _ = run_update(
        tmp_path,
        monkeypatch,
        ["192.168.1.1", "10.0.0.5"],
        ["10.0.0.5"],
        [],
    )

    assert allow_ips == ["192.168.1.1"]
    assert "Removed IPs: 10.0.0.5" in audit_text


def test_update_allow_list_adds_new_ips_from_add_list(tmp_path, monkeypatch):
    allow_ips, audit_text, _ = run_update(
        tmp_path,
        monkeypatch,
        ["192.168.1.1"],
        [],
        ["10.0.0.5"],
    )

    assert allow_ips == ["192.168.1.1", "10.0.0.5"]
    assert "Added IPs: 10.0.0.5" in audit_text


def test_existing_add_list_ip_is_not_duplicated(tmp_path, monkeypatch):
    allow_ips, audit_text, _ = run_update(
        tmp_path,
        monkeypatch,
        ["192.168.1.1"],
        [],
        ["192.168.1.1"],
    )

    assert allow_ips == ["192.168.1.1"]
    assert audit_text == ""


def test_invalid_ips_are_skipped_and_written_to_audit_log(tmp_path, monkeypatch):
    allow_ips, audit_text, _ = run_update(
        tmp_path,
        monkeypatch,
        ["192.168.1.1"],
        ["bad-ip"],
        ["10.0.0.5", "999.1.1.1"],
    )

    assert allow_ips == ["192.168.1.1", "10.0.0.5"]
    assert "Invalid IPs: bad-ip,999.1.1.1" in audit_text


def test_duplicate_count_appears_in_audit_log(tmp_path, monkeypatch):
    allow_ips, audit_text, _ = run_update(
        tmp_path,
        monkeypatch,
        ["192.168.1.1", "192.168.1.1"],
        [],
        ["10.0.0.5", "10.0.0.5"],
    )

    assert allow_ips == ["192.168.1.1", "10.0.0.5"]
    assert "Duplicate Count: 2" in audit_text


def test_audit_log_path_can_be_monkeypatched_to_temp_file(tmp_path, monkeypatch):
    _, audit_text, audit_file = run_update(
        tmp_path,
        monkeypatch,
        ["192.168.1.1"],
        ["192.168.1.1"],
        [],
    )

    assert audit_file.exists()
    assert str(audit_file).startswith(str(tmp_path))
    assert "Removed IPs: 192.168.1.1" in audit_text
