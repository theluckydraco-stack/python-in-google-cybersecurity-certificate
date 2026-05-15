# Healthcare Access List Manager (hACL)

## Purpose

hACL is a Python access-list management tool for healthcare-style access control. It validates IPv4 addresses, removes duplicates, applies approved additions/removals, and records changes in an audit log.

It is not a HIDS, password-spray detector, or broader detection system.

## Features

- IPv4 validation where each octet is 0–255
- Duplicate removal without exposing duplicate values
- Batch removals from `remove_list.txt`
- Batch additions from `add_list.txt`
- Audit logging for additions, removals, invalid IPs, and duplicate count
- Automatic creation of `audit_log.txt`

## Data Files

Place these files in the `data/` directory:

| File | Purpose |
|------|---------|
| `allow_list.txt` | Current approved IPs, one per line |
| `remove_list.txt` | IPs approved for removal |
| `add_list.txt` | IPs approved for addition |
| `audit_log.txt` | Timestamped audit history, auto-created if missing |

Required input files: `allow_list.txt`, `remove_list.txt`, and `add_list.txt`.

## Usage

Run from the project directory:

```bash
cd projects/healthcare_access_list_manager
python3 hACL.py
```

Import the workflow:

```python
from hACL import update_allow_list

update_allow_list("data/allow_list.txt", "data/remove_list.txt", "data/add_list.txt")
```

Importing `hACL.py` does not run the update workflow. File checks and updates only run when the script is executed directly.

## How It Works

1. Reads the allow, remove, and add files.
2. Validates IPs and separates invalid entries.
3. Removes duplicates and counts them.
4. Removes approved revoked IPs from the allow list.
5. Adds approved new IPs not already present.
6. Rewrites `allow_list.txt` when the file changes.
7. Writes one audit entry when changes or cleanup occur.

## Audit Log Format

```text
2026-05-12 14:30:45 | Removed IPs: 192.168.1.5 | Added IPs: 172.16.1.1 | Invalid IPs: bad-ip | Duplicate Count: 2
```

| Field | Meaning |
|------|---------|
| `Removed IPs` | IPs removed from the allow list |
| `Added IPs` | New IPs added to the allow list |
| `Invalid IPs` | Rejected malformed or out-of-range entries |
| `Duplicate Count` | Number of duplicate entries removed |

## Security Decisions

- Existing allow-list IPs from `add_list.txt` are skipped without logging their values.
- Duplicate values are counted but not logged individually.
- Invalid IPs are logged because they are rejected inputs.
- Helper functions return results; audit logging happens once in the main workflow.

## Function Reference

### `validate_ip_list(ip_list)`

Returns `valid_ips, invalid_ips`.

### `remove_duplicate(ip_list)`

Returns `unique_ips, duplicate_count`.

### `append_audit_log(file_path, removed_ips, added_ips, invalid_ips, duplicate_count=0)`

Writes one timestamped audit entry.

### `update_allow_list(allow_file, remove_file, add_file=None)`

Runs the full access-list update workflow.

## Testing

Run the test suite:

```bash
pytest projects/healthcare_access_list_manager/tests -v
```

Or:

```bash
python3 -m pytest projects/healthcare_access_list_manager/tests -v
```

## Limitations

hACL v1 does not parse authentication logs, detect password spraying, correlate employee access, monitor allow-list integrity, map detections to MITRE ATT&CK, write Sigma/KQL rules, or emit structured JSON alerts.

## Next Project: hACL-ITDR Detector

hACL is the access governance foundation for `hACL-ITDR Detector`, a follow-up project that adds password-spray detection, employee access correlation, allow-list integrity monitoring, structured JSON alerts, and MITRE ATT&CK T1110.003 mapping.