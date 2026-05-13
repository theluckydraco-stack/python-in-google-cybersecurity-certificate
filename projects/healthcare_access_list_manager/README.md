# Healthcare Access List Manager (hACL)

## Purpose

hACL manages a healthcare access allow list by validating IPs, removing duplicates, applying approved additions and removals, and recording changes in an audit log.

This project is an access-list management tool. It is not a HIDS, password-spray detector, or broader detection system.

## Features

- IP validation for IPv4-style addresses where each octet is 0-255
- Duplicate removal without exposing duplicate values in console output or logs
- Batch removals from `remove_list.txt`
- Batch additions from `add_list.txt`
- Audit logging for removed IPs, added IPs, invalid IPs, and duplicate count
- Auto-creation of `audit_log.txt` when the script runs

## Data Files

Place these files in the `data/` directory:

| File | Purpose |
|------|---------|
| `allow_list.txt` | Current approved IPs, one per line |
| `remove_list.txt` | IPs approved for revocation, one per line |
| `add_list.txt` | IPs approved for addition, one per line |
| `audit_log.txt` | Timestamped audit history, auto-created if missing |

The required input files are `allow_list.txt`, `remove_list.txt`, and `add_list.txt`. The audit log is created automatically.

## Usage

Run the script from the project directory:

```bash
cd projects/healthcare_access_list_manager
python3 hACL.py
```

Import the workflow from another Python file:

```python
from hACL import update_allow_list

update_allow_list("data/allow_list.txt", "data/remove_list.txt", "data/add_list.txt")
```

Importing `hACL.py` does not run the update workflow. The file check and update only run when `hACL.py` is executed directly.

## How It Works

1. Reads the allow, remove, and add files.
2. Validates each list and separates valid IPs from invalid IPs.
3. Removes duplicate IPs and counts how many were removed.
4. Removes approved revoked IPs from the allow list.
5. Adds approved new IPs that are not already allowed.
6. Rewrites `allow_list.txt` when additions, removals, or allow-list cleanup changed it.
7. Writes one audit entry for each meaningful run.

## Audit Log Format

```text
2026-05-12 14:30:45 | Removed IPs: 192.168.1.5 | Added IPs: 172.16.1.1 | Invalid IPs: bad-ip | Duplicate Count: 2
```

- `Removed IPs`: IPs successfully removed from the allow list.
- `Added IPs`: New IPs successfully added to the allow list.
- `Invalid IPs`: Rejected malformed or out-of-range entries.
- `Duplicate Count`: Number of duplicate entries removed across the input lists.

## Security Decisions

- Existing allow-list IPs from `add_list.txt` are skipped without logging their values.
- Duplicate values are counted but not logged individually.
- Invalid IPs are logged because they are rejected input values.
- The script records one clear audit entry per meaningful run instead of logging from helper functions.

## Function Reference

### `validate_ip_list(ip_list)`

Returns `valid_ips, invalid_ips`.

### `remove_duplicate(ip_list)`

Returns `unique_ips, duplicate_count`.

### `append_audit_log(file_path, removed_ips, added_ips, invalid_ips, duplicate_count=0)`

Appends one timestamped audit entry, including duplicate count.

### `update_allow_list(allow_file, remove_file, add_file=None)`

Runs the full access-list workflow: read files, validate IPs, remove duplicates, apply removals and additions, write the allow list when needed, and append the audit log when there is something to record.

## Testing

Run the hACL test suite:

```bash
pytest projects/healthcare_access_list_manager/tests -v
```

If `pytest` is not on PATH, use:

```bash
python3 -m pytest projects/healthcare_access_list_manager/tests -v
```

## Limitations

hACL v1 does not parse authentication logs, detect password spraying, correlate employee access, monitor allow-list integrity, produce MITRE ATT&CK mappings, write Sigma/KQL rules, or emit structured JSON alerts.

## Next Project: hACL-ITDR Detector

hACL is the access governance foundation for a follow-up project: hACL-ITDR Detector. The next project extends this access-list manager with password-spray detection, employee access correlation, allow-list integrity monitoring, structured JSON alerts, and MITRE ATT&CK T1110.003 mapping.
