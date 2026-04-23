# Healthcare Access List Manager (hACL)

## Purpose

Manages IP allow lists for healthcare access systems. Supports adding/removing IPs, validates input, detects duplicates, and maintains an audit log of all changes for compliance and security.

## Features

- ✅ **IP Validation** — Validates IPs in A.B.C.D format where A-D are 0-255
- ✅ **Duplicate Detection** — Removes duplicate IPs from input lists
- ✅ **Batch Operations** — Add/remove multiple IPs in one operation
- ✅ **Audit Logging** — Timestamped log of all changes for compliance
- ✅ **Security-Focused** — Does not log sensitive allowlist contents

## Usage

### Basic Usage

```python
from hACL import update_allow_list

update_allow_list("allow_list.txt", "remove_list.txt", "add_list.txt")
```

### From Command Line

```bash
cd projects/healthcare_access_list_manager
python hACL.py
```

## Data Files

Place these files in the `data/` directory:

| File | Purpose |
|------|---------|
| `allow_list.txt` | Current allowed IPs (one per line) |
| `remove_list.txt` | IPs to revoke/remove (one per line) |
| `add_list.txt` | New IPs to add (one per line) |
| `audit_log.txt` | Timestamped log of changes (auto-created) |

## File Format

Each IP file contains one IP address per line:
```
192.168.1.1
10.0.0.1
172.16.0.1
```

## How It Works

1. **Read** all input files
2. **Validate** IPs in each list (removes invalid entries)
3. **Deduplicate** removes duplicate IPs
4. **Process Removals** — IPs in remove_list are deleted from allow_list
5. **Process Additions** — New valid IPs are added to allow_list
6. **Log Changes** — Timestamps and changes written to audit_log.txt
7. **Write** updated allow_list back to file

## Audit Log Format

```
2026-04-21 14:30:45 | Removed IPs: 192.168.1.5,10.0.0.2 | Added IPs: 172.16.1.1 | Invalid IPs: 
```

- **Removed IPs**: Successfully deleted from allow list
- **Added IPs**: Successfully added to allow list
- **Invalid IPs**: Rejected entries (malformed or out of range)

## Testing

```bash
# Run all tests
pytest tests/test_healthcare_acl.py -v

# Run specific test
pytest tests/test_healthcare_acl.py::TestValidateIPList -v
```

## Security Notes

- ✅ Does not log IPs that already exist in allowlist (prevents exposure)
- ✅ Does not log duplicate IPs from inputs
- ✅ Invalid IPs are logged (these are user errors, not sensitive)
- ✅ All changes timestamped for compliance

## Example Workflow

**Step 1:** Create input files in `data/`
```
# data/remove_list.txt
192.168.1.5
10.0.0.2

# data/add_list.txt
172.16.1.1
192.168.100.50
```

**Step 2:** Run the script
```bash
python hACL.py
```

**Step 3:** Check results
```bash
cat data/allow_list.txt     # Updated allowlist
cat data/audit_log.txt      # Change log
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "File not found" error | Check all required files exist in `data/` |
| No changes logged | Verify IPs are valid format (A.B.C.D) |
| Unexpected results | Check for duplicates in input files |

## Function Reference

### `validate_ip_list(ip_list, audit_log_path)`
Validates IPs and logs invalid ones. Returns list of valid IPs only.

### `remove_duplicate(ip_list)`
Removes duplicate IPs from a list. Returns deduplicated list.

### `update_allow_list(allow_file, remove_file, add_file=None)`
Main function. Processes all operations and updates files.

### `append_audit_log(file_path, removed_ips, added_ips, invalid_ips)`
Logs changes with timestamp to audit log.

## Future Improvements

- Implement file backup before overwriting (prevent data loss)
- Improve file validation to handle empty and corrupted files
- Refactor validation logic to remove logging side effects
- Centralize audit logging for consistency and clarity
- Improve function design to enforce single responsibility

### Detection & Analysis
- Add log parsing for failed login attempts
- Implement detection logic for suspicious IP behavior (e.g., repeated failures)
- Integrate detection results with allow list for risk flagging

### Security Enhancements
- Add file integrity checks using hashing (SHA-256)
- Detect unauthorized modifications to critical files

### Data Correlation
- Integrate employee_access.csv
- Map IP addresses to authorized users
- Flag IPs not associated with valid employees

### Usability
- Add command-line arguments using argparse (e.g., --remove-only)
- Improve script flexibility without modifying code

### Testing
- Expand structured testing scenarios for edge cases and failure conditions