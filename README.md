# Python Cybersecurity Practice

Learning Python through the Google Cybersecurity Professional Certificate. Contains practice scripts and a working healthcare IP access control tool.

## What's Here

- **`concepts_learned/`** — Python fundamentals (strings, functions, regex, file handling)
- **`projects/healthcare_access_list_manager/`** — Working tool to manage IP allow/block lists

## Quick Start

### Healthcare Access List Manager

Adds/removes IPs from an allow list and logs all changes.

**Setup:**
```bash
cd projects/healthcare_access_list_manager/data
# Create these files with IPs (one per line):
# - allow_list.txt (current allowed IPs)
# - remove_list.txt (IPs to remove)
# - add_list.txt (new IPs to add)
```

**Run:**
```bash
cd projects/healthcare_access_list_manager
python hACL.py
```

**Output:**
- Updates `allow_list.txt` with changes
- Logs all changes to `audit_log.txt` with timestamps

### Learning Scripts

```bash
python concepts_learned/practice.py
```

Covers: functions, conditionals, strings, lists, regex, file I/O.

## Known Limitations

- IP validation is basic (A.B.C.D format only, no CIDR notation)
- No HTTPS or authentication (local tool only)
- Audit log appends without rotation (could get large)
- Duplicates silently removed (not reported in final log)

*Plan to add: file backup before overwrite, empty/corrupt file handling, centralized audit logging, log-based intrusion detection, CSV employee-IP correlation, hashing for file integrity, CLI argument support (argparse), structured test scenarios*

## File Format

All IP files are plain text, one IP per line:
```
192.168.1.1
10.0.0.5
172.16.0.1
```

## Requirements

Python 3.12+

No external dependencies (uses standard library only).

## License

MIT