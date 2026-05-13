# Python Cybersecurity Practice

Learning Python through cybersecurity-focused practice scripts and a completed healthcare IP access-list management project.

## What's Here

- **`concepts_learned/`** — Python fundamentals (strings, functions, regex, file handling)
- **`projects/healthcare_access_list_manager/`** — Finished hACL v1 access-list manager with tests

## Main Project: hACL

The main completed project in this repository is **hACL**, located at:

```text
projects/healthcare_access_list_manager/
```

hACL stands for **Healthcare Access List Manager**. It is a local Python tool for maintaining a healthcare access allow list. It reads approved input files, validates IPv4 addresses, removes duplicate entries, applies approved additions/removals, rewrites the allow list when needed, and records a timestamped audit log.

The main script is:

```text
projects/healthcare_access_list_manager/hACL.py
```

The test suite is:

```text
projects/healthcare_access_list_manager/tests/
```

Older practice scripts, such as files under `concepts_learned/` and `projects/trials/`, are learning material.

## Quick Start

### Healthcare Access List Manager

hACL validates IPs, removes duplicates, applies approved additions/removals, and writes an audit log with removed IPs, added IPs, invalid IPs, and duplicate count.

Project location:

```text
projects/healthcare_access_list_manager/
```

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
python3 hACL.py
```

**Output:**
- Updates `allow_list.txt` with changes
- Logs meaningful runs to `audit_log.txt` with timestamps and duplicate count

**Tests:**
```bash
python3 -m pytest projects/healthcare_access_list_manager/tests -v
```

### Learning Scripts

```bash
python concepts_learned/practice.py
```

Covers: functions, conditionals, strings, lists, regex, file I/O.

## Known Limitations

- IP validation is basic (A.B.C.D format only, no CIDR notation)
- No HTTPS or authentication (local tool only)
- Audit log appends without rotation (could get large)
- hACL is not a detection system; it does not parse authentication logs, detect password spraying, correlate employee access, or emit structured alerts

Future detection and correlation work belongs in the next project: **hACL-ITDR Detector**. That project will extend hACL with password-spray detection, employee access correlation, allow-list integrity monitoring, structured JSON alerts, and MITRE ATT&CK mapping.

## File Format

All IP files are plain text, one IP per line:
```
192.168.1.1
10.0.0.5
172.16.0.1
```

## Requirements

Python 3.12+

hACL itself uses the standard library. Running the test suite requires `pytest`.

## License

MIT
