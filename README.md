# Python Cybersecurity Practice

Python practice repository focused on cybersecurity scripting and access-list management.

## Contents

- `concepts_learned/` — Python fundamentals: strings, functions, lists, regex, and file handling
- `projects/healthcare_access_list_manager/` — hACL v1 access-list manager with tests
- `projects/trials/` — practice and experimentation scripts

## Main Project: hACL

**hACL** stands for **Healthcare Access List Manager**. It is a local Python tool that maintains a healthcare-style IP allow list by validating IPv4 addresses, removing duplicates, applying approved additions/removals, updating the allow list, and writing an audit log.

Project path:

```text
projects/healthcare_access_list_manager/
```

Main script:

```text
projects/healthcare_access_list_manager/hACL.py
```

Test suite:

```text
projects/healthcare_access_list_manager/tests/
```

## Quick Start

Create the required input files in the hACL `data/` directory:

```bash
cd projects/healthcare_access_list_manager/data
# allow_list.txt  - current approved IPs
# remove_list.txt - IPs approved for removal
# add_list.txt    - IPs approved for addition
```

Run hACL:

```bash
cd projects/healthcare_access_list_manager
python3 hACL.py
```

Run tests from the repository root:

```bash
python3 -m pytest projects/healthcare_access_list_manager/tests -v
```

## Output

hACL updates `allow_list.txt` when additions, removals, or cleanup change the file. It writes meaningful runs to `audit_log.txt`, including removed IPs, added IPs, invalid IPs, and duplicate count.

## Learning Scripts

Practice scripts are stored under `concepts_learned/` and `projects/trials/`.

Example:

```bash
python3 concepts_learned/practice.py
```

## Limitations

- IPv4 validation is basic and does not support CIDR notation.
- hACL is a local script; it has no web interface, authentication, or HTTPS.
- Audit logs append without rotation.
- hACL is not a detection system. It does not parse authentication logs, detect password spraying, correlate employee access, monitor file integrity, or emit structured alerts.

## Next Project

Future detection work belongs in **hACL-ITDR Detector**, a separate project that will extend hACL’s access-governance logic with password-spray detection, employee access correlation, allow-list integrity monitoring, structured JSON alerts, and MITRE ATT&CK mapping.

## Requirements

- Python 3.12+
- `pytest` for running tests

hACL itself uses only the Python standard library.

## License

MIT
