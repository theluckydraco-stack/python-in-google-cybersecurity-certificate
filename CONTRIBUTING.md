# Contributing

Contributions should improve the reliability, security, testability, or documentation of this repository without expanding hACL into a threat-detection system.

## Project boundaries

- `projects/healthcare_access_list_manager/` contains the supported hACL access-governance project.
- `concepts_learned/` and `projects/trials/` contain supporting learning material.
- Password-spray detection, identity correlation, integrity monitoring, MITRE ATT&CK mappings, Sigma/KQL content, and incident reporting belong in the separate planned `hACL-ITDR Detector` project.

## Development setup

From the repository root:

```bash
python3 -m pip install -e "projects/healthcare_access_list_manager[dev]"
cd projects/healthcare_access_list_manager
```

Run the complete quality gate before opening a pull request:

```bash
ruff check hACL.py tests
mypy hACL.py
python3 -m pytest
```

The pytest configuration enforces statement and branch coverage of at least 90%.

## Contribution workflow

1. Open or identify an issue for behavioural changes.
2. Create a focused branch from `main`.
3. Keep the change limited to one clearly defined problem.
4. Add or update tests that fail before the fix and pass after it.
5. Update documentation when behaviour, interfaces, audit fields, or limitations change.
6. Open a pull request and complete the repository template.

## Engineering requirements

Changes must:

- Preserve explicit error handling for missing, unreadable, or invalid files.
- Preserve deterministic ordering and stable de-duplication.
- Avoid direct truncation of the allow-list file.
- Preserve recoverable audit semantics.
- Use synthetic data only.
- Avoid secrets, credentials, real patient data, employee records, and production network information.
- Keep runtime dependencies minimal and justified.
- Pass CI on every supported Python version.

## Pull-request quality

A strong pull request explains:

- The problem and its impact
- The root cause
- The implementation decision
- Tests and failure paths covered
- Security or compatibility implications
- Any remaining limitations

Documentation-only changes should be accurate and directly useful. Cosmetic changes without a clear maintenance or usability benefit may be declined.
