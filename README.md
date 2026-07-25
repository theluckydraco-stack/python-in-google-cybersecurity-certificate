# Python Security Engineering Portfolio

[![hACL CI](https://github.com/theluckydraco-stack/python-in-google-cybersecurity-certificate/actions/workflows/hacl-ci.yml/badge.svg)](https://github.com/theluckydraco-stack/python-in-google-cybersecurity-certificate/actions/workflows/hacl-ci.yml)

This repository records my progression from Python fundamentals in the Google Cybersecurity Professional Certificate to a tested access-governance project.

## Featured project: hACL

### Healthcare Access List Manager

**hACL** validates and applies approved IPv4 allow-list changes for a healthcare-style access-control scenario.

It demonstrates:

- Strict IPv4 validation
- Separation of validation, business logic, persistence, and CLI handling
- Atomic file replacement
- Recoverable two-phase audit transactions
- Structured JSON Lines audit records
- SHA-256 before/after state verification
- Explicit error and conflict handling
- Automated tests, coverage, linting, type checking, and CI

| Resource | Link |
|---|---|
| Project documentation | [`projects/healthcare_access_list_manager/README.md`](projects/healthcare_access_list_manager/README.md) |
| Main implementation | [`projects/healthcare_access_list_manager/hACL.py`](projects/healthcare_access_list_manager/hACL.py) |
| Test suite | [`projects/healthcare_access_list_manager/tests/`](projects/healthcare_access_list_manager/tests/) |
| Changelog | [`projects/healthcare_access_list_manager/CHANGELOG.md`](projects/healthcare_access_list_manager/CHANGELOG.md) |
| Project configuration | [`projects/healthcare_access_list_manager/pyproject.toml`](projects/healthcare_access_list_manager/pyproject.toml) |

The original pre-hardening state is preserved on the branch `archive/hacl-v1-baseline-2026-07-25`.

## Repository contents

| Path | Purpose |
|---|---|
| `projects/healthcare_access_list_manager/` | Featured hACL access-governance project |
| `concepts_learned/` | Python fundamentals: strings, functions, lists, regex, and file handling |
| `projects/trials/` | Practice and experimentation scripts |

## Run hACL

```bash
cd projects/healthcare_access_list_manager
python3 hACL.py
```

Use explicit paths or JSON output when needed:

```bash
python3 hACL.py \
  --allow data/allow_list.txt \
  --remove data/remove_list.txt \
  --add data/add_list.txt \
  --audit data/audit_log.jsonl \
  --json
```

## Development checks

```bash
python3 -m pip install -e "projects/healthcare_access_list_manager[dev]"
cd projects/healthcare_access_list_manager
python3 -m pytest --cov=hACL --cov-report=term-missing
ruff check hACL.py tests
mypy hACL.py
```

## Current project boundary

hACL is an access-governance tool. It does not claim to be a HIDS or ITDR detector.

The separate planned `hACL-ITDR Detector` project will add password-spray detection, identity correlation, allow-list integrity monitoring, JSON security alerts, MITRE ATT&CK mapping, Sigma/KQL drafts, and an investigation report.

## Requirements

- Python 3.12+
- Standard library only at runtime
- Development dependencies declared in the hACL `pyproject.toml`

## Licence

MIT
