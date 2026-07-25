# Python Security Engineering Portfolio

[![hACL CI](https://github.com/theluckydraco-stack/python-in-google-cybersecurity-certificate/actions/workflows/hacl-ci.yml/badge.svg)](https://github.com/theluckydraco-stack/python-in-google-cybersecurity-certificate/actions/workflows/hacl-ci.yml)
[![CodeQL](https://github.com/theluckydraco-stack/python-in-google-cybersecurity-certificate/actions/workflows/codeql.yml/badge.svg)](https://github.com/theluckydraco-stack/python-in-google-cybersecurity-certificate/actions/workflows/codeql.yml)

A Python security-engineering portfolio centred on reliable access-governance automation, explicit failure handling, testable security decisions, and structured audit evidence.

The primary engineering project is **hACL**. Earlier certificate exercises are retained as development provenance, not presented as the main portfolio evidence.

## Reviewer path

A technical reviewer can assess the project through these artefacts:

1. [Merged hACL hardening pull request](https://github.com/theluckydraco-stack/python-in-google-cybersecurity-certificate/pull/1)
2. [`hACL.py` implementation](projects/healthcare_access_list_manager/hACL.py)
3. [Automated test suite](projects/healthcare_access_list_manager/tests/)
4. [Architecture and transaction model](projects/healthcare_access_list_manager/README.md)
5. [CI workflow](.github/workflows/hacl-ci.yml)
6. [Security policy](SECURITY.md)
7. [Contribution requirements](CONTRIBUTING.md)

## Featured project: hACL

### Healthcare Access List Manager

**hACL** validates and applies approved IPv4 allow-list changes for a healthcare-style access-control scenario.

It demonstrates:

- Strict standard-library IPv4 validation
- Separation of validation, business logic, persistence, and CLI handling
- Atomic file replacement
- Recoverable two-phase audit transactions
- Structured JSON Lines audit records
- SHA-256 before/after state verification
- Explicit error and conflicting-request handling
- Automated testing, coverage enforcement, linting, type checking, and CI

## Engineering evidence

| Area | Evidence |
|---|---|
| Delivery | Reviewed branch workflow and merged hardening pull request |
| Quality | Python 3.12/3.13 CI, Ruff, mypy, pytest, and a 90% coverage gate |
| Security | CodeQL `security-extended` scanning, security policy, and synthetic-data requirements |
| Reliability | Atomic replacement, recoverable audit states, and before/after SHA-256 hashes |
| Maintenance | Dependabot monitoring for Python and GitHub Actions dependencies |
| Collaboration | Contribution guide and pull-request evidence template |

## Project resources

| Resource | Link |
|---|---|
| Project documentation | [`projects/healthcare_access_list_manager/README.md`](projects/healthcare_access_list_manager/README.md) |
| Main implementation | [`projects/healthcare_access_list_manager/hACL.py`](projects/healthcare_access_list_manager/hACL.py) |
| Test suite | [`projects/healthcare_access_list_manager/tests/`](projects/healthcare_access_list_manager/tests/) |
| Changelog | [`projects/healthcare_access_list_manager/CHANGELOG.md`](projects/healthcare_access_list_manager/CHANGELOG.md) |
| Project configuration | [`projects/healthcare_access_list_manager/pyproject.toml`](projects/healthcare_access_list_manager/pyproject.toml) |
| Security policy | [`SECURITY.md`](SECURITY.md) |
| Contribution guide | [`CONTRIBUTING.md`](CONTRIBUTING.md) |

The exact pre-hardening state is preserved on `archive/hacl-v1-baseline-2026-07-25` for comparison and recovery.

## Repository contents

| Path | Purpose |
|---|---|
| `projects/healthcare_access_list_manager/` | Supported hACL access-governance project |
| `concepts_learned/` | Foundational Python exercises retained as provenance |
| `projects/trials/` | Isolated experimentation scripts, separate from the supported project |

## Run hACL

```bash
cd projects/healthcare_access_list_manager
python3 hACL.py
```

Use explicit paths and structured output when needed:

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
ruff check hACL.py tests
mypy hACL.py
python3 -m pytest
```

## Project boundary

hACL is an access-governance tool. It does not claim to be a HIDS or ITDR detector.

The separate planned `hacl-itdr-detector` project will add password-spray detection, identity correlation, allow-list integrity monitoring, structured security alerts, MITRE ATT&CK mapping, Sigma/KQL drafts, and an investigation report.

## Requirements

- Python 3.12+
- Standard library only at runtime
- Development dependencies declared in the hACL `pyproject.toml`

## Licence

MIT
