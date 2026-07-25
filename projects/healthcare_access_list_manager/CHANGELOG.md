# Changelog

All notable changes to hACL are documented here.

## [1.0.0] - 2026-07-25

### Added

- Dedicated baseline snapshot branch: `archive/hacl-v1-baseline-2026-07-25`
- Structured `UpdateResult`, `InvalidEntries`, and `DuplicateCounts` models
- Strict IPv4 validation through Python's `ipaddress` module
- Explicit conflict rejection for simultaneous add/remove requests
- Atomic file replacement through staged temporary files and `os.replace`
- Recoverable `prepared`/`committed` JSON Lines audit transactions
- SHA-256 before/after state hashes
- Recovery states for interrupted transactions
- Command-line arguments for input and audit paths
- Optional JSON result output
- Package and tool configuration in `pyproject.toml`
- GitHub Actions CI for Python 3.12 and 3.13
- Expanded normal, edge, and failure-path tests

### Changed

- Audit output changed from human-readable `audit_log.txt` to structured `audit_log.jsonl`
- Missing, unreadable, invalid UTF-8, and corrupt audit files now stop processing
- Duplicate counts are recorded separately for allow, remove, and add sources
- Absent removals and already-present additions are represented explicitly
- File-writing helpers now use atomic replacement rather than direct truncation
- The repository README now presents hACL as the featured engineering project

### Verified

- 20 tests passing
- More than 90% statement and branch coverage during local verification

### Preserved

The implementation immediately before this hardening work remains available on:

```text
archive/hacl-v1-baseline-2026-07-25
```
