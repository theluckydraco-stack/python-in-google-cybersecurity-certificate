## Summary

Describe the problem and the change.

## Root cause or rationale

Explain why the problem exists or why the change is necessary.

## Implementation

Describe the technical approach and important design decisions.

## Security and privacy impact

- Does this change affect validation, file handling, audit integrity, recovery, or data exposure?
- Confirm that only synthetic data is included.

## Verification

List the commands and scenarios used to validate the change.

```bash
ruff check hACL.py tests
mypy hACL.py
python3 -m pytest
```

## Checklist

- [ ] The change is focused and documented.
- [ ] Tests cover normal and relevant failure paths.
- [ ] CI passes on supported Python versions.
- [ ] No secrets or real healthcare, employee, credential, or production network data are included.
- [ ] Behavioural or interface changes are reflected in the README or changelog.
- [ ] The change stays within the documented hACL project boundary.
