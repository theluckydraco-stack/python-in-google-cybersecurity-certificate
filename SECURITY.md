# Security Policy

## Supported versions

Security fixes are applied to the latest version on the `main` branch.

| Version | Supported |
|---|---|
| 1.x | Yes |
| Earlier learning versions | No |

The pre-hardening snapshot is retained for historical comparison and must not be treated as a supported release.

## Reporting a vulnerability

Do not disclose exploit details, sensitive IP addresses, credentials, patient information, employee information, or other confidential data in a public issue.

Use GitHub's **Private vulnerability reporting** option in the repository's **Security and quality** area when it is available. Include:

- The affected version or commit
- The security impact
- Reproduction steps using synthetic data
- Any proposed mitigation

If private vulnerability reporting is unavailable, open a public issue titled `Private security contact requested` without technical details or sensitive information. A private channel can then be established.

## Security scope

Reports are in scope when they concern the hACL implementation, including:

- Validation bypasses
- Unsafe file replacement or recovery behaviour
- Audit-log integrity failures
- Path or file-handling vulnerabilities
- Unexpected disclosure of input data
- Dependency or workflow vulnerabilities

Reports based only on the intentionally unsupported historical snapshot are out of scope unless the same issue also affects `main`.

## Data handling

Use only synthetic data when testing or reporting. This repository must not contain real healthcare, patient, employee, credential, or production network data.
