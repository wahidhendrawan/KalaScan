# Security Policy

## Supported versions

Only the latest release gets security fixes.

| Version | Supported |
|---|---|
| 1.11.x | yes |
| < 1.11 | no |

## Reporting a vulnerability

Please report privately through GitHub: **Security → Report a vulnerability** on this repository ([direct link](https://github.com/wahidhendrawan/KalaScan/security/advisories/new)). Do not open a public issue.

Include the KalaScan version (`kalascan --version`), how you ran it (CLI, web server, Docker, GitHub Action), and steps or a sample that reproduces the problem. If the sample is live malware, describe where to get it rather than attaching it.

You should get a first reply within 7 days. Fixed issues are credited in the release notes unless you ask otherwise.

## In scope

- Code execution, path traversal or file writes outside the temp directory while scanning an untrusted repository, archive or package
- Authentication or authorisation bypass in the web server or API tokens
- Sandbox escape from `--sandbox`
- Secrets leaking into reports, logs or the database

## Out of scope

- A malicious sample that KalaScan scores low (a detection gap). Open a normal issue with the package name and version so it can go into the eval corpus.
- False positives. Open a normal issue.
- Findings that need an already-compromised host or a malicious local user with write access to the KalaScan binary or config.
