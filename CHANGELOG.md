# Changelog

All notable changes to KalaScan are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/). Releases before 1.8.0 were not
published on GitHub; their features are listed with version markers in `README.md`.

## [Unreleased]

## [1.13.0] - 2026-11-08

### Added
- `kalascan import <FILE>` normalizes Nessus, Nmap, Burp Suite, OWASP ZAP, Nuclei, Qualys and CSV scanner reports into one finding format (`--format text|json|sarif`, `--fail-on`); XML entity declarations are refused.
- `kalascan.toml` configuration file so a team can commit its scan policy (threshold, rules, YARA directory, ignore file, baseline); command-line flags override it.
- `--max-commits` and `--since` bound `--git-history` scans.
- CLI integration tests that run the `kalascan` binary and check output formats and exit codes.
- `[profile.release]` for a smaller, faster release binary; `rust-version = "1.95"` declares the minimum supported Rust.
- `deny.toml` and a `cargo-deny` CI job: RustSec advisories fail the build, licences must be on the allow-list, duplicate crate versions are reported.
- Dependabot restored for Cargo, Docker and GitHub Actions: one grouped minor/patch PR per week with a 7-day cooldown, auto-merged after CI passes.
- Release pipeline: the tag must match `Cargo.toml` and have an entry in this file; the release body is taken from it; a CycloneDX SBOM of the source tree, keyless cosign signatures (`*.sigstore.json`) and a SLSA build-provenance attestation are attached to every release.
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CITATION.cff`, `docs/` (architecture, detection rules, web UI security), issue and pull request templates, OpenSSF Scorecard workflow.

### Changed
- The regex pass covers more source files (`.jsx .tsx .rb .go .rs .lua .pl .psm1 .cs .swift .groovy .gradle`), CI files (`.yml` / `.yaml`, exfiltration / network / supply-chain / secret rules only) and `Dockerfile` / `Makefile` / `Justfile`, so an application repository no longer scores 0 because none of its files were looked at.
- `KS-RAN-004` (Ransom Note) matches whole words only and is `high`; it becomes the critical `Chain: Ransomware` when it sits within 4 KB of a file-encryption rule. In the risk score a single unchained critical finding counts 20 instead of 35; chains and multiple criticals still reach the 70 cap.
- In-place repository scans run only YARA on vendored or minified code (`*.min.js`, `*bundle*.js`, `vendor/`, `dist/`, `node_modules/`), which removed the regex noise from bundled third-party JavaScript.
- `--git-history` reports each finding once, at the commit where it first appeared, instead of once per revision of the file.
- SARIF `tool.driver` carries the KalaScan version; CLI JSON fills `duration_ms`.
- `Cargo.toml` uses the SPDX id `GPL-3.0-only`; `Cargo.lock` picks up the RustSec fixes for rustls, rustls-webpki, wasmtime and crypto-bigint.

### Fixed
- `RUST_LOG` is honoured (the log filter was hard-coded to `kalascan=info`).
- The weekly Security scan no longer fails on historical gitleaks fingerprints from rule examples.

## [1.12.0] - 2026-10-31

### Added
- Registry metadata checks for npm and PyPI packages: manifest confusion, install-script and provenance regressions between versions, lapsed maintainer e-mail domains, AI-vendor repository impersonation.
- `kalascan deps [PATH]` scans every version pinned by `package-lock.json`, `poetry.lock`, `Pipfile.lock` or `requirements.txt`.
- `--secrets`: 208 credential patterns converted from gitleaks (`rules/secrets.toml`, MIT), medium severity, config files included.
- Obfuscator string-table decoding, install-time sandbox tracing of npm scripts / `setup.py` / `.pth` files, GuardDog YARA conventions (`path_include`, `ecosystem`) in `--yara-dir`.
- Rules: fetch-then-eval download cradles, npm `install` scripts as install hooks, hex-encoded API names chained with host recon, aliased `os` / `subprocess` imports in `setup.py`, destructured `child_process`.

### Changed
- Work-stealing scan with one YARA scanner per worker and ASCII word boundaries (drawio: 17 s to 2 s).
- Baseline fingerprints no longer include line numbers; `--update-baseline` writes the file, `--new-only` only reads it.
- `tera` dropped (69 crates); the UI templates use plain substitution. `openapi.yaml` takes its version from the binary.
- Recall on the eval corpus 74 to 81 of 100 malicious samples, 0 of 227 clean false positives.

### Fixed
- Scanner evasions: multibyte context no longer panics and drops a worker's findings; a `/*` string no longer hides later matches; build directories and `kalascan:ignore` markers only apply to the operator's own checkout (`--untrusted` for third-party code on disk).
- Exports: CSV cells never start a formula, JUnit drops XML-illegal control characters, SARIF locations are URIs, Markdown escapes every cell.
- `install.sh` verifies the checksum; the GitHub Action builds from its own ref; README examples run as written.
- Low-entropy rule examples so the gitleaks gate passes.

### Security
- Downloads are time- and size-capped and zip totals count bytes written; API targets on internal hosts are refused; credentials in repository URLs are redacted from logs, history and reports.

## [1.11.0] - 2026-10-31

### Added
- 8 new rules and 5 behaviour chains: remote-code loaders (`new Function('require', …)` + fetch), VS Code extension side-loading, AI API traffic hijack (`ANTHROPIC_BASE_URL` persisted to shell profiles), system discovery, npm spam publishers, escaped `eval` payloads.
- Repackaged copies of the 2,000 most-installed VS Code extensions are flagged through their `repository` field (`rules/popular_extensions.tsv`).
- Dependency-confusion versions, install-time exfiltration and payload chains, zip-slip taint tracking, GitHub Actions workflow checks (pwn request, script injection, unpinned actions), `npm:` / `pypi:` registry targets.
- `kalascan installed`, `kalascan diff`, `kalascan rules`; rules as data in `rules/builtin.toml` with stable ids and examples verified on load; `--rules` for custom rules.
- Labelled eval corpus (`eval/`) with a false-positive gate in CI; IOC extraction with URLhaus lookups; listing and publisher reputation checks.
- `SECURITY.md`.

### Changed
- Eval corpus grown to 100 malicious + 227 clean samples; held-out recall 65% (was 58%), 0 false positives on the 227 clean packages.
- Docker images build natively per architecture and are merged into one manifest; every GitHub Action is pinned to a commit SHA.
- Dependency updates: zip 9, rusqlite 0.41, toml 1.1, tokio 1.54, yara-x 1.22.1, Rust 1.98 image. The local scan database is no longer tracked.

### Fixed
- False positives found by the clean corpus (greedy PowerShell / `bcdedit` regexes, web3 IPC paths, bidi regex ranges, official installers, firebase-tools); legitimate extensions no longer score 100.
- Entropy scanner panic on multi-byte tokens; VSIX entries over 128 MiB are truncated instead of failing the scan; installed-extension tampering is detected.
- Upload body cap raised to 1 GiB; stale `:latest` Docker tags.

### Security
- The API rejects local paths and CLI-only options; `serve` refuses an unauthenticated non-loopback address; git option injection through `base_ref` / `repo_url` is rejected; the spoofable `github.actor` check in CI was fixed.

## [1.10.0] - 2026-10-25

### Added
- `GET /api/sbom[?path=…]`: CycloneDX 1.5 SBOM for a directory under the server working directory (auth required; paths outside it are refused after canonicalization).
- Dashboard bearer token: every fetch attaches the token held in `sessionStorage` (tab-scoped, never persisted) and prompts once on 401.
- linux/arm64 Docker image; the GHCR package is made public after each push.

### Changed
- UI templates and `static/app.css` are embedded in the binary, so `kalascan serve` works from any directory.
- Every remaining hard-coded version string derives from `CARGO_PKG_VERSION`; `openapi.yaml` documents `/api/sbom` and `/api/audit`.

### Fixed
- `POST /scan` with only `repo_url` no longer fails deserialization (LLM fields default).
- Body limit raised so real `.vsix` uploads work; the installer resolves assets through the API and was simplified once the repository went public.

## [1.9.0] - 2026-10-25

### Added
- Parallel file scanning (up to 16 threads) with deterministic finding order.
- `kalascan sbom <dir> [-o file]`: CycloneDX 1.5 SBOM from manifests and lockfiles, offline.
- One-line install script (`install.sh`) for the prebuilt release binaries.

### Changed
- Engine and version strings derive from `CARGO_PKG_VERSION`.
- Clippy-clean code base; CI enforces `-D warnings`; the release matrix caches cargo; the Docker builder no longer needs pkg-config / libssl-dev.

## [1.8.0] - 2026-10-25

### Added
- Multi-user RBAC: `users` table with viewer / operator / admin roles, `kalascan user add|list|remove`, tokens stored as salted SHA-256 and shown once; `KALASCAN_TOKEN` remains a legacy admin token.
- Append-only `audit_log` and the admin-only `GET /api/audit`.
- Prometheus `GET /metrics`, `GET /healthz` liveness endpoint, `GET /openapi.yaml`.
- Export formats `csv`, `junit` and `github` (Actions annotations) for `--format` and `/api/report/{id}/{format}`.
- `kalascan rules` lists the ruleset; `kalascan rules <name>` explains a rule.

### Changed
- Schema v3; queued scans persist their request (API keys stripped) and resume on boot; `KALASCAN_HISTORY_LIMIT` (500) and `KALASCAN_MEMORY_SCANS` (100) bound storage.
- Release builds use rustls so the aarch64 Linux target builds; the GitHub release is created before the assets are uploaded.

### Fixed
- `openapi.yaml` is copied into the Docker builder stage.

[Unreleased]: https://github.com/wahidhendrawan/KalaScan/compare/v1.13.0...HEAD
[1.13.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.12.0...v1.13.0
[1.12.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.11.0...v1.12.0
[1.11.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.10.0...v1.11.0
[1.10.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.9.0...v1.10.0
[1.9.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.8.0...v1.9.0
[1.8.0]: https://github.com/wahidhendrawan/KalaScan/releases/tag/v1.8.0
