# Changelog

All notable changes to KalaScan are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/). Releases before 1.8.0 were not
published on GitHub; their features are listed with version markers in `README.md`.

## [Unreleased]

## [1.15.0] - 2026-11-18

### Added
- Detection: the rules also run on each file with string disguises undone (`'fe'+'tch'`, `\x66` / `\u0066` escapes, `String.fromCharCode(…)` and `bytes([…]).decode()` literals, a reversed literal, `obj['name']`), and a hit that only shows up there is reported on its line.
- Detection: `Chain: Web Page Published as a Package` (an npm package whose entry point is an HTML or SVG document with script written into it: phishing pages and cloned sites served from the registry's CDNs); `Base64-Encoded URL`; `Buffer Decode + eval` (Node's `eval(Buffer.from(blob, 'base64'))`, a lead rather than a verdict); javascript-obfuscator output with mangled names is recognised by its decoder.
- Evaluation: a tuning batch of 80 npm packages dated August 2026 or later in `dev` (`"set": "tune-recent-2026-11"`). Measured on the untouched holdout with ruleset 2026.11.2: 193 → 202 of 302 malicious samples caught (67%, 61-72), the newest npm samples 24 → 31 of 60, and still 0 of 822 clean packages flagged. `eval/results/2026.11.2.json` is the first record written by a run.
- `--format stix`: a STIX 2.1 bundle of the scan (identity, report, one indicator per IOC, an attack-pattern per ATT&CK technique, `indicates` relationships where a finding's matched line holds the URL). Ids are stable for the same scan. Also at `/api/report/{id}/stix`.
- `--format osv`: an OSV malicious-package record (`x_KALASCAN-<scan id>`, a local id, not an assigned MAL- id) for an `npm:name@version` or `pypi:name==version` scan that reached the danger level; refused otherwise. Also at `/api/report/{id}/osv` (422 when refused).
- Evasion-resistance eval (`eval/evasion.py`, `docs/evasion.md`): 10 inert seed packages x 20 rewrites from public malware write-ups, measuring how often a caught payload stays caught. 108 of 122 variants (89%) were still caught at risk 50 when first measured, with string-construction rewrites the weak spot (62%); after the changes below it is 116 of 122 (95%) and 85%. `--baseline eval/evasion-baseline.json` fails when a caught variant is lost.
- `docs/methodology.md`: what KalaScan claims and does not, the threat model, how detection quality is measured, how to reproduce the numbers and the known limits.
- Evaluation: `eval/run_eval.py --summary FILE` writes the aggregate counts of a run (per split and sample set, thresholds 30 / 50 / 70 with Wilson bounds, errors; no sample names). `eval/results/` holds one file per ruleset version.
- `score_breakdown` in the JSON result (and one line in text and Markdown reports): the score model and the parts the risk score is the sum of. Stored with the scan (database schema v5).
- `--score-model v2` (also `score_model` in `kalascan.toml` and in API requests): a weight per finding, fitted on the `dev` split of the evaluation corpus by `eval/fit_weights.py` (`rules/weights.toml`), combined with the accumulation THOR uses; known vulnerabilities are counted apart from the score. On the holdout it is level with v1 at the default gate (193 of 302 malicious, 0 of 457 clean) and adds a range between 30 and 70 that v1 does not have, so v1 stays the default. `docs/scoring.md` has the model and the numbers.
- SARIF rules carry `security-severity` (and the `security` tag), so GitHub Code Scanning shows critical / high / medium / low and its severity gate applies.
- `kalascan rules --coverage` and `docs/coverage.md`: which vectors of the supply-chain attack tree of Ladisa et al. (IEEE S&P 2023) KalaScan covers (6 direct, 17 partial, 5 gaps, 6 payload only, 16 out of scope), and the ATT&CK techniques, MBC objective and vector of every finding. `kalascan rules <id>` prints them for one rule.
- Detection: `Chain: Dependency Confusion Install Hook` (an install script in a package whose version is all nines); `Char-Code Encoded API Name` (`require`, `child_process`, `process` or a URL spelled as decimal character codes); name and version are read from a wheel's `METADATA`, so typo-squat and dependency-confusion checks work on what pip installs.
- Evaluation: 95% Wilson intervals on every rate; `--rule-stats` (hits per class and likelihood ratio for every finding); a second, independent malicious source (100 PyPI packages from pypi_malregistry) and 60 npm packages dated August 2026 or later, both in the holdout; `eval/sample_malicious.py` to draw such sets; 299 more random clean packages in `dev`. Holdout misses are counted, not listed.
- `kalascan guard -- <install command>`: scans what `npm` / `pnpm` / `yarn` / `bun`, `pip` / `uv` or `code` / `cursor` / `windsurf --install-extension` would fetch and runs the command only when nothing reaches `--fail-on-risk` (default 50). `npm ci` and a bare `npm install` audit the lockfile. A package that cannot be scanned blocks the install.
- Data flow inside one Python or JS file: the whole environment, an SSH key or a browser / wallet store followed through variables to a network call, and a download followed to `exec` / `eval` / `new Function` / `node -e`. Reported as `Chain: Credential Exfiltration` / `Chain: Download and Execute`.
- Detection: npm install scripts that run `curl` / `nslookup` next to `$(whoami)` or a dependency-confusion version; dependencies given as an http(s) tarball on someone's own server (`Remote URL Dependency`, PhantomRaven); `setup.py` code that calls a capture service at module level; `Chain: Install-time Reconnaissance` (user or host name read by a `setup.py` install hook); DNS lookups of a host name built from data; shell `whoami` / `hostname` and `os.uname().nodename` as host recon; Telegram bot tokens outside a URL; `__import__('zlib')` / `__import__('base64')` loaders. Code decoded straight into exec is scored like a chain.
- `kalascan installed` also scans the MCP and hook configs of Cursor, Windsurf, Claude Code, Claude Desktop, VS Code and Gemini CLI (of `~/.claude.json`, only its MCP servers).
- Evaluation corpus: a tuning batch of 100 malicious samples (every 2026 PyPI package not used before, 19 from 2025, 40 npm from 2026) in the `dev` split, `"set": "tune-2026-11"`. Measured on the untouched holdout: 82 → 94 of 147 malicious samples caught (PyPI 22 → 33 of 48), none lost, and still 0 of 526 clean packages flagged.
- AI agent files and MCP servers: `SKILL.md`, `CLAUDE.md`, `AGENTS.md`, Cursor and Copilot rule files, MCP configs and Claude Code settings and hooks are scanned for hidden text (Unicode tags, zero-width and bidi characters, directives in HTML comments), instructions to hide actions from the user or override earlier instructions, and the builtin download, exfiltration and credential rules. MCP server code gets the same instruction checks on its tool descriptions. New chains: `Chain: Malicious Agent Instruction` and `Chain: Agent Config Runs Remote Code`.
- `kalascan installed` also lists Claude Code plugins (`~/.claude/plugins/cache`) and skills (`~/.claude/skills`).
- Evaluation corpus: 299 clean packages drawn at random from all of npm and PyPI (`eval/sample_clean.py`), not picked. One legitimate package among them was flagged (fixed below); the clean set is now 526 samples.
- Sandbox: a simulated network inside the isolated container. Names resolve to a loopback stand-in that answers DNS and accepts HTTP and TLS, so the report shows the hosts, request lines and TLS server names a sample asked for, and each host becomes a `sandbox-host` indicator. The container still has no network.
- Sandbox: `--sandbox-runtime <NAME>` / `KALASCAN_SANDBOX_RUNTIME` runs the container under another OCI runtime, for example gVisor's `runsc`.
- Fuzz targets (`fuzz/`, cargo-fuzz) for the report importers, lockfile parsers, archive extraction, rule files, text analyzers, binary triage and emulation, the deobfuscator and the strace parser, with a weekly Fuzz workflow.
- `eval/run_eval.py --scanner guarddog` measures GuardDog on the same corpus.
- Evaluation corpus: 120 fresh malicious samples (2026 npm and PyPI packages, extensions) join the holdout split. The published detection rate is now the holdout figure, 82 of 147 (56%); the earlier 26 of 27 came from too few samples.

### Security
- A failed package download no longer shows credentials from its URL in the scan status, history, reports or the server log.
- A server that started with a token or users keeps requiring auth when its last user is removed or its database cannot be read; it used to grant anonymous admin. `kalascan user remove` prints a note when it removes the last user.
- Requests without valid credentials write at most 30 audit rows per minute, audit details are cut at 512 characters, and `GET /api/audit` returns the newest 200 denied requests plus the newest 200 other entries, so a flood of 401s cannot hide real actions.
- On a loopback server without auth, the DNS-rebinding Host check covers every path, including the dashboard page `/` that embeds scan history.
- Each server log record is one line: CR and LF inside logged values are written as `\r` and `\n`.
- Web API: a target shaped like a marketplace id (`budget.xlsx`) is no longer read from the server's working directory; only the CLI opens a local package file.
- `kalascan serve`: scans resumed after a restart are checked against the current target rules again (`KALASCAN_ALLOW_PRIVATE_TARGETS` included). One that no longer passes is marked `failed: not resumed`, as is a queued upload.
- `kalascan serve`: at most 64 scans are queued or running at once; further submissions get HTTP 429.
- API scans: `llm_endpoint` gets the same internal-address refusal as the scan target, except the built-in local Ollama and 9Router defaults; `KALASCAN_ALLOW_PRIVATE_TARGETS=1` allows it. LLM requests no longer follow redirects, and replies are read through a 1 MiB cap.
- `--git-history`: a file larger than 1 MiB in an old commit is no longer read into memory before it is skipped.
- API, upload and resumed scans run `git clone` / `git fetch` without the server user's credential helpers, `~/.netrc`, ssh keys or agent, and without prompting. Private repositories need credentials in the URL. The CLI is unchanged.
- Sandbox: at most 2 MiB of container stdout and 64 KiB of stderr are held; a container that prints more is stopped and its truncated trace analysed.
- Text output of `scan`, `import`, `diff` and the `deps` package column shows control characters from scanned content as escapes, continues embedded line breaks under `|`, and never starts a line with `::`; `--format github` escapes ESC and other control characters.

### Fixed
- `kalascan serve` stops cleanly on Ctrl-C or SIGTERM (`docker stop`) and removes the temp dirs of its queued and running scans.
- The triage, correlation, deobfuscation and emulation passes run on the blocking pool, so a one-CPU server keeps answering (`/healthz` included) during a scan and the scan timeout can fire.
- ATT&CK techniques of KalaScan's own findings are written out per finding instead of guessed from keywords in the name: `GitHub Actions Script Injection` was Process Injection, `Make File Executable` a script interpreter, and install-time findings were all Event Triggered Execution.
- Four false positives found in a fresh random draw of 297 clean packages: a link to a `.sh` source line inside a webpack `eval` module, a `curl … .EXE` in `circle.yml` counted as reachable from an npm install script, a curl command line kept in a variable read as downloaded content, and zc.buildout's `bootstrap.py` fetching `ez_setup.py`. With the first draw the measured rate on random packages is 5 in 595 (0.8%, 0.4-2.0).
- The eval harness scanned a `sources/` checkout instead of the wheel for some PyPI samples.
- `Chain: Reconnaissance Beacon` no longer fires on a hostname read plus the Telegram API host: agents and bots call it with the user's own token. A bot token written into the code still counts. Malicious recall is unchanged.
- CI: the `false-positives` check runs on every pull request and skips the scan when no detection code or corpus changed. With a paths filter it never reported on Dockerfile- or workflow-only PRs, so Dependabot updates could not be merged.

### Changed
- The Detection eval workflow also runs weekly, so registry drift under the fixed clean corpus shows up without a pull request.
- An oversized package download reports "Response too large" instead of "Package too large".
- Timestamps come from the `time` crate (already in the dependency tree) instead of `chrono`, which RustSec lists as unmaintained (RUSTSEC-2026-0543). New timestamps end in `Z` instead of `+00:00`; both are RFC 3339.
- The crate is a library (`src/lib.rs`) with a thin binary (`src/main.rs`), so the fuzz targets can call the parsers. No behaviour change.

### Changed
- ATT&CK mapping follows Enterprise ATT&CK v20.1: findings formerly under the Defense Evasion tactic are reported under Stealth or Defense Impairment, `T1562` / `T1562.001` / `T1562.006` became `T1685` (Disable or Modify Tools), `T1070.001` / `T1070.002` became `T1685.005` / `T1685.006`, and `T1036.005` and `T1176` carry their current names. Reports and SARIF exported by earlier versions keep the old ids.

### Added
- Dashboard: "Remember key in this browser" keeps the AI provider API key (one per provider) in the browser's localStorage. Off by default; switching it off deletes the saved keys. Switching provider no longer carries a typed key over to another provider.

### Fixed
- Dashboard: the rule count is the real number of built-in rules (it said "50+"), and the "0 code exec" claim is gone: nothing runs unless the sandbox is switched on.
- Dashboard: scan progress shows the server's state and the elapsed time instead of an invented percentage.
- Dashboard: package files can be dropped onto the upload area; the label offered it but only clicking worked.
- Dashboard: errors appear in the page instead of browser alerts.
- Dashboard: keyboard focus is visible on every control, and the upload area and history entries can be reached and activated with the keyboard.

## [1.14.0] - 2026-11-15

### Added
- `kalascan deps` reads `yarn.lock` (classic and Berry), `pnpm-lock.yaml` (v5-v9), `uv.lock` and `Cargo.lock`, and keeps results in `~/.cache/kalascan` (`KALASCAN_CACHE_DIR`) so a package is downloaded and scanned once per KalaScan and ruleset version; `--no-cache` scans everything again.
- `crates:name[@version]` scan targets (crates.io), for `scan`, `diff`, `deps` and the API.
- `Chain: Phishing Redirect Package`: an npm package with no dependencies whose only code sends the browser to a hard-coded site.
- A name cut across two `splitStrings` pieces of a javascript-obfuscator string table (`readF` + `ileSy`) is put back together.
- javascript-obfuscator string tables encoded with `rc4` are decrypted with the keys found at the call sites, so the `Chain: Obfuscated Credential Theft` / `Obfuscated Download and Execute` checks cover them.
- CLI integration tests for `diff`, `deps`, `installed`, `rules`, `sbom`, `import` and the web API (upload, status polling, local-path refusal), all offline.
- CI scans the repository with the freshly built binary (`.kalascanignore` lists the files that hold detection signatures).

### Changed
- The popular-extension list behind `Repackaged Copy of Popular Extension` covers the 10,000 most-installed extensions (was 2,000). Detection on the eval corpus: 85 of 100 malicious samples (was 81), still 0 of 227 clean ones.
- `src/main.rs` is split: the web server moved to `src/server.rs`, the CLI subcommands to `src/commands.rs`, the HTML report to `src/export/html.rs`. No behaviour change.

### Security
- The web server no longer sends permissive CORS headers (`Access-Control-Allow-Origin: *`) and refuses requests from another origin with 403. Before, any web page open in the same browser could queue scans on a loopback server without a token and read its results.
- A loopback server without a token or users answers only requests whose `Host` is `localhost`, `127.0.0.1` or `[::1]` (DNS rebinding).

### Fixed
- `./.kalascanignore` is applied only to a checkout scanned in place. It used to filter every target scanned from that directory, so a pattern such as `src/*` hid findings in downloaded packages; `--ignore <FILE>` still applies to any target.
- Piping output into a command that stops reading (`kalascan scan . --format json | head`) no longer ends in a panic message and exit 101; the run exits 141, as a SIGPIPE death would.

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

[Unreleased]: https://github.com/wahidhendrawan/KalaScan/compare/v1.15.0...HEAD
[1.15.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.14.0...v1.15.0
[1.14.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.13.0...v1.14.0
[1.13.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.12.0...v1.13.0
[1.12.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.11.0...v1.12.0
[1.11.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.10.0...v1.11.0
[1.10.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.9.0...v1.10.0
[1.9.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.8.0...v1.9.0
[1.8.0]: https://github.com/wahidhendrawan/KalaScan/releases/tag/v1.8.0
