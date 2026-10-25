# 🛡️ KalaScan

**Security & Malware Scanner for Git Repositories and IDE Extensions** (VS Code, Open VSX, JetBrains, Chrome CRX) — detects malicious code, token stealers, supply chain attacks, and known CVEs using high-speed Rust RegEx rules, YARA rules engine, Shannon entropy analysis, deep static binary triage, recursive deobfuscation, safe static emulation, TTP/ATT&CK coverage mapping, opt-in Docker sandboxing, and optional AI deep audit.

<p align="center">
  <img src="https://img.shields.io/badge/rust-1.95+-orange?logo=rust" />
  <img src="https://img.shields.io/badge/license-GPL--3.0-blue" />
  <img src="https://img.shields.io/badge/tests-98%20passed-brightgreen" />
  <img src="https://img.shields.io/badge/docker-ready-2496ED?logo=docker" />
</p>

## Features

### Core Scanning
- **50+ RegEx & YARA Rules** across threat categories: exfiltration, sensitive data access, obfuscation, ransomware, supply chain, and IDE malware
- **Rust Speed** — compiled binary, multi-threaded WalkDir scanner, zero-copy regex matching
- **Safe by Design** — clones repos read-only via `git clone --depth 1`, never executes untrusted code, auto-cleanup with RAII temp dirs

### Multi-Ecosystem Extension Scanning
- **Multi-Source Ingestion** — scan local packages via drag-and-drop file upload (`.vsix`, `.zip`, `.jar`, `.crx`), or scan remote extensions directly by entering an ID or marketplace URL:
  - **VS Code**: Visual Studio Marketplace URLs and `publisher.extension-name` identifiers
  - **Open VSX**: Open-source registry URLs (`open-vsx.org/extension/<namespace>/<name>`)
  - **JetBrains**: IntelliJ / PyCharm / WebStorm plugin archives (`.jar`, `.zip`)
  - **Chrome / Browser**: Extension packages (`.crx`, `.zip`) with `manifest.json` permission checks
- **Safe Unpacking** — automated extraction with zip-slip path traversal guards, targeting runtime payloads (`extension/`, `META-INF/`)
- **IDE Malware Rules**:
  - VS Code session token theft (`getSession`), clipboard harvesting (`clipboard.readText`), unauthorized workspace file access (`findFiles`), wildcard startup activations (`*`, `onStartupFinished`)
  - JetBrains dynamic class loading (`URLClassLoader`, `DexClassLoader`), process execution (`ProcessBuilder`, `Runtime.getRuntime().exec`), reflection tampering (`Method.invoke`, `Field.setAccessible`), raw sockets
  - Browser extension dangerous permissions (`<all_urls>`, `webRequestBlocking`, `debugger`, `nativeMessaging`), script injection (`chrome.tabs.executeScript`), keystroke loggers, cookie theft

### YARA Rules Engine (`yara-x`)
- Built-in pure-Rust YARA rule compilation for generic reverse shells, crypto drainers, and Discord webhook stealers
- Support for loading custom user YARA rules from a directory via `--yara-dir <PATH>`

### Deep Static Binary Triage (v1.3)
- **Binary Metadata** — detects PE, ELF, Mach-O, Java class, WebAssembly, archives, and scripts; extracts SHA-256, architecture, bitness, entrypoint, sections, and imports
- **Packer & Entropy Detection** — identifies UPX, ASPack, MPRESS, Themida, VMProtect, Enigma, and high-entropy/encrypted executable sections
- **Capability Mapping** — maps static rules and binary indicators to MITRE ATT&CK techniques
- **Optional Deep Tools** — integrates `capa`, `FLOSS`, and `DIE` when available, with bounded execution and graceful fallback
- **Safe by Design** — never executes samples; all triage is static and read-only

### Recursive Deobfuscation (v1.4)
- **Multi-Encoding Recovery** — recursively decodes base64, hex escapes/arrays/strings, URL percent encoding, PowerShell `-EncodedCommand`, JS/Python/PowerShell char codes, Unicode escapes, ROT13, single-byte XOR, gzip, and zlib
- **Decode Chains** — follows nested layers up to depth 3, tracking confidence, decoded size, source file, and line number
- **Indicator & ATT&CK Mapping** — reuses the scanner's indicator engine and maps recovered behavior to MITRE ATT&CK
- **Safe by Design** — pure static string and byte analysis; recovered payloads are never executed

### Safe Static Emulation (v1.4)
- **Bounded x86/x64 Emulation** — uses `iced-x86` to emulate entrypoint code for PE, ELF, and Mach-O binaries with strict instruction and memory budgets
- **Import Stubbing** — resolves PE IAT imports to synthetic addresses so API usage can be recorded without calling host functions
- **Stack String Recovery** — reconstructs strings built through `push`/`mov` sequences and writes to mapped memory
- **API & ATT&CK Tracing** — records imported API calls, recovered strings, behavioral indicators, and mapped ATT&CK techniques
- **Safe by Design** — no syscalls, no network access, no sample execution; emulation stops on unsupported instructions or budget exhaustion

### TTP / ATT&CK Coverage (v1.5)
- **Unified Technique Mapping** — aggregates observations from RegEx/YARA matches, static triage capabilities, recursive deobfuscation, static emulation, and sandbox telemetry
- **Kill-Chain Ordering** — groups techniques by ATT&CK tactic in execution order with per-tactic observation counts
- **Coverage Scoring** — reports technique/tactic coverage and contributes a capped risk signal without overriding the primary risk model
- **Safe by Design** — pure metadata aggregation; no sample execution or network access

### Opt-in Docker Sandbox (v1.5)
- **Isolated Execution** — optionally executes host-compatible ELF samples inside a disposable Docker container with `--network none`, read-only root filesystem, `--cap-drop ALL`, `no-new-privileges`, non-root user, and pids/memory/CPU/time limits
- **Strace Telemetry** — captures process creation, network attempts, credential/persistence file access, executable memory, shell/transfer tool usage, and anti-analysis behavior
- **ATT&CK Enrichment** — maps sandbox indicators into the unified TTP report and risk score
- **Graceful Fallback** — if Docker or the sandbox image is unavailable, the scan continues with a clear note; samples are never executed on the host
- **Runtime Requirement** — the KalaScan process needs access to a Docker daemon; when running KalaScan itself in a container, mount the Docker socket or run the CLI on the host
- **Build the Image** — `docker build -t kalascan-sandbox:latest sandbox`

### Entropy & Advanced Obfuscation Analysis
- **Shannon Entropy Analysis**: Scans string literals for high-entropy blobs (> 5.2 entropy on tokens >= 60 chars) indicating encrypted ciphers or packed scripts
- **Invisible Zero-Width Character Detection**: Uncovers hidden unicode steganography (`\u{200B}`, `\u{200C}`, `\u{200D}`, `\u{FEFF}`)
- **Trojan Source Detection (CVE-2021-42574)**: Flags dangerous Bi-Directional override characters disguised as comments
- **Homoglyph Spoofing Detection**: Catches Cyrillic lookalikes mixed into Latin code identifiers

### Dependency CVE Audit (OSV API)
- Automatically inspects project manifests: `package.json` (npm), `Cargo.lock` (Rust), and `requirements.txt` (Python)
- Batch queries the official [OSV (Open Source Vulnerabilities)](https://osv.dev/) database for known security advisories

### Standalone CLI Subcommands (CI/CD Gates)
- Run headless scans in terminal or automated pipelines without starting the web server
- Configurable quality gates via `--fail-on-risk <SCORE>` (exits with code 1 if risk threshold is exceeded)
- Multiple export formats: `--format <text|json|md|html|sarif>` and `--output <FILE>`

### CI Workflow Features (v1.6)
- **SARIF 2.1.0 output** (`--format sarif`) for GitHub Code Scanning, with stable partial fingerprints per finding
- **Baselines** — `--baseline <FILE>` records known findings; `--new-only` reports only findings that are not yet baselined
- **Path suppression** — `.kalascanignore` (or `--ignore <FILE>`) accepts globs such as `src/generated/*` and `*.min.js`
- **Inline suppression** — add `kalascan:ignore` on a line, or `kalascan:ignore-file` anywhere in a file
- **Changed-files scanning** — `--changed-only --base-ref origin/main` restricts the scan to files touched by the PR
- **Raw JSON** is unaffected: the async web API and CLI `json` format still return every finding

### API Authentication
- Set `KALASCAN_TOKEN` to require `Authorization: Bearer <token>` on all routes
- When bound to a non-loopback address without a token, KalaScan logs a prominent warning at startup
- Responses carry a strict `Content-Security-Policy` (self-hosted assets only), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`

### Multi-User Auth & RBAC (v1.8)
- `kalascan user add <name> --role viewer|operator|admin` prints a bearer token once (stored as a salted `sha256`, never recoverable)
- Roles: **viewer** (read results), **operator** (submit/cancel scans), **admin** (view audit log)
- `kalascan user list` / `kalascan user remove <name>`; `KALASCAN_TOKEN` still works as a legacy admin token
- Every submit, cancel, login failure and user change is written to an append-only `audit_log` (`GET /api/audit`, admin only)

### Observability & Standards (v1.8)
- `GET /healthz` — liveness probe; `GET /metrics` — Prometheus metrics (queue depth, active scans, durations, rule hits)
- `GET /openapi.yaml` — OpenAPI 3.0 spec; extra report formats `csv`, `junit`, `github` (workflow annotations)
- `kalascan rules` lists built-in rules; `kalascan rules <name>` explains a rule and shows its pattern

### Persistence Bounds & Resume (v1.8)
- `KALASCAN_HISTORY_LIMIT` (default 500) caps rows in SQLite; `KALASCAN_MEMORY_SCANS` (default 100) caps the in-memory list
- Queued scans are persisted with their request; on restart they are requeued automatically (API keys are stripped before storage)

### Async Web Scans
- `POST /scan` and `POST /api/scan` return `{ "success": true, "result_id": "...", "status": "queued" }` immediately
- Poll `GET /api/scan/{id}/status`; it returns `done: true` plus the full result when the job finishes
- Upload (`POST /api/scan/upload`) follows the same contract; archive unpacking runs on a blocking thread and scanning runs as a background task
- `DELETE /api/scan/{id}` cancels a queued or running scan (aborts the task and releases its temp dir)

### Operational Limits (v1.7)
| Env var | Default | Purpose |
|---------|---------|---------|
| `KALASCAN_MAX_CONCURRENT_SCANS` | `4` | Scans running at once; the rest wait in FIFO order |
| `KALASCAN_SCAN_TIMEOUT_SECS` | `900` | Hard timeout per scan; exceeded scans are marked failed |
| `KALASCAN_SCAN_RATE_LIMIT` | `30` | Submissions allowed per minute (HTTP `429` beyond that) |
| `KALASCAN_TOKEN` | unset | Bearer token required on every route |
| `KALASCAN_HISTORY_LIMIT` | `500` | Scans kept in SQLite; older finished scans are pruned |
| `KALASCAN_MEMORY_SCANS` | `100` | Scans kept in the in-memory cache |

### Local Directory Scans (v1.7)
- Pass a directory path as the target to scan a checkout in place: `kalascan scan . --changed-only --base-ref origin/main`
- No clone is performed, so `--changed-only` uses the real PR diff and finishes faster in CI
- Local paths are read-only; packages (`.vsix`/`.zip`/`.jar`/`.crx`) are still extracted into a temp dir

### Database Migrations (v1.7)
- `PRAGMA user_version` tracks schema state; versions upgrade in place on startup
- Legacy databases gain missing columns automatically and are stamped to the current version

### Self-Hosted UI (v1.7)
- Tailwind is compiled into `static/app.css` (no CDN, no Google Fonts); the UI works fully offline
- Rebuild after editing templates: `npx tailwindcss@3.4.17 -c tailwind.config.js -i tailwind.input.css -o static/app.css --minify`

### AI Deep Analysis
- **Multi-Provider LLM Support**: Ollama (local), OpenAI, DeepSeek, 9Router (local proxy), or any OpenAI-compatible custom endpoint
- Structured malware analysis system prompt returning risk assessment JSON

### Git History Scanning
- **Full Commit History Scan** — walks commits via `git log` and scans historical file versions with RegEx rules

## Quick Start

### Install (prebuilt binary)
```bash
curl -fsSL https://raw.githubusercontent.com/wahidhendrawan/KalaScan/main/install.sh | sh
```

### Build & Run

```bash
git clone https://github.com/wahidhendrawan/KalaScan.git
cd KalaScan
cargo build --release
```

#### Run Web UI
```bash
./target/release/kalascan
# Or with explicit serve command
./target/release/kalascan serve --addr 127.0.0.1:3000
```
Open **http://127.0.0.1:3000**

#### Run Headless CLI Scan
```bash
# Scan a VS Code extension by identifier
kalascan scan ms-python.python

# Scan a Git repository and output JSON
kalascan scan https://github.com/user/repo.git --format json

# Scan the full commit history for secrets or malware that was later removed
kalascan scan https://github.com/user/repo.git --git-history --format md -o history.md

# Quality Gate for CI/CD: fail if risk score >= 70
kalascan scan ./my-extension.vsix --fail-on-risk 70

# Scan with custom YARA rules and save HTML report
kalascan scan target/package.jar --yara-dir ./custom_rules/ --format html -o report.html

# Deep static binary triage (optionally uses capa, FLOSS, and DIE from PATH)
kalascan scan ./suspicious.vsix --deep-triage --format json -o triage.json

# Recursive deobfuscation + bounded static emulation
kalascan scan ./suspicious.vsix --deobfuscate --emulate --format html -o deep-report.html

# Opt-in Docker sandbox execution (requires Docker + kalascan-sandbox image)
docker build -t kalascan-sandbox:latest sandbox
kalascan scan ./suspicious.vsix --sandbox --format json -o sandbox-report.json

# SARIF report for GitHub Code Scanning
kalascan scan https://github.com/user/repo.git --format sarif -o kalascan.sarif

# Baseline: record known findings, then report only new ones in CI
kalascan scan https://github.com/user/repo.git --baseline .kalascan.baseline.json
kalascan scan https://github.com/user/repo.git \
  --baseline .kalascan.baseline.json --new-only --format sarif -o kalascan.sarif

# Restrict a PR scan to changed files
kalascan scan https://github.com/user/repo.git --changed-only --base-ref origin/main

# CI annotations (GitHub Actions) and machine-readable test reports
kalascan scan . --format github
kalascan scan . --format junit -o kalascan-junit.xml
kalascan scan . --format csv -o kalascan.csv

# CycloneDX SBOM from lockfiles and manifests (no network calls)
kalascan sbom . -o sbom.json
```

#### Run with Docker
```bash
docker run --rm -p 3000:3000 ghcr.io/wahidhendrawan/kalascan:latest
```

### Scan performance
- Files are scanned in parallel across available CPU cores (up to 16 workers); findings keep deterministic order

Suppress known noise with a `.kalascanignore` file in the working directory:

```gitignore
# path globs, one per line
src/generated/*
*.min.js
vendor/**
```

Or inline in the scanned code: `eval(payload) // kalascan:ignore` (single line) and
`kalascan:ignore-file` (whole file).

### GitHub Action

```yaml
name: security
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  kalascan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: wahidhendrawan/KalaScan@v1.8.0
        with:
          target: https://github.com/${{ github.repository }}.git
          fail_on_risk: "60"
```

The action installs KalaScan, writes `kalascan.sarif`, and uploads it to GitHub Code Scanning.

### Securing the Web UI

```bash
KALASCAN_TOKEN=change-me kalascan serve --addr 0.0.0.0:3000
```

All requests then need `Authorization: Bearer change-me`.

## Architecture

```
KalaScan/
├── src/
│   ├── main.rs            # Axum web server, scan orchestrator & CLI router
│   ├── cli.rs             # Clap CLI subcommand argument parser
│   ├── vsix.rs            # VSIX, Open VSX, JetBrains & CRX extraction
│   ├── scanner.rs         # 50+ RegEx rules, WalkDir scanner, file filter
│   ├── yara_engine.rs     # YARA rules engine (yara-x) & custom rule loader
│   ├── entropy.rs         # Shannon entropy, Zero-Width, Trojan Source, Homoglyphs
│   ├── attack.rs          # MITRE ATT&CK technique mapping
│   ├── triage.rs          # Deep static binary triage (goblin, capa/FLOSS/DIE)
│   ├── deobfuscate.rs     # Recursive decoding chains & recovered payloads
│   ├── emulate.rs         # Bounded x86/x64 static emulation (iced-x86)
│   ├── sandbox.rs         # Opt-in Docker sandbox runner & strace parser
│   ├── ttp.rs             # Unified ATT&CK technique & kill-chain aggregation
│   ├── cve.rs             # Manifest dependency extractor & OSV API client
│   ├── ai_analyzer.rs     # Ollama / OpenAI / DeepSeek / 9Router integration
│   ├── db.rs              # SQLite scan history persistence & migrations
│   ├── auth.rs            # Multi-user RBAC tokens, principals, audit helpers
│   ├── metrics.rs         # Prometheus counters/gauges (atomic, lock-free)
│   ├── git_history.rs     # Commit history scanner
│   ├── baseline.rs        # Finding fingerprints, baselines & .kalascanignore
│   └── export.rs          # MD + HTML + SARIF + CSV + JUnit + GitHub export
├── templates/
│   ├── index.html         # Dashboard with drag-and-drop upload & scan form
│   └── result.html        # Redirect shim to the single-page result view
├── .github/workflows/
│   ├── ci.yml             # Rust build + test
│   ├── release.yml        # Cross-platform binary upload on tags
│   ├── security.yml       # Gitleaks + Trivy container scan
│   ├── dependabot-auto-merge.yml
│   ├── dependency-review.yml
│   └── docker.yml         # Multi-arch build + push to ghcr.io
├── action.yml             # Composite GitHub Action (SARIF → Code Scanning)
├── sandbox/
│   └── Dockerfile         # Minimal strace-enabled sandbox runtime image
├── Dockerfile             # Multi-stage Rust container build
├── docker-compose.yml     # KalaScan stack
├── Cargo.toml
├── LICENSE                # GPL-3.0
└── README.md
```

## Detection Rules

| Category | Patterns Detected |
|----------|-------------------|
| **Exfiltration** | Discord webhooks, Telegram Bot API tokens, Slack webhooks, AWS keys, GitHub tokens, generic API key assignments, hardcoded IP addresses, browser keyloggers, Java raw sockets |
| **File Access** | Browser profiles, crypto wallets, Discord tokens, SSH keys, `.env`/`.npmrc`, password managers, Chrome cookies/local storage |
| **Obfuscation** | `eval()`/`exec()`, `b64decode` chains, `subprocess`/`os.system`, PowerShell `-EncodedCommand`, process injection APIs, DLL loading, JetBrains classloading & reflection |
| **Advanced Obfuscation** | Shannon high-entropy string blobs (> 5.2), invisible Unicode zero-width characters, Trojan Source BiDi control characters (CVE-2021-42574), confusable Cyrillic homoglyphs |
| **Deep Static Triage** | PE/ELF/Mach-O metadata, SHA-256, section entropy, packer signatures, suspicious imports, capa/FLOSS/DIE capabilities, ATT&CK mapping |
| **Recursive Deobfuscation** | Nested base64/hex/URL/PowerShell/char-code/Unicode/ROT13/XOR/gzip/zlib layers, decoded payload previews, ATT&CK mapping |
| **Safe Static Emulation** | Bounded x86/x64 entrypoint emulation, PE import stubs, API call tracing, stack string recovery, ATT&CK mapping |
| **TTP / ATT&CK Coverage** | Unified technique/tactic aggregation, kill-chain ordering, coverage scoring, capped risk contribution |
| **Docker Sandbox (opt-in)** | Isolated ELF execution, strace process/network/file telemetry, credential & persistence access detection, ATT&CK enrichment, graceful fallback |
| **YARA Rules** | Reverse shells (`/bin/bash -i`, `nc -e`, `pty.spawn`), crypto wallet drainers (`drainAll`, `signTypedData_v4`), Discord webhook credential stealers |
| **Dependency CVEs** | Known exploited vulnerabilities in `package.json`, `Cargo.lock`, and `requirements.txt` via OSV database |
| **IDE & Extension Malware** | VS Code session/token theft (`getSession`), clipboard snooping (`clipboard.readText`), workspace file exfiltration (`findFiles`), wildcard auto-activation (`*`, `onStartupFinished`), browser extension `<all_urls>` / `debugger` permissions |
| **Ransomware** | File encryption functions (`fernet.encrypt`), shadow copy deletion (`vssadmin`), encrypted extensions, ransom note text |
| **Supply Chain** | npm `postinstall`/`preinstall` scripts, typo-squatted package names, remote script download (`curl|sh`), hidden directory installs |

## Development

```bash
# Run tests (98 tests)
cargo test

# Build release binary
cargo build --release

# Rebuild the bundled UI stylesheet after editing templates
npx tailwindcss@3.4.17 -c tailwind.config.js -i tailwind.input.css -o static/app.css --minify

# Run with debug logging
RUST_LOG=kalascan=debug cargo run

# Custom listen address
KALASCAN_ADDR=0.0.0.0:8080 cargo run --release
```

## CI/CD

- **CI**: `cargo check` → `cargo test` → `cargo build --release`
- **Release**: tagged `v*` builds upload cross-platform `kalascan` binaries via `.github/workflows/release.yml`
- **Security**: Gitleaks (secret detection) + Trivy (vuln + secret + misconfig scan)
- **Docker**: Multi-stage build published to `ghcr.io/wahidhendrawan/kalascan` on push to main
- **Dependency Review**: Audits dependency changes on PRs

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).

---

<p align="center">
  <b>⚠️ Never execute untrusted code.</b> KalaScan helps you audit repositories — but always review findings manually before running any code.
</p>
