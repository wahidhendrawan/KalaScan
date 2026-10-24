# 🛡️ KalaScan

**Security & Malware Scanner for Git Repositories and IDE Extensions** (VS Code, Open VSX, JetBrains, Chrome CRX) — detects malicious code, token stealers, supply chain attacks, and known CVEs using high-speed Rust RegEx rules, YARA rules engine, Shannon entropy analysis, deep static binary triage, and optional AI deep audit.

<p align="center">
  <img src="https://img.shields.io/badge/rust-1.95+-orange?logo=rust" />
  <img src="https://img.shields.io/badge/license-GPL--3.0-blue" />
  <img src="https://img.shields.io/badge/tests-56%20passed-brightgreen" />
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
- Multiple export formats: `--format <text|json|md|html>` and `--output <FILE>`

### AI Deep Analysis
- **Multi-Provider LLM Support**: Ollama (local), OpenAI, DeepSeek, 9Router (local proxy), or any OpenAI-compatible custom endpoint
- Structured malware analysis system prompt returning risk assessment JSON

### Git History Scanning
- **Full Commit History Scan** — walks commits via `git log` and scans historical file versions with RegEx rules

## Quick Start

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
```

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
│   ├── cve.rs             # Manifest dependency extractor & OSV API client
│   ├── ai_analyzer.rs     # Ollama / OpenAI / DeepSeek / 9Router integration
│   ├── db.rs              # SQLite scan history persistence
│   ├── git_history.rs     # Commit history scanner
│   └── export.rs          # Markdown + HTML report generator
├── templates/
│   ├── index.html         # Dashboard with drag-and-drop upload & scan form
│   └── result.html        # Detail view with risk gauge & findings table
├── .github/workflows/
│   ├── ci.yml             # Rust build + test
│   ├── security.yml       # Gitleaks + Trivy container scan
│   ├── dependabot-auto-merge.yml
│   ├── dependency-review.yml
│   └── docker.yml         # Multi-arch build + push to ghcr.io
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
| **YARA Rules** | Reverse shells (`/bin/bash -i`, `nc -e`, `pty.spawn`), crypto wallet drainers (`drainAll`, `signTypedData_v4`), Discord webhook credential stealers |
| **Dependency CVEs** | Known exploited vulnerabilities in `package.json`, `Cargo.lock`, and `requirements.txt` via OSV database |
| **IDE & Extension Malware** | VS Code session/token theft (`getSession`), clipboard snooping (`clipboard.readText`), workspace file exfiltration (`findFiles`), wildcard auto-activation (`*`, `onStartupFinished`), browser extension `<all_urls>` / `debugger` permissions |
| **Ransomware** | File encryption functions (`fernet.encrypt`), shadow copy deletion (`vssadmin`), encrypted extensions, ransom note text |
| **Supply Chain** | npm `postinstall`/`preinstall` scripts, typo-squatted package names, remote script download (`curl|sh`), hidden directory installs |

## Development

```bash
# Run tests (56 tests)
cargo test

# Build release binary
cargo build --release

# Run with debug logging
RUST_LOG=kalascan=debug cargo run

# Custom listen address
KALASCAN_ADDR=0.0.0.0:8080 cargo run --release
```

## CI/CD

- **CI**: `cargo check` → `cargo test` → `cargo build --release`
- **Security**: Gitleaks (secret detection) + Trivy (vuln + secret + misconfig scan)
- **Docker**: Multi-stage build published to `ghcr.io/wahidhendrawan/kalascan` on push to main
- **Dependency Review**: Audits dependency changes on PRs

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).

---

<p align="center">
  <b>⚠️ Never execute untrusted code.</b> KalaScan helps you audit repositories — but always review findings manually before running any code.
</p>
