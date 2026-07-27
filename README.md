# 🛡️ KalaScan

**Local Git Repository Security & Malware Scanner** — detects malicious code (Information Stealer, Ransomware, Backdoor, Obfuscation, Supply Chain Attack) in GitHub/GitLab repositories using high-speed Rust RegEx scanning and optional AI deep analysis.

<p align="center">
  <img src="https://img.shields.io/badge/rust-1.75+-orange?logo=rust" />
  <img src="https://img.shields.io/badge/license-GPL--3.0-blue" />
  <img src="https://img.shields.io/badge/tests-28%20passed-brightgreen" />
  <img src="https://img.shields.io/badge/docker-ready-2496ED?logo=docker" />
</p>

## Features

### Core Scanning
- **40+ RegEx Rules** across 5 threat categories: exfiltration, sensitive data access, obfuscation, ransomware, supply chain
- **Rust Speed** — compiled binary, multi-threaded WalkDir scanner, zero-copy regex matching
- **Safe by Design** — clones repos read-only via `git clone --depth 1`, never executes any code, auto-cleanup with RAII temp dirs

### AI Deep Analysis
- **Multi-Provider LLM Support**: Ollama (local), OpenAI, DeepSeek, 9Router (local proxy), or any OpenAI-compatible custom endpoint
- LLM evaluates suspicious code with a structured malware analysis system prompt
- Results returned as structured risk assessment JSON (risk score, malware type, threat summary, recommendations)

### Git History Scanning
- **Full Commit History Scan** — walks every commit via `git log` and scans historical file versions with the same RegEx rules
- Detects secrets, malware, and suspicious patterns that were introduced and later removed
- Results annotated with commit hash + file path

### Scan History & Persistence
- **SQLite Database** (`rusqlite` with bundled feature) — all scans saved with full results, timestamps, and risk scores
- Browse scan history in the sidebar dashboard
- Delete old scans with one click

### Export Reports
- **Markdown Report** — clean `.md` file with risk badge, summary table, AI analysis, match details
- **HTML Report** — self-contained dark-themed HTML with inline Tailwind CSS, ready to share or archive

### Web UI
- Professional dark cybersecurity dashboard with scan history sidebar
- Animated risk gauge, sortable match tables, progress indicators
- Status badges (Safe / Warning / High Risk) with color coding
- Download report buttons per scan (MD + HTML)
- localStorage persistence for LLM provider settings

## Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) 1.75+
- Git
- (Optional) AI: [Ollama](https://ollama.ai/), OpenAI key, DeepSeek key, or [9Router](https://github.com/decolua/9router)

### Build & Run

```bash
git clone https://github.com/wahidhendrawan/KalaScan.git
cd KalaScan
cargo build --release
cargo run --release
```

Open **http://127.0.0.1:3000**

### Docker

```bash
# Build & run
docker build -t kalascan .
docker run -p 3000:3000 --add-host host.docker.internal:host-gateway kalascan

# From GitHub Container Registry
docker pull ghcr.io/wahidhendrawan/kalascan:latest
docker run -p 3000:3000 --add-host host.docker.internal:host-gateway ghcr.io/wahidhendrawan/kalascan:latest
```

### Docker Compose

```bash
docker compose up -d
# KalaScan at http://127.0.0.1:3000
```

### LLM Providers

| Provider | Endpoint (auto-configured) | API Key |
|----------|---------------------------|---------|
| **Ollama** | `http://localhost:11434/api/generate` | — |
| **DeepSeek** | `https://api.deepseek.com/v1/chat/completions` | Required |
| **OpenAI** | `https://api.openai.com/v1/chat/completions` | Required |
| **9Router** | `http://localhost:20128/v1/chat/completions` | Required |
| **Custom** | User-defined | Optional |

Settings are auto-saved to browser localStorage.

## Usage

1. Enter a GitHub/GitLab repository URL (e.g., `https://github.com/user/repo.git`)
2. Select LLM provider and configure API key if needed
3. Click **Start Scan**
4. View results: risk score gauge, matched patterns table, AI analysis card
5. Download MD or HTML report
6. Browse scan history in the sidebar

## Architecture

```
KalaScan/
├── src/
│   ├── main.rs            # Axum web server, routes, scan orchestrator
│   ├── scanner.rs         # 40+ RegEx rules, WalkDir scanner, file filter
│   ├── ai_analyzer.rs     # Ollama / OpenAI / DeepSeek / 9Router integration
│   ├── db.rs              # SQLite scan history persistence
│   ├── git_history.rs     # Commit history scanner
│   └── export.rs          # Markdown + HTML report generator
├── templates/
│   ├── index.html         # Dashboard with history sidebar, scan form, results
│   └── result.html        # Detail view with gauge, stats, download buttons
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

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Dashboard |
| `POST` | `/scan` | Start a new scan |
| `POST` | `/api/scan` | Start scan (JSON response) |
| `GET` | `/api/results/:id` | Get scan result |
| `GET` | `/results/:id` | Result detail page |
| `GET` | `/api/history` | List scan history |
| `DELETE` | `/api/history/:id` | Delete scan |
| `GET` | `/api/report/:id/md` | Download Markdown report |
| `GET` | `/api/report/:id/html` | Download HTML report |

## Detection Rules

| Category | Patterns Detected |
|----------|-------------------|
| **Exfiltration** | Discord webhooks, Telegram Bot API tokens, Slack webhooks, AWS keys (`AKIA*`), GitHub tokens (`ghp_*`), generic API key assignments, hardcoded IP addresses |
| **File Access** | Browser profiles (`/AppData/Local/Chrome`), crypto wallets (`wallet.dat`, `metamask`), Discord tokens, SSH keys, `.env`/`.npmrc`, password managers |
| **Obfuscation** | `eval()`/`exec()`, `b64decode` chains, `child_process`/`subprocess`, `os.system`/`os.popen`, PowerShell `-EncodedCommand`, nested encoding, process injection APIs, DLL loading |
| **Ransomware** | File encryption functions (`fernet.encrypt`), shadow copy deletion (`vssadmin`), encrypted file extensions, ransom note text, Bitcoin addresses |
| **Supply Chain** | npm `postinstall`/`preinstall` scripts, typo-squatted package names, remote script download (`curl|sh`), hidden directory installs |

## Risk Scoring

| Score | Level | Recommendation |
|-------|-------|---------------|
| 0–29 | 🟢 Safe | Code appears benign |
| 30–69 | 🟡 Warning | Review suspicious findings manually |
| 70–100 | 🔴 High Risk | Do not execute — possible malware |

## Development

```bash
# Run tests (28 tests)
cargo test

# Build release
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
