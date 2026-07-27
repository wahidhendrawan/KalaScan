# KalaScan

**Local Git Repository Security & Malware Scanner** — detects malware indicators (Information Stealer, Ransomware, Backdoor, Obfuscated Code, Supply Chain Attack) in GitHub/GitLab repos using high-speed Rust RegEx rules and optional AI deep analysis via Ollama/OpenAI.

## Features

- **Static RegEx Scan** — 40+ detection rules across 5 categories (exfiltration, file access, obfuscation, ransomware, supply chain)
- **AI Deep Analysis** — optional LLM analysis of suspicious findings via Ollama (local) or OpenAI API
- **Rust Speed** — compiled binary, multi-threaded file walker, zero-copy regex
- **Docker Ready** — multi-stage build, published to GitHub Container Registry
- **Safe by Design** — clones repos read-only, never executes any code, auto-cleanup with RAII
- **Web UI** — dark-themed dashboard at `http://127.0.0.1:3000`

## Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) 1.75+
- Git
- (Optional) [Ollama](https://ollama.ai/) for local AI analysis, or an OpenAI API key

### Build & Run (Rust)

```bash
git clone https://github.com/wahidhendrawan/KalaScan.git
cd KalaScan
cargo build --release
cargo run --release
```

Open **http://127.0.0.1:3000**.

### Docker

```bash
# Build locally
docker build -t kalascan .
docker run -p 3000:3000 kalascan

# Or pull from GitHub Container Registry
docker pull ghcr.io/wahidhendrawan/kalascan:latest
docker run -p 3000:3000 ghcr.io/wahidhendrawan/kalascan:latest

# With Ollama sidecar
docker compose up -d
```

### Using Ollama (Local AI)

```bash
ollama pull llama3
# Run KalaScan, select "Ollama" in UI, set model to "llama3"
```

### Using OpenAI

Select **OpenAI** in the Web UI, enter your API key and model name (e.g., `gpt-4`).

## Usage

1. Enter a GitHub/GitLab repository URL (e.g., `https://github.com/user/repo.git`)
2. Configure AI settings (optional)
3. Click **Start Scan**
4. View results: risk score, matched patterns, AI analysis

## Architecture

```
KalaScan/
├── src/
│   ├── main.rs          # Axum web server, routes, scan orchestrator
│   ├── scanner.rs       # 40+ RegEx rules, WalkDir scanner, file filter
│   └── ai_analyzer.rs   # Ollama / OpenAI API integration
├── templates/
│   ├── index.html       # Main dashboard (Tailwind CSS, dark theme)
│   └── result.html      # JSON result viewer
├── Dockerfile           # Multi-stage container build
├── docker-compose.yml   # KalaScan (+ optional Ollama) stack
├── Cargo.toml
└── README.md
```

## Detection Rules

| Category | Examples |
|----------|----------|
| **Exfiltration** | Discord webhooks, Telegram Bot API, AWS keys, GitHub tokens, IP addresses |
| **File Access** | Browser profiles, crypto wallets, Discord tokens, SSH keys, .env files |
| **Obfuscation** | eval/exec, b64decode chains, child_process, PowerShell encoded commands, hex encoding |
| **Ransomware** | File encryption, shadow copy deletion, ransom notes, Bitcoin addresses |
| **Supply Chain** | Post-install scripts, typo-squatting packages, remote script downloads |

## Risk Scoring

- **0-29**: Safe
- **30-69**: Warning — review findings
- **70-100**: High Risk — do not execute

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).
