use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "kalascan",
    author = "Wahid Hendrawan",
    version = "1.6.0",
    about = "🛡️ KalaScan — Local Git Repository & IDE Extension Security and Malware Scanner"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Host address to bind web server (default: 127.0.0.1:3000 or KALASCAN_ADDR)
    #[arg(short, long, env = "KALASCAN_ADDR")]
    pub addr: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start the Web UI dashboard server (default when no subcommand is provided)
    Serve {
        #[arg(short, long, env = "KALASCAN_ADDR", default_value = "127.0.0.1:3000")]
        addr: String,
    },
    /// Scan a Git repository, IDE extension, or local package in headless CLI mode
    Scan {
        /// Target URL (Git repo, VS Code / Open VSX / JetBrains marketplace) or local file path (.vsix, .zip, .jar, .crx)
        target: String,

        /// Output format: text, json, md, html, sarif
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Exit with code 1 if risk score is equal to or greater than threshold (ideal for CI/CD gates)
        #[arg(long)]
        fail_on_risk: Option<u8>,

        /// Path to save export report
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Only report findings absent from the baseline file (requires --baseline)
        #[arg(long)]
        new_only: bool,

        /// Baseline JSON file of known findings; also rewritten with current findings when set
        #[arg(long)]
        baseline: Option<PathBuf>,

        /// Path-glob ignore file (default: .kalascanignore in the working directory, if present)
        #[arg(long)]
        ignore: Option<PathBuf>,

        /// Only scan files changed against --base-ref (fast PR scans)
        #[arg(long)]
        changed_only: bool,

        /// Git ref used as the diff base for --changed-only
        #[arg(long, default_value = "origin/main")]
        base_ref: String,

        /// Enable AI deep analysis
        #[arg(long)]
        ai: bool,

        /// AI LLM provider: ollama, openai, deepseek, 9router, custom
        #[arg(long, default_value = "ollama")]
        llm_provider: String,

        /// AI LLM model name
        #[arg(long, default_value = "llama3")]
        llm_model: String,

        /// AI LLM API key
        #[arg(long, env = "KALASCAN_LLM_KEY")]
        llm_key: Option<String>,

        /// Custom AI LLM API endpoint URL
        #[arg(long, env = "KALASCAN_LLM_ENDPOINT")]
        llm_endpoint: Option<String>,

        /// Scan dependency manifests for known CVEs via OSV API
        #[arg(long)]
        cve: bool,

        /// Custom YARA rules directory
        #[arg(long)]
        yara_dir: Option<PathBuf>,

        /// Scan full git commit history (only applies to Git repositories)
        #[arg(long)]
        git_history: bool,

        /// Enable deep static binary triage with optional capa, FLOSS, and DIE
        #[arg(long)]
        deep_triage: bool,

        /// Recursively decode obfuscated strings and scripts
        #[arg(long)]
        deobfuscate: bool,

        /// Safely emulate supported x86/x64 code to recover stack strings and API calls
        #[arg(long)]
        emulate: bool,

        /// Execute compatible ELF samples in an isolated Docker sandbox
        #[arg(long)]
        sandbox: bool,

        /// Docker image used for sandbox execution
        #[arg(long, default_value = "kalascan-sandbox:latest")]
        sandbox_image: String,
    },
}
