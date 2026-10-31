use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "kalascan",
    author = "Wahid Hendrawan",
    version,
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
#[allow(clippy::large_enum_variant)]
pub enum Commands {
    /// Start the Web UI dashboard server (default when no subcommand is provided)
    Serve {
        #[arg(short, long, env = "KALASCAN_ADDR", default_value = "127.0.0.1:3000")]
        addr: String,
    },
    /// Scan a Git repository, IDE extension, or local package in headless CLI mode
    Scan {
        /// Target URL (Git repo, VS Code / Open VSX / JetBrains marketplace), registry package (npm:name[@ver], pypi:name[==ver]) or local file path (.vsix, .zip, .jar, .crx)
        target: String,

        /// Output format: text, json, md, html, sarif, csv, junit, github
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

        /// Extra RegEx rules (TOML, same format as rules/builtin.toml); examples are validated on load
        #[arg(long)]
        rules: Option<PathBuf>,

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
    /// Manage API users (RBAC tokens for the web server)
    User {
        #[command(subcommand)]
        action: UserAction,
    },
    /// List built-in detection rules, or explain one by name
    Rules {
        /// Rule name (or unique substring) to explain; omit to list all rules
        name: Option<String>,
    },
    /// Emit a CycloneDX SBOM of the dependencies declared in a directory
    Sbom {
        /// Directory to inspect (package.json, Cargo.lock, requirements.txt, ...)
        path: PathBuf,

        /// Write the SBOM here instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Audit the IDE (VS Code, Cursor, Windsurf, VSCodium) and browser (Chrome, Edge, Brave) extensions installed on this machine
    Installed {
        /// Output format: text or json
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Only list extensions at or above this risk score
        #[arg(long, default_value_t = 0)]
        min_risk: u8,

        /// Exit 1 if any extension scores at or above this risk
        #[arg(long)]
        fail_on_risk: Option<u8>,

        /// Extensions scanned in parallel
        #[arg(long, default_value_t = 4)]
        jobs: usize,
    },
    /// Compare two versions of a package or extension and list capabilities the new one adds
    Diff {
        /// Old version (any scan target, e.g. npm:pkg@1.0.0, publisher.ext@1.2.0, old.vsix)
        old: String,

        /// New version
        new: String,

        /// Output format: text or json
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Exit 1 if a new capability is at or above this severity (critical, high, medium, low)
        #[arg(long)]
        fail_on_new: Option<String>,

        /// Also diff known dependency vulnerabilities (OSV, network)
        #[arg(long)]
        cve: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum UserAction {
    /// Create a user and print its token (shown only once)
    Add {
        name: String,
        /// Role: viewer (read-only), operator (scan), admin (everything)
        #[arg(long, default_value = "operator")]
        role: String,
    },
    /// List users
    List,
    /// Delete a user (its token stops working immediately)
    Remove { name: String },
}
