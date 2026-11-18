//! KalaScan as a library: `run` is the program; the public modules are the
//! parsers of untrusted input, public so fuzz/ can drive them.

pub mod agent;
mod ai_analyzer;
mod attack;
mod auth;
mod baseline;
mod cli;
mod commands;
mod correlate;
mod cve;
pub mod dataflow;
mod db;
pub mod deobfuscate;
mod diff;
pub mod emulate;
pub mod entropy;
mod export;
mod git_history;
pub mod import;
mod installed;
mod iocs;
pub mod lockfile;
mod metrics;
pub mod obfuscator;
mod registry;
mod reputation;
pub mod sandbox;
pub mod scanner;
mod score;
mod server;
mod taxonomy;
pub mod triage;
mod ttp;
pub mod vsix;
pub mod workflow;
mod yara_engine;
pub mod zipslip;

use clap::Parser;
use cli::{Cli, Commands};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::{error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub repo_url: String,
    #[serde(default)]
    pub llm_provider: String,
    #[serde(default)]
    pub llm_model: String,
    #[serde(default)]
    pub llm_api_key: Option<String>,
    #[serde(default)]
    pub llm_endpoint: Option<String>,
    #[serde(default)]
    pub ai_analysis_enabled: bool,
    #[serde(default)]
    pub check_cve: Option<bool>,
    #[serde(default)]
    pub yara_dir: Option<String>,
    /// Extra RegEx rules TOML (CLI-only, like yara_dir)
    #[serde(default)]
    pub rules_file: Option<String>,
    #[serde(default)]
    pub git_history: bool,
    /// `--git-history` bounds: newest commits walked, and `git log --since`.
    #[serde(default)]
    pub history_max_commits: Option<usize>,
    #[serde(default)]
    pub history_since: Option<String>,
    #[serde(default)]
    pub deep_triage: bool,
    #[serde(default)]
    pub deobfuscate: bool,
    #[serde(default)]
    pub emulate: bool,
    #[serde(default)]
    pub sandbox: bool,
    #[serde(default)]
    pub sandbox_image: Option<String>,
    #[serde(default)]
    pub sandbox_runtime: Option<String>,
    /// Only report findings absent from `baseline` (CI new-findings mode)
    #[serde(default)]
    pub new_only: bool,
    /// Baseline JSON path; when set the current findings are also re-recorded
    #[serde(default)]
    pub baseline: Option<String>,
    /// Path-glob ignore file (default: .kalascanignore when present)
    #[serde(default)]
    pub ignore: Option<String>,
    /// Scan only files changed vs `base_ref` (PR mode)
    #[serde(default)]
    pub changed_only: bool,
    #[serde(default)]
    pub base_ref: Option<String>,
    /// Also report hard-coded credentials (gitleaks patterns, `--secrets`).
    #[serde(default)]
    pub secrets: bool,
    /// A local directory holding someone else's code (`kalascan installed`).
    /// Never read from the API: remote targets are untrusted by construction.
    #[serde(skip)]
    pub third_party: bool,
    /// Risk score model: `v2` for the fitted weights, otherwise v1.
    #[serde(default)]
    pub score_model: Option<String>,
}

/// The current time as an RFC 3339 UTC timestamp, for scans, users and audit rows.
pub(crate) fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("a UTC time formats as RFC 3339")
}

/// `https://user:token@host/x` -> `https://host/x`, also inside error text
/// such as git's stderr. Scan targets are shown in logs, the audit log, the
/// history table and every report.
pub(crate) fn redact_credentials(text: &str) -> String {
    static USERINFO: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/@\s]+@").unwrap()
    });
    USERINFO.replace_all(text, "$1").into_owned()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleMatch {
    pub file_path: String,
    pub line_number: usize,
    pub matched_pattern: String,
    pub severity: String,
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAnalysis {
    pub is_malicious: bool,
    pub risk_score: u8,
    pub malware_type: String,
    pub threat_summary: String,
    pub suspicious_lines: Vec<String>,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: String,
    pub repo_url: String,
    pub timestamp: String,
    pub total_files: usize,
    pub scanned_files: usize,
    pub total_matches: usize,
    pub risk_score: u8,
    pub ai_analysis: Option<AiAnalysis>,
    pub rule_matches: Vec<RuleMatch>,
    #[serde(default)]
    pub triage: Option<triage::TriageReport>,
    #[serde(default)]
    pub deobfuscation: Option<deobfuscate::DeobfuscationReport>,
    #[serde(default)]
    pub emulation: Option<emulate::EmulationReport>,
    #[serde(default)]
    pub ttp: Option<ttp::TtpReport>,
    #[serde(default)]
    pub sandbox: Option<sandbox::SandboxReport>,
    pub status: String,
    /// Wall-clock duration of the scan, when it ran to completion.
    #[serde(default)]
    pub duration_ms: Option<u64>,
    /// External URLs / IPs the scanned code refers to.
    #[serde(default)]
    pub iocs: Vec<iocs::Ioc>,
    /// The parts `risk_score` is the sum of (capped at 100).
    #[serde(default)]
    pub score_breakdown: Option<score::ScoreBreakdown>,
}

/// Log writer: stderr, with CR and LF inside a record escaped. A repo URL,
/// a scan id or git's stderr with a line break in it otherwise starts a
/// second line that reads as a record of its own.
struct OneLinePerRecord;

impl std::io::Write for OneLinePerRecord {
    // tracing-subscriber hands over each record whole, its newline last.
    fn write(&mut self, record: &[u8]) -> std::io::Result<usize> {
        let text = String::from_utf8_lossy(record);
        let body = text.strip_suffix('\n').unwrap_or(&text);
        let line = body.replace('\r', "\\r").replace('\n', "\\n") + "\n";
        std::io::stderr().write_all(line.as_bytes())?;
        Ok(record.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stderr().flush()
    }
}

/// The whole program: parse the command line and run the subcommand.
pub async fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("kalascan=info")),
        )
        .with_writer(|| OneLinePerRecord)
        .init();

    // `kalascan … | head` closes stdout early and println! panics (exit 101
    // plus a backtrace hint). Exit the way a SIGPIPE death reports instead.
    // Not 0: a truncated run never reached its --fail-on-risk gate. SIGPIPE
    // itself stays ignored so a dropped client cannot kill `serve`.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if info
            .payload_as_str()
            .is_some_and(|m| m.contains("failed printing to stdout"))
        {
            std::process::exit(141);
        }
        default_hook(info);
    }));

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Scan {
            target,
            config,
            format,
            fail_on_risk,
            output,
            new_only,
            baseline,
            update_baseline,
            ignore,
            untrusted,
            secrets,
            changed_only,
            base_ref,
            ai,
            llm_provider,
            llm_model,
            llm_key,
            llm_endpoint,
            cve,
            yara_dir,
            rules,
            git_history,
            max_commits,
            since,
            deep_triage,
            deobfuscate,
            emulate,
            sandbox,
            sandbox_image,
            sandbox_runtime,
            score_model,
        }) => {
            // kalascan.toml fills in whatever the command line left unset.
            // In someone else's checkout (--untrusted) ./kalascan.toml is that
            // author's policy (ignore globs, a baseline): only --config counts.
            let cfg = if untrusted && config.is_none() {
                cli::Config::default()
            } else {
                cli::Config::load(config.as_deref())?
            };
            let format = format.or(cfg.format).unwrap_or_else(|| "text".to_string());
            // The flag is checked by clap; a typo in kalascan.toml must not
            // quietly fall back to v1.
            let score_model = score_model.or(cfg.score_model);
            if score_model
                .as_deref()
                .is_some_and(|m| m != "v1" && m != "v2")
            {
                anyhow::bail!("score_model must be \"v1\" or \"v2\"");
            }
            let baseline = baseline.or(cfg.baseline);
            let new_only = new_only || cfg.new_only.unwrap_or(false);
            if (new_only || update_baseline) && baseline.is_none() {
                anyhow::bail!(
                    "--new-only and --update-baseline need --baseline (flag or kalascan.toml)"
                );
            }
            // Written only on request: --new-only reads the baseline, never updates it.
            let baseline_path = baseline.clone().filter(|_| update_baseline);
            let path_str = |p: std::path::PathBuf| p.to_string_lossy().to_string();
            let req = ScanRequest {
                repo_url: target,
                llm_provider,
                llm_model,
                llm_api_key: llm_key,
                llm_endpoint,
                ai_analysis_enabled: ai,
                check_cve: Some(cve || cfg.cve.unwrap_or(false)),
                yara_dir: yara_dir.or(cfg.yara_dir).map(path_str),
                rules_file: rules.or(cfg.rules).map(path_str),
                git_history: git_history || cfg.git_history.unwrap_or(false),
                history_max_commits: max_commits.or(cfg.max_commits),
                history_since: since.or(cfg.since),
                deep_triage: deep_triage || cfg.deep_triage.unwrap_or(false),
                deobfuscate: deobfuscate || cfg.deobfuscate.unwrap_or(false),
                emulate: emulate || cfg.emulate.unwrap_or(false),
                sandbox,
                sandbox_image: Some(sandbox_image),
                sandbox_runtime,
                new_only,
                baseline: baseline.map(path_str),
                ignore: ignore.or(cfg.ignore).map(path_str),
                changed_only,
                base_ref: Some(
                    base_ref
                        .or(cfg.base_ref)
                        .unwrap_or_else(|| "origin/main".to_string()),
                ),
                secrets: secrets || cfg.secrets.unwrap_or(false),
                third_party: untrusted,
                score_model,
            };
            commands::run_cli_scan(
                req,
                format,
                fail_on_risk.or(cfg.fail_on_risk),
                output,
                baseline_path,
            )
            .await?;
        }
        Some(Commands::Serve { addr }) => {
            server::start_web_server(&addr).await?;
        }
        Some(Commands::User { action }) => {
            commands::run_user_command(action)?;
        }
        Some(Commands::Rules { name, coverage }) => {
            commands::run_rules_command(name, coverage)?;
        }
        Some(Commands::Installed {
            format,
            min_risk,
            fail_on_risk,
            jobs,
        }) => {
            commands::run_installed_command(&format, min_risk, fail_on_risk, jobs).await?;
        }
        Some(Commands::Guard {
            fail_on_risk,
            jobs,
            command,
        }) => {
            commands::run_guard_command(&command, fail_on_risk, jobs).await?;
        }
        Some(Commands::Deps {
            path,
            format,
            include_dev,
            min_risk,
            fail_on_risk,
            jobs,
            max,
            no_cache,
        }) => {
            commands::run_deps_command(
                &path,
                &format,
                include_dev,
                min_risk,
                fail_on_risk,
                jobs,
                max,
                no_cache,
            )
            .await?;
        }
        Some(Commands::Diff {
            old,
            new,
            format,
            fail_on_new,
            cve,
        }) => {
            commands::run_diff_command(&old, &new, &format, fail_on_new.as_deref(), cve).await?;
        }
        Some(Commands::Sbom { path, output }) => {
            commands::run_sbom_command(&path, output.as_deref())?;
        }
        Some(Commands::Import {
            file,
            format,
            output,
            fail_on,
        }) => {
            commands::run_import_command(&file, &format, output.as_deref(), fail_on.as_deref())?;
        }
        None => {
            // clap already reads KALASCAN_ADDR. Loopback like `serve`: 0.0.0.0
            // made a bare `kalascan` refuse to start without auth.
            let addr = cli.addr.unwrap_or_else(|| "127.0.0.1:3000".to_string());
            server::start_web_server(&addr).await?;
        }
    }

    Ok(())
}

tokio::task_local! {
    /// Set around a CLI scan (see `operator_scan`).
    pub(crate) static OPERATOR_SCAN: ();
}

/// The CLI is the operator's own tool: its scans may use the host's git
/// identity and an LLM on the local network. False for API and requeued
/// scans, whose remote and LLM endpoint a caller chose.
pub(crate) fn operator_scan() -> bool {
    OPERATOR_SCAN.try_with(|_| ()).is_ok()
}

/// `git` for a remote. An API caller's remote gets none of the server
/// user's credentials (helpers, ~/.netrc, ssh keys and agent, config
/// headers) and no prompt: an operator-role user cloned a repository that
/// only the server's stored token could read. `empty_home` stands in for
/// HOME, where curl looks for .netrc.
fn git_command(empty_home: &std::path::Path) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new("git");
    if !operator_scan() {
        cmd.env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("HOME", empty_home)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env_remove("GIT_ASKPASS")
            .env_remove("SSH_ASKPASS")
            .env(
                "GIT_SSH_COMMAND",
                "ssh -F /dev/null -o BatchMode=yes -o IdentityAgent=none \
                 -o IdentityFile=none -o IdentitiesOnly=yes",
            )
            .args(["-c", "credential.helper="]);
    }
    cmd
}

/// CLI entry point; the server calls `execute_scan_with_id`.
async fn execute_scan(req: ScanRequest) -> anyhow::Result<ScanResult> {
    let id = uuid::Uuid::new_v4().to_string();
    OPERATOR_SCAN.scope((), execute_scan_with_id(req, id)).await
}

async fn execute_scan_with_id(req: ScanRequest, id: String) -> anyhow::Result<ScanResult> {
    let shown = redact_credentials(&req.repo_url);
    info!("Starting scan for: {}", shown);

    // A local directory is scanned in place (no clone, no temp dir). This keeps
    // PR scans fast and avoids a second clone when the caller already has a
    // checkout. Packages (.vsix/.zip/.jar/.crx) still go through unpacking.
    // An existing directory is a directory whatever its name ends with
    // (an installed extension folder `x-1.0.0.zip` used to fail as a package);
    // only a registry or marketplace id still goes to unpack_extension.
    let local_path = std::path::Path::new(&req.repo_url);
    let t = req.repo_url.trim();
    if local_path.is_dir()
        && vsix::parse_package_target(t).is_none()
        && vsix::parse_marketplace_id(t).is_none()
    {
        let path = local_path.to_path_buf();
        info!("Scanning local directory {:?} in place", path);
        return execute_scan_in(req, path, id, None, false).await;
    }

    let tmp_dir = tempfile::tempdir()?;
    let target_dir = tmp_dir.path().join("source");
    std::fs::create_dir_all(&target_dir)?;

    let is_extension = vsix::is_vsix_target(&req.repo_url);
    let scan_dir = if is_extension {
        info!("Target detected as IDE Extension / Package: {}", shown);
        // Only the CLI reads a package file from this machine: an API target
        // is downloaded or cloned, never opened on the server's disk.
        vsix::unpack_extension(&req.repo_url, &target_dir, operator_scan()).await?
    } else {
        info!("Cloning {} to {:?}", shown, target_dir);
        let mut clone_cmd = git_command(tmp_dir.path());
        clone_cmd.arg("clone");
        if !req.git_history {
            clone_cmd.arg("--depth").arg("1");
        }
        // The raw URL (credentials included) goes to git only; logs and
        // errors use `shown`. `--`: a repo_url like `--upload-pack=<cmd>`
        // must never parse as an option. kill_on_drop: a timed-out or
        // cancelled scan must not leave git cloning into a deleted temp dir.
        let clone_output = clone_cmd
            .arg("--")
            .arg(&req.repo_url)
            .arg(&target_dir)
            .kill_on_drop(true)
            .output()
            .await
            .map_err(|e| anyhow::anyhow!("Git not found: {}. Install git: brew install git", e))?;

        if !clone_output.status.success() {
            let stderr = redact_credentials(&String::from_utf8_lossy(&clone_output.stderr));
            return Err(anyhow::anyhow!(
                "Git clone failed for {}: {}",
                shown,
                stderr
            ));
        }
        target_dir
    };

    execute_scan_in(req, scan_dir, id, Some(tmp_dir), is_extension).await
}

/// `package`: `scan_dir` was extracted from an archive, so even its `.git`
/// is the author's (see `scanner::Tree`).
async fn execute_scan_in(
    req: ScanRequest,
    scan_dir: std::path::PathBuf,
    scan_id: String,
    tmp_guard: Option<tempfile::TempDir>,
    package: bool,
) -> anyhow::Result<ScanResult> {
    let timestamp = crate::now_rfc3339();
    let repo_url = redact_credentials(&req.repo_url);
    // The operator's own checkout, scanned in place. Anything cloned,
    // downloaded or uploaded (it has a temp dir) is someone else's code.
    let tree = if tmp_guard.is_none() && !req.third_party {
        scanner::Tree::Own
    } else if package {
        scanner::Tree::Package
    } else {
        scanner::Tree::Checkout
    };
    let own_tree = tree == scanner::Tree::Own;

    info!(
        "Source ready at {:?}. Running static + YARA + entropy scan...",
        scan_dir
    );

    // Phase 1: optional changed-only filter (PR mode)
    let changed_files = if req.changed_only && !vsix::is_vsix_target(&repo_url) {
        let base = req.base_ref.as_deref().unwrap_or("origin/main");
        info!("Collecting files changed vs {}...", base);
        git_changed_files(&scan_dir, base).await
    } else {
        None
    };

    // Phase 2: Static rule + YARA + Entropy check
    let custom_yara = req.yara_dir.clone().map(std::path::PathBuf::from);
    // Fail the scan on a broken rules file rather than silently matching nothing.
    let mut extra_rules = match &req.rules_file {
        Some(path) => scanner::load_rules_file(std::path::Path::new(path))?,
        None => Vec::new(),
    };
    if req.secrets {
        extra_rules.extend(scanner::secret_rules());
    }
    let scan_path = scan_dir.clone();
    let changed_clone = changed_files.clone();
    let (total_files, scanned_files, mut rule_matches) = tokio::task::spawn_blocking(move || {
        scanner::scan_directory_filtered(
            &scan_path,
            custom_yara.as_deref(),
            &extra_rules,
            changed_clone.as_ref(),
            tree,
        )
    })
    .await
    .map_err(|e| anyhow::anyhow!("Scanner task failed: {}", e))?;

    // Phase 2b: offline typo-squat check, then dependency CVEs via OSV if enabled
    let pkgs = cve::extract_manifest_packages(&scan_dir);
    rule_matches.extend(cve::typosquat_matches(&pkgs));
    rule_matches.extend(cve::own_package_matches(&scan_dir));
    // An unpacked package, not a repository: a web app's own checkout has
    // `"main": "index.html"` too (NW.js), and it has a `.git`.
    if !own_tree && !scan_dir.join(".git").exists() {
        rule_matches.extend(cve::web_page_entry(&scan_dir));
    }
    rule_matches.extend(reputation::identity_matches(&scan_dir));
    if let Some((publisher, name, _)) = vsix::parse_marketplace_id(&repo_url) {
        rule_matches.extend(reputation::marketplace_matches(publisher, name).await);
    }
    if let Some(pkg) = vsix::parse_package_target(&repo_url) {
        rule_matches.extend(registry::findings(&pkg, &scan_dir).await);
    }

    // IOCs, and exact-URL threat intel when an abuse.ch key is configured.
    let ioc_dir = scan_dir.clone();
    let mut iocs = tokio::task::spawn_blocking(move || iocs::extract(&ioc_dir, tree))
        .await
        .unwrap_or_default();
    if let Ok(key) = std::env::var("URLHAUS_AUTH_KEY") {
        if !key.trim().is_empty() && !iocs.is_empty() {
            info!("Checking {} IOCs against URLhaus...", iocs.len().min(100));
            rule_matches.extend(iocs::urlhaus_matches(&iocs, key.trim()).await);
        }
    }
    if req.check_cve.unwrap_or(true) && !pkgs.is_empty() {
        info!("Auditing {} manifest packages with OSV API...", pkgs.len());
        let cve_matches = cve::check_vulnerabilities(&pkgs).await;
        rule_matches.extend(cve_matches);
    }

    // Cross-file chains, once every current-tree finding is in (history hits
    // are old snapshots and must not complete a chain).
    let chain_dir = scan_dir.clone();
    let mut rule_matches = tokio::task::spawn_blocking(move || {
        let chains =
            correlate::correlate_package_with(&rule_matches, !cve::is_vscode_extension(&chain_dir));
        rule_matches.extend(chains);
        rule_matches.extend(correlate::redirect_package(&chain_dir));
        rule_matches
    })
    .await
    .map_err(|e| anyhow::anyhow!("Correlation task failed: {}", e))?;

    // Phase 2c: Full git commit history scan
    if req.git_history && !vsix::is_vsix_target(&repo_url) {
        info!("Scanning full git commit history at {:?}...", scan_dir);
        let history_matches = git_history::scan_git_history(
            &scan_dir,
            req.history_max_commits
                .unwrap_or(git_history::DEFAULT_MAX_COMMITS),
            req.history_since.as_deref(),
        )
        .await;
        info!("Git history scan found {} matches", history_matches.len());
        rule_matches.extend(history_matches);
    }

    // Phase 2d: baseline / ignore filtering (CI mode)
    // ./.kalascanignore describes the operator's own checkout. Applied to a
    // package fetched while standing in that directory, its `src/*` would
    // hide the package's findings; --ignore is explicit and always applies.
    let ignore_path = req
        .ignore
        .as_ref()
        .map(std::path::PathBuf::from)
        .or_else(|| own_tree.then(|| std::path::PathBuf::from(".kalascanignore")));
    let ignore_set = ignore_path
        .as_deref()
        .map(baseline::IgnoreSet::load)
        .unwrap_or_default();
    if let Some(path) = ignore_path.as_ref().filter(|_| !ignore_set.is_empty()) {
        info!("Applying ignore rules from {:?}", path);
    }
    let baseline_set = match req.baseline.as_ref() {
        Some(p) if req.new_only => {
            let set = baseline::load_baseline(std::path::Path::new(p))?;
            info!("Loaded {} baselined findings from {}", set.len(), p);
            Some(set)
        }
        _ => None,
    };
    let total_before_filter = rule_matches.len();
    rule_matches = baseline::apply_filters(rule_matches, &ignore_set, baseline_set.as_ref());
    if total_before_filter != rule_matches.len() {
        info!(
            "Filtered {} findings (ignored/baselined); {} remain",
            total_before_filter - rule_matches.len(),
            rule_matches.len()
        );
    }

    info!(
        "Scan complete: {} files scanned, {} matches found",
        scanned_files,
        rule_matches.len()
    );

    // Phase 2d: Deep static binary triage
    info!("Running static binary triage...");
    let triage_report = triage::analyze_directory(&scan_dir, &rule_matches, req.deep_triage).await;

    // CPU-bound like the scanner pass, so off the async workers too: inline,
    // a one-worker server (1-CPU container) answered nothing, /healthz
    // included, until the pass returned, and the scan timeout could not fire.
    let deobfuscation_report = if req.deobfuscate {
        info!("Running recursive deobfuscation...");
        let dir = scan_dir.clone();
        Some(
            tokio::task::spawn_blocking(move || deobfuscate::analyze_directory(&dir))
                .await
                .map_err(|e| anyhow::anyhow!("Deobfuscation task failed: {}", e))?,
        )
    } else {
        None
    };

    let emulation_report = if req.emulate {
        info!("Running bounded static emulation...");
        let (dir, triage) = (scan_dir.clone(), triage_report.clone());
        Some(
            tokio::task::spawn_blocking(move || emulate::analyze_triage(&dir, &triage))
                .await
                .map_err(|e| anyhow::anyhow!("Emulation task failed: {}", e))?,
        )
    } else {
        None
    };

    let sandbox_report = if req.sandbox {
        info!("Running Docker-isolated sandbox execution...");
        let config = sandbox::SandboxConfig {
            image: req
                .sandbox_image
                .clone()
                .unwrap_or_else(|| "kalascan-sandbox:latest".to_string()),
            runtime: req.sandbox_runtime.clone(),
            ..Default::default()
        };
        let mut report = sandbox::analyze_triage(&scan_dir, &triage_report, &config).await;
        rule_matches.extend(sandbox::trace_install(&scan_dir, &config, &mut report).await);
        for (host, file) in sandbox::contacted_hosts(&report) {
            iocs.push(iocs::Ioc {
                kind: "sandbox-host".to_string(),
                value: host.clone(),
                host,
                files: vec![file],
            });
        }
        Some(report)
    } else {
        None
    };

    let ttp_report = ttp::build(
        &rule_matches,
        Some(&triage_report),
        deobfuscation_report.as_ref(),
        emulation_report.as_ref(),
        sandbox_report.as_ref(),
    );

    // Phase 3: AI analysis
    let ai_result = if req.ai_analysis_enabled && !rule_matches.is_empty() {
        info!("Running AI deep analysis...");

        let context_snippets: Vec<String> = rule_matches
            .iter()
            .map(|m| {
                format!(
                    "File: {}\nLine {}: {}\nContext: {}",
                    m.file_path, m.line_number, m.matched_pattern, m.context
                )
            })
            .collect();

        let combined_prompt = context_snippets.join("\n\n---\n\n");

        let analysis = ai_analyzer::analyze_with_llm(
            &req.llm_provider,
            &req.llm_model,
            &req.llm_api_key,
            &req.llm_endpoint,
            &combined_prompt,
        )
        .await;

        match analysis {
            Ok(a) => Some(a),
            Err(e) => {
                error!("AI analysis error: {}", e);
                None
            }
        }
    } else {
        None
    };

    let score_breakdown = score::calculate(
        req.score_model.as_deref(),
        &rule_matches,
        &ai_result,
        Some(&triage_report),
        deobfuscation_report.as_ref(),
        emulation_report.as_ref(),
        sandbox_report.as_ref(),
    );
    let risk_score = score_breakdown.total();

    let result = ScanResult {
        id: scan_id.clone(),
        repo_url,
        timestamp,
        total_files,
        scanned_files,
        total_matches: rule_matches.len(),
        risk_score,
        ai_analysis: ai_result,
        rule_matches,
        triage: Some(triage_report),
        deobfuscation: deobfuscation_report,
        emulation: emulation_report,
        ttp: Some(ttp_report),
        sandbox: sandbox_report,
        status: "completed".to_string(),
        duration_ms: None,
        iocs,
        score_breakdown: Some(score_breakdown),
    };

    info!("Scan complete. ID: {}", scan_id);

    Ok(result)
}

/// Resolve the set of files changed between `base_ref` and HEAD inside a clone.
/// Returns `None` on any failure so callers fall back to a full scan.
async fn git_changed_files(
    repo: &std::path::Path,
    base_ref: &str,
) -> Option<std::collections::HashSet<std::path::PathBuf>> {
    // base_ref comes from the API request and is passed to `git fetch` / `git
    // diff` as a positional arg; `--upload-pack=<cmd>` would run a command.
    if base_ref.starts_with('-') {
        warn!("Rejected base_ref {:?}: looks like a git option", base_ref);
        return None;
    }

    // Try to make the base ref available in shallow clones. Ignore failures:
    // the ref may already exist locally.
    let remote_ref = base_ref.strip_prefix("origin/").unwrap_or(base_ref);
    // An API scan's clone sits alone in the scan's temp dir.
    let fetched = git_command(repo.parent().unwrap_or(repo))
        .arg("-C")
        .arg(repo)
        .args(["fetch", "--depth", "1", "origin", remote_ref])
        .kill_on_drop(true)
        .output()
        .await;

    let run_diff = |range: &str| {
        let repo = repo.to_path_buf();
        let range = range.to_string();
        async move {
            tokio::process::Command::new("git")
                .arg("-C")
                .arg(repo)
                .args(["diff", "--name-only", &range])
                .kill_on_drop(true)
                .output()
                .await
                .ok()
        }
    };

    let range = format!("{}...HEAD", base_ref);
    let output = run_diff(&range).await?;
    // Shallow-clone fallback: diff against the freshly fetched FETCH_HEAD.
    let output = if output.status.success() {
        output
    } else if fetched.as_ref().is_ok_and(|f| f.status.success()) {
        run_diff("FETCH_HEAD...HEAD").await?
    } else {
        output
    };
    if !output.status.success() {
        info!(
            "git diff against {} failed; falling back to full scan",
            base_ref
        );
        return None;
    }

    let changed: std::collections::HashSet<std::path::PathBuf> =
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(std::path::PathBuf::from)
            .collect();

    if changed.is_empty() {
        info!("No changed files vs {}; scanning all files", base_ref);
        return None;
    }
    info!("Restricting scan to {} changed files", changed.len());
    Some(changed)
}

#[cfg(test)]
mod git_injection_tests {
    use super::*;

    fn git(dir: &std::path::Path, args: &[&str]) {
        let ok = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .unwrap()
            .status
            .success();
        assert!(ok, "git {:?} failed", args);
    }

    /// A clone with a real `origin`, so an injected `--upload-pack` would run.
    fn repo_with_origin() -> (tempfile::TempDir, std::path::PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let origin = tmp.path().join("origin");
        std::fs::create_dir(&origin).unwrap();
        git(&origin, &["init", "-q"]);
        std::fs::write(origin.join("a.txt"), "x").unwrap();
        git(&origin, &["add", "."]);
        git(
            &origin,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "commit",
                "-qm",
                "init",
            ],
        );
        git(tmp.path(), &["clone", "-q", "origin", "clone"]);
        let clone = tmp.path().join("clone");
        (tmp, clone)
    }

    #[tokio::test]
    async fn base_ref_cannot_inject_git_options() {
        let (tmp, clone) = repo_with_origin();
        let marker = tmp.path().join("pwned");
        let evil = format!("--upload-pack=touch {}", marker.display());
        assert!(git_changed_files(&clone, &evil).await.is_none());
        assert!(!marker.exists(), "injected --upload-pack ran");
    }

    /// A remote that answers 401 to everything, like a private repository.
    async fn private_remote() -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/private.git", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let _ = sock.read(&mut [0u8; 4096]).await;
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"x\"\r\n\
                          Content-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
            }
        });
        url
    }

    #[tokio::test]
    async fn only_a_cli_scan_offers_the_host_git_credentials() {
        let (tmp, clone) = repo_with_origin();
        let marker = tmp.path().join("helper-ran");
        git(
            &clone,
            &["remote", "set-url", "origin", &private_remote().await],
        );
        // Stands in for the server user's stored token.
        let helper = format!(
            "!f() {{ touch {}; echo username=dummy; echo password=dummy; }}; f",
            marker.display()
        );
        git(&clone, &["config", "credential.helper", &helper]);

        assert!(git_changed_files(&clone, "no-such-ref").await.is_none());
        assert!(!marker.exists(), "an API scan asked the credential helper");

        OPERATOR_SCAN
            .scope((), git_changed_files(&clone, "no-such-ref"))
            .await;
        assert!(marker.exists(), "a CLI scan lost its credential helper");
    }

    #[tokio::test]
    async fn api_scan_clones_without_the_host_git_config() {
        let (tmp, _) = repo_with_origin();
        let req: ScanRequest = serde_json::from_value(serde_json::json!({
            "repo_url": format!("file://{}", tmp.path().join("origin").display()),
            "check_cve": false
        }))
        .unwrap();
        let result = execute_scan_with_id(req, "id".to_string()).await.unwrap();
        assert_eq!(result.total_files, 1);
    }

    #[tokio::test]
    async fn repo_url_cannot_inject_git_options() {
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("pwned");
        let req: ScanRequest = serde_json::from_value(serde_json::json!({
            "repo_url": format!("--upload-pack=touch {}", marker.display()),
            "ai_analysis_enabled": false,
            "llm_provider": "ollama",
            "llm_model": "llama3"
        }))
        .unwrap();
        assert!(execute_scan(req).await.is_err());
        assert!(!marker.exists(), "injected --upload-pack ran");
    }
}

#[cfg(test)]
mod blocking_pass_tests {
    use super::*;
    use std::future::Future;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Log(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Log {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Inline, the scan future ran from the pass's log line to the end of
    /// the scan in one poll: nothing else got the worker meanwhile.
    #[test]
    fn deobfuscate_pass_returns_the_worker_to_the_runtime() {
        let log = Log::default();
        let writer = log.clone();
        let _capture = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_writer(move || writer.clone())
                .finish(),
        );
        let dir = tempfile::tempdir().unwrap();
        for i in 0..20 {
            std::fs::write(
                dir.path().join(format!("{}.js", i)),
                "eval(atob('YWxlcnQoMSk='));\n".repeat(200),
            )
            .unwrap();
        }
        let req: ScanRequest = serde_json::from_value(serde_json::json!({
            "repo_url": dir.path(),
            "check_cve": false,
            "deobfuscate": true,
        }))
        .unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _entered = rt.enter();
        let mut scan = std::pin::pin!(execute_scan_in(
            req,
            dir.path().to_path_buf(),
            "test".to_string(),
            None,
            false
        ));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        let mut yielded_in_pass = false;
        while scan.as_mut().poll(&mut cx).is_pending() {
            yielded_in_pass |= String::from_utf8_lossy(&log.0.lock().unwrap())
                .contains("Running recursive deobfuscation");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(
            yielded_in_pass,
            "the deobfuscate pass ran on the async worker"
        );
    }
}
