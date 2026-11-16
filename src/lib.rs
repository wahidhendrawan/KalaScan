//! KalaScan as a library: `run` is the program; the public modules are the
//! parsers of untrusted input, public so fuzz/ can drive them.

mod ai_analyzer;
mod attack;
mod auth;
mod baseline;
mod cli;
mod commands;
mod correlate;
mod cve;
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
mod server;
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
}

/// The whole program: parse the command line and run the subcommand.
pub async fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("kalascan=info")),
        )
        .with_writer(std::io::stderr)
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
        }) => {
            // kalascan.toml fills in whatever the command line left unset.
            let cfg = cli::Config::load(config.as_deref())?;
            let format = format.or(cfg.format).unwrap_or_else(|| "text".to_string());
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
        Some(Commands::Rules { name }) => {
            commands::run_rules_command(name)?;
        }
        Some(Commands::Installed {
            format,
            min_risk,
            fail_on_risk,
            jobs,
        }) => {
            commands::run_installed_command(&format, min_risk, fail_on_risk, jobs).await?;
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

async fn execute_scan(req: ScanRequest) -> anyhow::Result<ScanResult> {
    let id = uuid::Uuid::new_v4().to_string();
    execute_scan_with_id(req, id).await
}

async fn execute_scan_with_id(req: ScanRequest, id: String) -> anyhow::Result<ScanResult> {
    let shown = redact_credentials(&req.repo_url);
    info!("Starting scan for: {}", shown);

    // A local directory is scanned in place (no clone, no temp dir). This keeps
    // PR scans fast and avoids a second clone when the caller already has a
    // checkout. Packages (.vsix/.zip/.jar/.crx) still go through unpacking.
    let local_path = std::path::Path::new(&req.repo_url);
    if local_path.is_dir() && !vsix::is_vsix_target(&req.repo_url) {
        let path = local_path.to_path_buf();
        info!("Scanning local directory {:?} in place", path);
        return execute_scan_in(req, path, id, None).await;
    }

    let tmp_dir = tempfile::tempdir()?;
    let target_dir = tmp_dir.path().join("source");
    std::fs::create_dir_all(&target_dir)?;

    let is_extension = vsix::is_vsix_target(&req.repo_url);
    let scan_dir = if is_extension {
        info!("Target detected as IDE Extension / Package: {}", shown);
        vsix::unpack_extension(&req.repo_url, &target_dir).await?
    } else {
        info!("Cloning {} to {:?}", shown, target_dir);
        let mut clone_cmd = tokio::process::Command::new("git");
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

    execute_scan_in(req, scan_dir, id, Some(tmp_dir)).await
}

async fn execute_scan_in(
    req: ScanRequest,
    scan_dir: std::path::PathBuf,
    scan_id: String,
    tmp_guard: Option<tempfile::TempDir>,
) -> anyhow::Result<ScanResult> {
    let timestamp = chrono::Utc::now().to_rfc3339();
    let repo_url = redact_credentials(&req.repo_url);
    // The operator's own checkout, scanned in place. Anything cloned,
    // downloaded or uploaded (it has a temp dir) is someone else's code.
    let own_tree = tmp_guard.is_none() && !req.third_party;

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
            own_tree,
        )
    })
    .await
    .map_err(|e| anyhow::anyhow!("Scanner task failed: {}", e))?;

    // Phase 2b: offline typo-squat check, then dependency CVEs via OSV if enabled
    let pkgs = cve::extract_manifest_packages(&scan_dir);
    rule_matches.extend(cve::typosquat_matches(&pkgs));
    rule_matches.extend(cve::own_package_matches(&scan_dir));
    rule_matches.extend(reputation::identity_matches(&scan_dir));
    if let Some((publisher, name, _)) = vsix::parse_marketplace_id(&repo_url) {
        rule_matches.extend(reputation::marketplace_matches(publisher, name).await);
    }
    if let Some(pkg) = vsix::parse_package_target(&repo_url) {
        rule_matches.extend(registry::findings(&pkg, &scan_dir).await);
    }

    // IOCs, and exact-URL threat intel when an abuse.ch key is configured.
    let ioc_dir = scan_dir.clone();
    let mut iocs = tokio::task::spawn_blocking(move || iocs::extract(&ioc_dir, own_tree))
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
    let chains =
        correlate::correlate_package_with(&rule_matches, !cve::is_vscode_extension(&scan_dir));
    rule_matches.extend(chains);
    rule_matches.extend(correlate::redirect_package(&scan_dir));

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

    let deobfuscation_report = if req.deobfuscate {
        info!("Running recursive deobfuscation...");
        Some(deobfuscate::analyze_directory(&scan_dir))
    } else {
        None
    };

    let emulation_report = if req.emulate {
        info!("Running bounded static emulation...");
        Some(emulate::analyze_triage(&scan_dir, &triage_report))
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

    let risk_score = calculate_risk_score(
        &rule_matches,
        &ai_result,
        Some(&triage_report),
        deobfuscation_report.as_ref(),
        emulation_report.as_ref(),
        sandbox_report.as_ref(),
    );

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
    let fetched = tokio::process::Command::new("git")
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

fn calculate_risk_score(
    matches: &[RuleMatch],
    ai: &Option<AiAnalysis>,
    triage: Option<&triage::TriageReport>,
    deobfuscation: Option<&deobfuscate::DeobfuscationReport>,
    emulation: Option<&emulate::EmulationReport>,
    sandbox: Option<&sandbox::SandboxReport>,
) -> u8 {
    use std::collections::HashSet;

    // Count each (file, rule) pair once: the same regex firing 40 times in a
    // minified bundle is one finding, not 40. The old code added every hit at
    // full weight, so a legitimate extension with a few hundred benign matches
    // saturated the static cap by itself and every later pass pushed it to 100.
    let mut seen: HashSet<(&str, &str)> = HashSet::new();
    let (mut critical, mut high, mut medium, mut cve) = (0u16, 0u16, 0u16, 0u16);

    for m in matches {
        // History hits (`<hash>:<path>`) count as the file they belong to.
        let file = git_history::tree_path(&m.file_path);
        if !seen.insert((file, m.matched_pattern.as_str())) {
            continue;
        }
        if m.matched_pattern.starts_with("Known Vulnerability:") {
            cve += 1;
            continue;
        }
        // A chain is two corroborating hard signals by construction. Listing
        // spoofs (invisible characters, look-alike publisher, a popular
        // extension's repository under a stranger's name) and an install
        // script hidden from the registry's manifest have no benign reading
        // at all, so they weigh the same.
        if m.matched_pattern.starts_with(correlate::CHAIN_PREFIX)
            || m.matched_pattern == reputation::INVISIBLE_NAME
            || m.matched_pattern == reputation::PUBLISHER_LOOKALIKE
            || m.matched_pattern == reputation::REPACKAGED_COPY
            || m.matched_pattern == reputation::AI_VENDOR_REPO
            || m.matched_pattern == registry::MANIFEST_CONFUSION
            || m.matched_pattern == iocs::URLHAUS_HIT
        {
            critical += 2;
            continue;
        }
        match m.severity.as_str() {
            "critical" => critical += 1,
            "high" => high += 1,
            "medium" => medium += 1,
            _ => {}
        }
    }

    // Hard signals dominate (exfil endpoints, encoded commands). Soft ones
    // (`process.env`, loopback IPs, `exec()` in a Python extension) are
    // ubiquitous in legitimate code, so they saturate quickly.
    // One critical on its own (a `ghp_x…` placeholder, one `vssadmin` in a
    // forensics playbook) is a lead, not a verdict: a chain or a second
    // critical makes it one. Caps are unchanged.
    let critical_score = match critical {
        0 => 0,
        1 => 20,
        n => (n * 35).min(70),
    };
    let static_score = critical_score + (high * 5).min(15) + medium.min(5);

    // Vulnerable dependencies are a hygiene issue, not malware evidence.
    let cve_score = cve.min(5);

    // The deep passes overlap heavily. One shared budget keeps them from
    // stacking five separate ceilings on the same evidence.
    let dynamic = triage.map_or(0, |r| triage::risk_contribution(r) as u16)
        + deobfuscation.map_or(0, |r| deobfuscate::risk_contribution(r) as u16)
        + emulation.map_or(0, |r| emulate::risk_contribution(r) as u16)
        + sandbox.map_or(0, |r| sandbox::risk_contribution(r) as u16);
    let dynamic_score = dynamic.min(20);

    // AI corroborates the static result; a benign verdict never raises it.
    // TTP is derived from the matches above, so it is reported but not scored
    // twice.
    let ai_score = ai.as_ref().map_or(0, |a| {
        if a.is_malicious {
            (a.risk_score as u16 / 2).min(25)
        } else {
            0
        }
    });

    (static_score + cve_score + dynamic_score + ai_score).min(100) as u8
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
mod risk_score_tests {
    use super::*;

    fn hit(file: &str, rule: &str, severity: &str) -> RuleMatch {
        RuleMatch {
            file_path: file.to_string(),
            line_number: 1,
            matched_pattern: rule.to_string(),
            severity: severity.to_string(),
            context: String::new(),
        }
    }

    fn benign_ai() -> Option<AiAnalysis> {
        Some(AiAnalysis {
            is_malicious: false,
            risk_score: 15,
            malware_type: "None".to_string(),
            threat_summary: String::new(),
            suspicious_lines: Vec::new(),
            recommendation: String::new(),
        })
    }

    #[test]
    fn repeated_benign_hits_do_not_reach_high_risk() {
        // Real case: legitimate Python extension, 310 files, 570 matches and
        // 14 CVEs, AI says benign — the score was pinned at 100.
        let mut matches = Vec::new();
        for file in 0..300 {
            for rule in ["Environment Variable Dump", "Hardcoded IP Address"] {
                for line in 0..3 {
                    let mut m = hit(&format!("out/{}", file), rule, "medium");
                    m.line_number = line;
                    matches.push(m);
                }
            }
            matches.push(hit(&format!("out/{}", file), "exec() Usage", "high"));
        }
        for id in 0..14 {
            matches.push(hit(
                "package.json",
                &format!("Known Vulnerability: GHSA-{} in lodash@4.17.15", id),
                "high",
            ));
        }

        let score = calculate_risk_score(&matches, &benign_ai(), None, None, None, None);
        assert!(score < 70, "benign extension scored {}", score);
    }

    #[test]
    fn single_hit_per_rule_per_file() {
        let many: Vec<_> = (0..50)
            .map(|_| hit("a.js", "Environment Variable Dump", "medium"))
            .collect();
        let one = vec![hit("a.js", "Environment Variable Dump", "medium")];
        assert_eq!(
            calculate_risk_score(&many, &None, None, None, None, None),
            calculate_risk_score(&one, &None, None, None, None, None)
        );
    }

    #[test]
    fn real_malware_chain_stays_high_risk() {
        let matches = vec![
            hit("out/extension.js", "Discord Webhook", "critical"),
            hit("out/extension.js", "SSH Key Access", "high"),
            // What correlate_file emits for that pair in a real scan.
            hit("out/extension.js", correlate::CREDENTIAL_EXFIL, "critical"),
            hit("out/extension.js", "exec() Usage", "high"),
            hit("out/extension.js", "Environment Variable Dump", "medium"),
        ];
        let score = calculate_risk_score(&matches, &benign_ai(), None, None, None, None);
        assert!(score >= 40, "malware chain scored {}", score);
    }

    #[test]
    fn malicious_package_scores_as_critical_not_hygiene() {
        let vuln = vec![hit(
            "requirements.txt",
            "Known Vulnerability: GHSA-x in requests@2.25.1",
            "high",
        )];
        let mal = vec![hit(
            "requirements.txt",
            "Malicious Package: MAL-2024-1 in evilpkg@1.0",
            "critical",
        )];
        assert_eq!(
            calculate_risk_score(&vuln, &None, None, None, None, None),
            1
        );
        assert_eq!(
            calculate_risk_score(&mal, &None, None, None, None, None),
            20
        );
    }

    #[test]
    fn listing_spoof_alone_is_high_risk() {
        let m = vec![hit("package.json", reputation::INVISIBLE_NAME, "critical")];
        assert_eq!(calculate_risk_score(&m, &None, None, None, None, None), 70);
    }

    #[test]
    fn one_unchained_critical_is_a_lead_not_a_verdict() {
        let one = vec![hit("db.js", "Shadow Copy Deletion", "critical")];
        assert_eq!(
            calculate_risk_score(&one, &None, None, None, None, None),
            20
        );
        let two = vec![
            hit("db.js", "Shadow Copy Deletion", "critical"),
            hit("enc.js", "Discord Webhook", "critical"),
        ];
        assert_eq!(
            calculate_risk_score(&two, &None, None, None, None, None),
            70
        );
        let chained = vec![hit("enc.js", correlate::RANSOMWARE, "critical")];
        assert_eq!(
            calculate_risk_score(&chained, &None, None, None, None, None),
            70
        );
    }

    #[test]
    fn benign_ai_never_raises_score() {
        let base = vec![hit("a.js", "exec() Usage", "high")];
        let without = calculate_risk_score(&base, &None, None, None, None, None);
        let with = calculate_risk_score(&base, &benign_ai(), None, None, None, None);
        assert_eq!(without, with);
    }
}
