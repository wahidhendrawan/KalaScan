//! The CLI subcommands other than `serve`: `scan`, `user`, `sbom`, `import`,
//! `deps`, `installed`, `diff`, `rules`, and the text report.

use crate::*;
use cli::UserAction;
use std::sync::Arc;

pub(crate) fn run_user_command(action: UserAction) -> anyhow::Result<()> {
    db::init_db()?;
    match action {
        UserAction::Add { name, role } => {
            let role = auth::Role::parse(&role).ok_or_else(|| {
                anyhow::anyhow!("Invalid role '{}'; use viewer, operator or admin", role)
            })?;
            match auth::create_user(&name, role) {
                Ok(token) => {
                    auth::audit("cli", "user.add", Some(&name), None);
                    println!(
                        "User '{}' created ({}).\n\nToken (store it now; it is not shown again):\n\n  {}",
                        name,
                        role.as_str(),
                        token
                    );
                }
                Err(e) => anyhow::bail!("Failed to create user '{}': {}", name, e),
            }
        }
        UserAction::List => {
            let users = auth::list_users()?;
            if users.is_empty() {
                println!("No users yet. Create one with: kalascan user add <name> --role operator");
                return Ok(());
            }
            for u in users {
                println!(
                    "{:8} {} (created {}, last used {})",
                    u.role,
                    u.name,
                    u.created_at,
                    u.last_used_at.as_deref().unwrap_or("never")
                );
            }
        }
        UserAction::Remove { name } => {
            if auth::remove_user(&name)? {
                auth::audit("cli", "user.remove", Some(&name), None);
                println!("User '{}' removed", name);
            } else {
                eprintln!("User '{}' not found", name);
                std::process::exit(2);
            }
        }
    }
    Ok(())
}

pub(crate) fn run_sbom_command(
    path: &std::path::Path,
    output: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    if !path.is_dir() {
        anyhow::bail!("{} is not a directory", path.display());
    }
    let packages = cve::extract_manifest_packages(path);
    let sbom = export::export_cyclonedx(&packages, path);
    match output {
        Some(out) => {
            std::fs::write(out, &sbom)?;
            println!(
                "SBOM written to {} ({} components)",
                out.display(),
                packages.len()
            );
        }
        None => println!("{}", sbom),
    }
    Ok(())
}

/// `kalascan import`: normalize another scanner's report.
pub(crate) fn run_import_command(
    file: &std::path::Path,
    format: &str,
    output: Option<&std::path::Path>,
    fail_on: Option<&str>,
) -> anyhow::Result<()> {
    let imported = import::import(file)?;
    if imported.truncated {
        eprintln!(
            "warning: stopped at {} findings; the rest of {} was not imported",
            import::MAX_FINDINGS,
            file.display()
        );
    }
    let content = match format {
        "json" => import::format_json(&imported, file),
        "sarif" => import::format_sarif(&imported),
        _ => import::format_text(&imported, file),
    };
    match output {
        Some(out) => {
            std::fs::write(out, &content)?;
            println!("Report successfully saved to: {:?}", out);
        }
        None => println!("{}", content),
    }
    if let Some(threshold) = fail_on {
        let limit = import::rank(threshold);
        if imported
            .findings
            .iter()
            .any(|f| import::rank(f.severity) <= limit)
        {
            eprintln!("Finding at or above '{}' severity", threshold);
            std::process::exit(1);
        }
    }
    Ok(())
}

/// Critical findings and chains of a result, for one-line summaries.
fn strong_findings(r: &ScanResult) -> Vec<String> {
    let mut names: Vec<String> = r
        .rule_matches
        .iter()
        .filter(|m| {
            m.severity == "critical" || m.matched_pattern.starts_with(correlate::CHAIN_PREFIX)
        })
        .map(|m| m.matched_pattern.clone())
        .collect();
    names.sort();
    names.dedup();
    names
}

/// What `kalascan deps` reports for one package, and what its cache keeps.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct DepResult {
    risk_score: u8,
    critical: Vec<String>,
}

/// Results of earlier `kalascan deps` runs: a published `name@version`
/// never changes, so its scan need not be repeated. One file per KalaScan
/// and ruleset version: new rules must look at every package again.
/// `KALASCAN_CACHE_DIR`, else `~/.cache/kalascan`.
fn deps_cache_path() -> Option<std::path::PathBuf> {
    let dir = std::env::var_os("KALASCAN_CACHE_DIR")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
            Some(std::path::PathBuf::from(home).join(".cache/kalascan"))
        })?;
    Some(dir.join(format!(
        "deps-{}-{}.json",
        env!("CARGO_PKG_VERSION"),
        scanner::RULESET_VERSION
    )))
}

/// `kalascan deps`: download and scan every package a lockfile pins.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_deps_command(
    path: &std::path::Path,
    format: &str,
    include_dev: bool,
    min_risk: u8,
    fail_on_risk: Option<u8>,
    jobs: usize,
    max: usize,
    no_cache: bool,
) -> anyhow::Result<()> {
    let locked = lockfile::read(path, include_dev);
    if locked.is_empty() {
        anyhow::bail!(
            "no package-lock.json, yarn.lock, pnpm-lock.yaml, poetry.lock, Pipfile.lock, uv.lock, \
             pinned requirements.txt or Cargo.lock in {}",
            path.display()
        );
    }
    if locked.len() > max {
        eprintln!(
            "{} packages locked; scanning the first {} (--max)",
            locked.len(),
            max
        );
    }

    let cache_path = deps_cache_path().filter(|_| !no_cache);
    // An unreadable or damaged cache is an empty one.
    let mut cache: std::collections::BTreeMap<String, DepResult> = cache_path
        .as_ref()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();

    let permits = Arc::new(tokio::sync::Semaphore::new(jobs.max(1)));
    let mut tasks = tokio::task::JoinSet::new();
    let mut rows = Vec::new();
    for pkg in locked.into_iter().take(max) {
        if let Some(known) = cache.get(&pkg.target()) {
            rows.push((pkg, known.clone()));
            continue;
        }
        let permits = permits.clone();
        tasks.spawn(async move {
            let _permit = permits.acquire_owned().await;
            let mut req: ScanRequest = serde_json::from_value(serde_json::json!({
                "repo_url": pkg.target(),
                "check_cve": false,
            }))
            .expect("static request");
            req.third_party = true;
            (pkg, execute_scan(req).await)
        });
    }
    eprintln!(
        "Scanning {} locked packages ({} from the cache)...",
        tasks.len(),
        rows.len()
    );
    let (scanned, mut failed) = (tasks.len(), 0);
    while let Some(joined) = tasks.join_next().await {
        let (pkg, result) = joined?;
        match result {
            Ok(r) => {
                let result = DepResult {
                    risk_score: r.risk_score,
                    critical: strong_findings(&r),
                };
                cache.insert(pkg.target(), result.clone());
                rows.push((pkg, result));
            }
            Err(e) => {
                failed += 1;
                eprintln!("  failed {}: {}", pkg.target(), e);
            }
        }
    }
    if let Some(path) = cache_path.filter(|_| scanned > failed) {
        // Best effort: a read-only home must not fail the audit.
        let saved = path
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .and_then(|_| std::fs::write(&path, serde_json::to_vec(&cache)?));
        if let Err(e) = saved {
            eprintln!("  cache not saved to {}: {}", path.display(), e);
        }
    }
    rows.sort_by(|a, b| b.1.risk_score.cmp(&a.1.risk_score).then(a.0.cmp(&b.0)));

    let shown: Vec<_> = rows
        .iter()
        .filter(|(_, r)| r.risk_score >= min_risk)
        .collect();
    if format == "json" {
        let out: Vec<_> = shown
            .iter()
            .map(|(p, r)| {
                serde_json::json!({
                    "package": p.target(),
                    "source": p.source,
                    "dev": p.dev,
                    "risk_score": r.risk_score,
                    "critical": r.critical,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("{:>4}  {:<56} CRITICAL FINDINGS", "RISK", "PACKAGE");
        for (p, r) in &shown {
            println!(
                "{:>4}  {:<56} {}",
                r.risk_score,
                p.target(),
                r.critical.join(", ")
            );
        }
        eprintln!("{} scanned, {} failed", rows.len(), failed);
    }
    if let Some(threshold) = fail_on_risk {
        if rows.iter().any(|(_, r)| r.risk_score >= threshold) {
            std::process::exit(1);
        }
    }
    Ok(())
}

pub(crate) async fn run_installed_command(
    format: &str,
    min_risk: u8,
    fail_on_risk: Option<u8>,
    jobs: usize,
) -> anyhow::Result<()> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or_else(|| anyhow::anyhow!("cannot locate the home directory"))?;
    let found = installed::discover(std::path::Path::new(&home));
    eprintln!("Scanning {} installed extensions...", found.len());

    let permits = Arc::new(tokio::sync::Semaphore::new(jobs.max(1)));
    let mut tasks = tokio::task::JoinSet::new();
    for ext in found {
        let permits = permits.clone();
        tasks.spawn(async move {
            let _permit = permits.acquire_owned().await;
            // Offline and in place: no OSV calls, nothing copied or executed.
            let mut req: ScanRequest = serde_json::from_value(serde_json::json!({
                "repo_url": ext.path.to_string_lossy(),
                "check_cve": false,
            }))
            .expect("static request");
            req.third_party = true;
            (ext, execute_scan(req).await)
        });
    }
    let mut rows = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        let (ext, result) = joined?;
        match result {
            Ok(r) => rows.push((ext, r)),
            Err(e) => eprintln!("  failed {}: {}", ext.path.display(), e),
        }
    }
    rows.sort_by(|a, b| {
        b.1.risk_score
            .cmp(&a.1.risk_score)
            .then(a.0.name.cmp(&b.0.name))
    });

    let strong = strong_findings;
    let shown: Vec<_> = rows
        .iter()
        .filter(|(_, r)| r.risk_score >= min_risk)
        .collect();
    if format == "json" {
        let out: Vec<_> = shown
            .iter()
            .map(|(ext, r)| {
                serde_json::json!({
                    "app": ext.app,
                    "extension": ext.name,
                    "path": ext.path,
                    "risk_score": r.risk_score,
                    "critical": strong(r),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!(
            "{:>4}  {:<16} {:<48} CRITICAL FINDINGS",
            "RISK", "APP", "EXTENSION"
        );
        for (ext, r) in &shown {
            println!(
                "{:>4}  {:<16} {:<48} {}",
                r.risk_score,
                ext.app,
                ext.name,
                strong(r).join(", ")
            );
        }
    }
    if let Some(threshold) = fail_on_risk {
        if rows.iter().any(|(_, r)| r.risk_score >= threshold) {
            std::process::exit(1);
        }
    }
    Ok(())
}

pub(crate) async fn run_diff_command(
    old: &str,
    new: &str,
    format: &str,
    fail_on_new: Option<&str>,
    cve: bool,
) -> anyhow::Result<()> {
    let request = |target: &str| -> anyhow::Result<ScanRequest> {
        Ok(serde_json::from_value(serde_json::json!({
            "repo_url": target,
            "check_cve": cve,
        }))?)
    };
    // Sequential: both may download from the same registry.
    let old_result = execute_scan(request(old)?).await?;
    let new_result = execute_scan(request(new)?).await?;
    let d = diff::diff(&old_result, &new_result);
    match format {
        "json" => println!("{}", serde_json::to_string_pretty(&d)?),
        _ => print!("{}", diff::format_text(&d)),
    }
    if let Some(threshold) = fail_on_new {
        if !["critical", "high", "medium", "low"].contains(&threshold) {
            anyhow::bail!("--fail-on-new must be critical, high, medium or low");
        }
        let limit = diff::severity_rank(threshold);
        if d.new_capabilities
            .iter()
            .any(|c| diff::severity_rank(&c.severity) <= limit)
        {
            eprintln!("New capability at or above '{}' severity", threshold);
            std::process::exit(1);
        }
    }
    Ok(())
}

pub(crate) fn run_rules_command(name: Option<String>) -> anyhow::Result<()> {
    let rules = scanner::build_rules();
    match name {
        Some(query) => {
            let q = query.to_lowercase();
            let matches: Vec<_> = rules
                .iter()
                .filter(|r| r.name.to_lowercase().contains(&q) || r.id.to_lowercase() == q)
                .collect();
            match matches.as_slice() {
                [rule] => {
                    println!(
                        "Rule: {} {}  [{}, {}]",
                        rule.id, rule.name, rule.severity, rule.category
                    );
                    println!("Ruleset: {}", scanner::RULESET_VERSION);
                    println!();
                    println!("{}", rule.description);
                    println!();
                    println!("Pattern: {}", rule.pattern.as_str());
                }
                [] => {
                    eprintln!(
                        "Unknown rule '{}'. Use `kalascan rules` to list rules.",
                        query
                    );
                    std::process::exit(2);
                }
                many => {
                    eprintln!("'{}' is ambiguous; matches:", query);
                    for r in many {
                        println!("  {}", r.name);
                    }
                    std::process::exit(2);
                }
            }
        }
        None => {
            println!("Ruleset version: {}", scanner::RULESET_VERSION);
            println!(
                "{:<11} {:8}  {:<34} {:<14} DESCRIPTION",
                "ID", "SEVERITY", "RULE", "CATEGORY"
            );
            for r in rules.iter() {
                let desc = if r.description.len() > 50 {
                    format!("{}…", r.description.chars().take(50).collect::<String>())
                } else {
                    r.description.to_string()
                };
                println!(
                    "{:<11} {:8}  {:<34} {:<14} {}",
                    r.id, r.severity, r.name, r.category, desc
                );
            }
        }
    }
    Ok(())
}

pub(crate) async fn run_cli_scan(
    req: ScanRequest,
    format: String,
    fail_on_risk: Option<u8>,
    output: Option<std::path::PathBuf>,
    baseline_out: Option<std::path::PathBuf>,
) -> anyhow::Result<()> {
    let started = Instant::now();
    let mut result = execute_scan(req).await?;
    result.duration_ms = Some(started.elapsed().as_millis() as u64);

    // `--update-baseline` (exclusive with --new-only, so these are all findings).
    if let Some(path) = baseline_out {
        baseline::save_baseline(&path, &result.rule_matches)?;
        eprintln!(
            "Baseline updated at {} ({} findings)",
            path.display(),
            result.rule_matches.len()
        );
    }

    let output_content = match format.to_lowercase().as_str() {
        "json" => serde_json::to_string_pretty(&result)?,
        "md" | "markdown" => export::export_markdown(&result),
        "html" => export::export_html(&result),
        "sarif" => export::export_sarif(&result),
        "csv" => export::export_csv(&result),
        "junit" | "junit.xml" => export::export_junit(&result),
        "github" => export::export_github(&result),
        _ => format_cli_text(&result),
    };

    if let Some(out_path) = output {
        std::fs::write(&out_path, &output_content)?;
        println!("Report successfully saved to: {:?}", out_path);
    } else {
        println!("{}", output_content);
    }

    if let Some(threshold) = fail_on_risk {
        if result.risk_score >= threshold {
            eprintln!(
                "\n❌ Quality Gate Failed: Risk score {} >= threshold {}",
                result.risk_score, threshold
            );
            std::process::exit(1);
        }
    }

    Ok(())
}

fn format_cli_text(result: &ScanResult) -> String {
    let mut out = String::new();
    out.push_str("============================================================\n");
    out.push_str("🛡️  KalaScan Security & Malware Audit Report\n");
    out.push_str("============================================================\n");
    out.push_str(&format!("Target:        {}\n", result.repo_url));
    out.push_str(&format!("Scan ID:       {}\n", result.id));
    out.push_str(&format!("Timestamp:     {}\n", result.timestamp));
    out.push_str(&format!(
        "Files Scanned: {} / {}\n",
        result.scanned_files, result.total_files
    ));
    out.push_str(&format!("Total Matches: {}\n", result.total_matches));

    let level = match export::risk_score_to_level(result.risk_score) {
        "danger" => "🔴 HIGH RISK (Possible Malware)",
        "warning" => "🟡 WARNING (Suspicious)",
        _ => "🟢 SAFE",
    };
    out.push_str(&format!(
        "Risk Score:    {} / 100 [{}]\n",
        result.risk_score, level
    ));
    out.push_str("------------------------------------------------------------\n");

    if result.rule_matches.is_empty() {
        out.push_str("No malicious patterns or high-risk vulnerabilities detected.\n");
    } else {
        out.push_str("FINDINGS:\n");
        for (i, m) in result.rule_matches.iter().enumerate() {
            out.push_str(&format!(
                "\n[{}] [{}] {}\n     File:    {}:{}\n     Context: {}\n",
                i + 1,
                m.severity.to_uppercase(),
                m.matched_pattern,
                m.file_path,
                m.line_number,
                m.context.trim()
            ));
        }
    }

    if let Some(ai) = &result.ai_analysis {
        out.push_str("\n------------------------------------------------------------\n");
        out.push_str("AI DEEP ANALYSIS:\n");
        out.push_str(&format!("Malware Type:   {}\n", ai.malware_type));
        out.push_str(&format!("Threat Summary: {}\n", ai.threat_summary));
        out.push_str(&format!("Recommendation: {}\n", ai.recommendation));
    }

    if let Some(triage) = &result.triage {
        out.push_str("\n------------------------------------------------------------\n");
        out.push_str("DEEP STATIC TRIAGE:\n");
        out.push_str(&format!("Files Analyzed: {}\n", triage.files_scanned));
        out.push_str(&format!("Binaries:       {}\n", triage.binaries.len()));
        out.push_str(&format!("Capabilities:   {}\n", triage.capabilities.len()));
        out.push_str(&format!(
            "ATT&CK Techniques: {}\n",
            triage.attack_techniques.len()
        ));
        if triage.deep {
            let available: Vec<String> = triage
                .tools
                .iter()
                .filter(|tool| tool.available)
                .map(|tool| tool.name.clone())
                .collect();
            out.push_str(&format!(
                "Deep Tools:     {}\n",
                if available.is_empty() {
                    "none available".to_string()
                } else {
                    available.join(", ")
                }
            ));
        }
        for binary in &triage.binaries {
            out.push_str(&format!(
                "\nBinary: {} [{} {}] entropy {:.2}\n",
                binary.path,
                binary.file_type,
                binary.architecture.as_deref().unwrap_or("unknown"),
                binary.entropy
            ));
            out.push_str(&format!("  SHA-256: {}\n", binary.sha256));
            if let Some(packer) = &binary.packer {
                out.push_str(&format!(
                    "  Packer:  {} ({}) - {}\n",
                    packer.name, packer.confidence, packer.evidence
                ));
            }
            if !binary.indicators.is_empty() {
                out.push_str(&format!("  Indicators: {}\n", binary.indicators.join("; ")));
            }
        }
        if !triage.attack_techniques.is_empty() {
            out.push_str("\nATT&CK Techniques:\n");
            for technique in &triage.attack_techniques {
                out.push_str(&format!(
                    "  {} {} [{}]\n",
                    technique.id, technique.name, technique.tactic
                ));
            }
        }
    }

    if let Some(deobfuscation) = &result.deobfuscation {
        out.push_str("\n------------------------------------------------------------\n");
        out.push_str("DEOBFUSCATION:\n");
        out.push_str(&format!(
            "Files Analyzed: {}\n",
            deobfuscation.files_scanned
        ));
        out.push_str(&format!(
            "Artifacts:      {}\n",
            deobfuscation.artifacts.len()
        ));
        for artifact in &deobfuscation.artifacts {
            out.push_str(&format!(
                "\n[{}] {}:{} ({})\n",
                artifact.confidence.to_uppercase(),
                artifact.file_path,
                artifact.line_number,
                artifact.encoding
            ));
            out.push_str(&format!(
                "  Decoded: {}\n",
                artifact.decoded.replace('\n', " ")
            ));
            if !artifact.indicators.is_empty() {
                out.push_str(&format!(
                    "  Indicators: {}\n",
                    artifact.indicators.join("; ")
                ));
            }
        }
    }

    if let Some(emulation) = &result.emulation {
        out.push_str("\n------------------------------------------------------------\n");
        out.push_str("SAFE STATIC EMULATION:\n");
        out.push_str(&format!("Files Analyzed: {}\n", emulation.files_scanned));
        out.push_str(&format!("Traces:         {}\n", emulation.traces.len()));
        for trace in &emulation.traces {
            out.push_str(&format!(
                "\n{} [{}] entry {} instructions {}\n",
                trace.file_path, trace.architecture, trace.entrypoint, trace.instructions
            ));
            out.push_str(&format!("  Stopped: {}\n", trace.stopped_reason));
            if !trace.api_calls.is_empty() {
                out.push_str(&format!("  API Calls: {}\n", trace.api_calls.join(", ")));
            }
            if !trace.recovered_strings.is_empty() {
                out.push_str(&format!(
                    "  Recovered Strings: {}\n",
                    trace.recovered_strings.join(" | ")
                ));
            }
            if !trace.indicators.is_empty() {
                out.push_str(&format!("  Indicators: {}\n", trace.indicators.join("; ")));
            }
        }
    }

    if let Some(sandbox) = &result.sandbox {
        out.push_str("\n------------------------------------------------------------\n");
        out.push_str("DOCKER SANDBOX:\n");
        out.push_str(&format!(
            "Available:      {}\n",
            if sandbox.available { "yes" } else { "no" }
        ));
        out.push_str(&format!("Image:          {}\n", sandbox.image));
        out.push_str(&format!("Files Analyzed: {}\n", sandbox.files_analyzed));
        out.push_str(&format!("Executions:     {}\n", sandbox.executions.len()));
        for execution in &sandbox.executions {
            out.push_str(&format!(
                "\n{} [{}] exit {:?} in {}ms ({} syscalls)\n",
                execution.file_path,
                execution.architecture,
                execution.exit_code,
                execution.duration_ms,
                execution.syscalls
            ));
            if execution.timed_out {
                out.push_str("  Timed out: yes\n");
            }
            if !execution.processes.is_empty() {
                out.push_str(&format!(
                    "  Processes: {}\n",
                    execution.processes.join(", ")
                ));
            }
            if !execution.network_attempts.is_empty() {
                out.push_str(&format!(
                    "  Network Attempts: {}\n",
                    execution.network_attempts.join(" | ")
                ));
            }
            if !execution.file_accesses.is_empty() {
                out.push_str(&format!(
                    "  Sensitive Files: {}\n",
                    execution.file_accesses.join(" | ")
                ));
            }
            if !execution.indicators.is_empty() {
                out.push_str(&format!(
                    "  Indicators: {}\n",
                    execution.indicators.join("; ")
                ));
            }
        }
        for note in &sandbox.notes {
            out.push_str(&format!("  Note: {}\n", note));
        }
    }

    if let Some(ttp) = &result.ttp {
        out.push_str("\n------------------------------------------------------------\n");
        out.push_str("TTP / ATT&CK COVERAGE:\n");
        out.push_str(&format!(
            "Techniques:     {}\nTactics:        {}\nCoverage:       {}%\n",
            ttp.techniques.len(),
            ttp.tactics.len(),
            ttp.coverage_score
        ));
        for technique in &ttp.techniques {
            out.push_str(&format!(
                "\n[{}] {} {} [{}] ({} observations)\n",
                technique.severity.to_uppercase(),
                technique.id,
                technique.name,
                technique.tactic,
                technique.observations
            ));
            out.push_str(&format!("  Sources: {}\n", technique.sources.join(", ")));
        }
        if !ttp.tactics.is_empty() {
            out.push_str("\nKill Chain:\n");
            for tactic in &ttp.tactics {
                out.push_str(&format!(
                    "  {}: {}\n",
                    tactic.tactic,
                    tactic.techniques.join(", ")
                ));
            }
        }
    }

    if !result.iocs.is_empty() {
        out.push_str("------------------------------------------------------------\n");
        out.push_str(&format!(
            "INDICATORS ({} external URLs / IPs):\n",
            result.iocs.len()
        ));
        for ioc in result.iocs.iter().take(30) {
            out.push_str(&format!(
                "  [{}] {}  ({})\n",
                ioc.kind,
                ioc.value,
                ioc.files.join(", ")
            ));
        }
        if result.iocs.len() > 30 {
            out.push_str("  … see --format json for the full list\n");
        }
    }

    out.push_str("============================================================\n");
    out
}
