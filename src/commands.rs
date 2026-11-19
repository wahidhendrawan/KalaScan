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
                if !auth::any_users() {
                    // Easy to miss when revoking a leaked token: the next
                    // start of a loopback server finds no auth configured.
                    eprintln!(
                        "No users left. A running server keeps refusing requests without a \
                         valid token; after a restart a loopback server runs without auth \
                         unless KALASCAN_TOKEN is set or a user is added"
                    );
                }
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
        // Findings past the cap were never read, so they cannot pass the gate.
        if imported.truncated
            || imported
                .findings
                .iter()
                .any(|f| import::rank(f.severity) <= limit)
        {
            eprintln!(
                "Finding at or above '{}' severity, or the report was too large to check",
                threshold
            );
            std::process::exit(1);
        }
    }
    Ok(())
}

/// Critical findings and chains of a result, for one-line summaries.
pub(crate) fn strong_findings(r: &ScanResult) -> Vec<String> {
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
    base_ref: Option<&str>,
) -> anyhow::Result<()> {
    let mut locked = lockfile::read(path, include_dev);
    if locked.is_empty() {
        anyhow::bail!(
            "no package-lock.json, yarn.lock, pnpm-lock.yaml, poetry.lock, Pipfile.lock, uv.lock, \
             pinned requirements.txt or Cargo.lock in {}",
            path.display()
        );
    }
    if let Some(git_ref) = base_ref {
        let before = lockfile::pinned_at(path, git_ref)?;
        let all = locked.len();
        locked.retain(|p| !before.contains(&(p.ecosystem, p.name.clone(), p.version.clone())));
        eprintln!(
            "{} of {all} locked packages are new since {git_ref}",
            locked.len()
        );
        if locked.is_empty() {
            return Ok(());
        }
    }
    let skipped = locked.len().saturating_sub(max);
    if skipped > 0 {
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
                eprintln!("  failed {}: {}", export::inert(&pkg.target()), e);
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
                export::inert(&p.target()),
                r.critical.join(", ")
            );
        }
        eprintln!("{} scanned, {} failed", rows.len(), failed);
    }
    if let Some(threshold) = fail_on_risk {
        // Fail closed: a package that was not scanned is not a pass.
        if failed > 0 || skipped > 0 {
            eprintln!(
                "{} package(s) failed to scan and {} were past --max; failing the gate",
                failed, skipped
            );
            std::process::exit(1);
        }
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
    let home = std::path::Path::new(&home);
    let mut found = installed::discover(home);
    // MCP and hook configs are single files: each is scanned in a folder of
    // its own, kept alive until the scans finish.
    let mut folders = Vec::new();
    for cfg in installed::agent_configs(home) {
        let Some(text) = installed::agent_config_text(&cfg.path) else {
            continue;
        };
        let dir = tempfile::tempdir()?;
        let file = dir.path().join(cfg.as_file);
        std::fs::create_dir_all(file.parent().unwrap_or(dir.path()))?;
        std::fs::write(&file, text)?;
        found.push(installed::Installed {
            app: cfg.app,
            name: format!(
                "~/{}",
                cfg.path.strip_prefix(home).unwrap_or(&cfg.path).display()
            ),
            path: dir.path().to_path_buf(),
        });
        folders.push(dir);
    }
    eprintln!(
        "Scanning {} installed extensions and agent configs...",
        found.len()
    );

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
    let mut failed = 0;
    while let Some(joined) = tasks.join_next().await {
        let (ext, result) = joined?;
        match result {
            Ok(r) => rows.push((ext, r)),
            Err(e) => {
                failed += 1;
                eprintln!("  failed {}: {}", ext.path.display(), e);
            }
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
        // Fail closed: an extension that could not be scanned is not a pass.
        if failed > 0 {
            eprintln!("{} extension(s) failed to scan; failing the gate", failed);
            std::process::exit(1);
        }
        if rows.iter().any(|(_, r)| r.risk_score >= threshold) {
            std::process::exit(1);
        }
    }
    Ok(())
}

/// What an install command would fetch, as scan targets, or `None` when the
/// command installs nothing (`npm test`). An empty list means "whatever the
/// lockfile says" (`npm ci`, a bare `npm install`). Fails closed: a spec it
/// cannot scan (alias, git, URL, path) or a command that installs something
/// it cannot name (`npm update`, `npx`) is an error, so the guard refuses.
/// For npm the guard then scans the whole tree the install adds
/// (`npm_tree`); for the others the named packages, and a range
/// (`lodash@^4`) scans the latest version.
fn install_targets(command: &[String]) -> anyhow::Result<Option<Vec<String>>> {
    let prog = std::path::Path::new(command.first().map_or("", String::as_str))
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let prog = prog.trim_end_matches(".exe").trim_end_matches(".cmd");
    let args: Vec<&str> = command.iter().skip(1).map(String::as_str).collect();
    // Flags whose value is the next argument, not a package.
    const VALUE_FLAGS: &[&str] = &[
        "--registry",
        "--prefix",
        "--workspace",
        "-w",
        "--tag",
        "--cache",
        "--userconfig",
        "--filter",
        "--dir",
        "-C",
        "-c",
        "--constraint",
        "-i",
        "--index-url",
        "--extra-index-url",
        "-t",
        "--target",
        "--root",
        "-f",
        "--find-links",
        "--platform",
        "--python-version",
        "--python",
        "-p",
        "--group",
        "-r",
        "--requirement",
    ];
    let positional = |from: usize| -> Vec<&str> {
        let mut out = Vec::new();
        let mut skip = false;
        for a in &args[from..] {
            if skip {
                skip = false;
            } else if VALUE_FLAGS.contains(a) {
                skip = true;
            } else if !a.starts_with('-') {
                out.push(*a);
            }
        }
        out
    };
    let verb_at = |verbs: &[&str]| args.iter().position(|a| verbs.contains(a));

    let refuse = || {
        anyhow::anyhow!(
            "kalascan guard cannot tell what `{}` installs, so it is not running it; \
             run it without `kalascan guard --` to install anyway",
            command.join(" ")
        )
    };
    // Every named spec must map to a scan target: one that does not
    // (`x@npm:y`, git, URL, path) would install unscanned.
    let all = |specs: Vec<&str>, map: fn(&str) -> Option<String>| -> anyhow::Result<Vec<String>> {
        specs
            .into_iter()
            .map(|s| map(s).ok_or_else(refuse))
            .collect()
    };

    match prog {
        "npm" | "pnpm" | "yarn" | "bun" => {
            // Install from the lockfile.
            if args.is_empty() && prog != "npm" {
                return Ok(Some(Vec::new()));
            }
            if verb_at(&["install-test", "it", "install-ci-test", "cit"]).is_some() {
                return Ok(Some(Vec::new()));
            }
            // Fetch or run packages the guard cannot name.
            const FETCHES: &[&str] = &[
                "update", "upgrade", "up", "exec", "x", "dlx", "create", "init", "link",
                "rebuild", "import",
            ];
            if args.first().is_some_and(|a| FETCHES.contains(a)) {
                return Err(refuse());
            }
            let Some(at) = verb_at(&["install", "i", "add", "ci"]) else {
                // `npm test`, `npm run x`, `yarn build`: a script, nothing fetched.
                return Ok(None);
            };
            Ok(Some(all(positional(at + 1), npm_target)?))
        }
        "pip" | "pip3" | "uv" | "python" | "python3" => {
            if prog == "uv" && args.first().is_some_and(|a| ["sync", "run"].contains(a)) {
                return Ok(Some(Vec::new())); // installs what uv.lock pins
            }
            // The first verb decides (`pip install wheel` installs `wheel`).
            // `pip download` / `pip wheel` build sdists, which runs setup.py.
            let Some(at) = verb_at(&["install", "add", "download", "wheel", "sync"]) else {
                return Ok(None);
            };
            if !["install", "add"].contains(&args[at]) {
                return Err(refuse());
            }
            let mut targets = all(positional(at + 1), pypi_target)?;
            // -r / --requirement files: one spec per line.
            for (i, a) in args.iter().enumerate() {
                let file = match *a {
                    "-r" | "--requirement" => args.get(i + 1).copied(),
                    _ => a.strip_prefix("--requirement="),
                };
                if let Some(file) = file {
                    let text = std::fs::read_to_string(file)
                        .map_err(|e| anyhow::anyhow!("cannot read {}: {}", file, e))?;
                    let lines: Vec<&str> = text
                        .lines()
                        .map(|l| l.split('#').next().unwrap_or("").trim())
                        .filter(|l| !l.is_empty())
                        .collect();
                    // `-e .`, `--index-url`, a nested `-r`: not scannable here.
                    if lines.iter().any(|l| l.starts_with('-')) {
                        return Err(refuse());
                    }
                    targets.extend(all(lines, pypi_target)?);
                }
            }
            Ok(Some(targets))
        }
        "code" | "code-insiders" | "cursor" | "windsurf" | "codium" => {
            let ids: Vec<String> = args
                .windows(2)
                .filter(|w| w[0] == "--install-extension")
                .map(|w| w[1].to_string())
                .collect();
            Ok(Some(ids).filter(|ids| !ids.is_empty()))
        }
        _ => anyhow::bail!(
            "kalascan guard knows npm, pnpm, yarn, bun, pip, uv and code / cursor / windsurf, not `{}`",
            prog
        ),
    }
}

/// For `npm install <specs>`: every package the install would add, at the
/// exact version npm picks, dependencies of dependencies included. npm
/// resolves the tree in a scratch copy of the project with
/// `--package-lock-only --ignore-scripts`, which downloads metadata and runs
/// nothing; packages the current lockfile already pins are left out. `None`
/// for other commands and for global installs, which have no lockfile.
/// shortcut: npm and pip (`pip_tree`) only; pnpm, yarn, bun and uv installs
/// still scan the named packages.
async fn npm_tree(command: &[String]) -> anyhow::Result<Option<Vec<String>>> {
    let prog = std::path::Path::new(command.first().map_or("", String::as_str))
        .file_stem()
        .map(|n| n.to_string_lossy().to_ascii_lowercase());
    let args = &command[1.min(command.len())..];
    if prog.as_deref() != Some("npm") || args.iter().any(|a| a == "-g" || a == "--global") {
        return Ok(None);
    }
    let scratch = tempfile::tempdir()?;
    for file in ["package.json", "package-lock.json", ".npmrc"] {
        if std::path::Path::new(file).is_file() {
            std::fs::copy(file, scratch.path().join(file))?;
        }
    }
    if !scratch.path().join("package.json").exists() {
        std::fs::write(scratch.path().join("package.json"), "{}")?;
    }
    let out = tokio::process::Command::new(&command[0])
        .args(args)
        .args([
            "--package-lock-only",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ])
        .current_dir(scratch.path())
        .output()
        .await?;
    if !out.status.success() {
        anyhow::bail!(
            "kalascan guard could not resolve what `{}` installs (npm: {}); \
             run it without `kalascan guard --` to install anyway",
            command.join(" "),
            String::from_utf8_lossy(&out.stderr)
                .lines()
                .last()
                .unwrap_or("failed")
        );
    }
    let resolved = std::fs::read_to_string(scratch.path().join("package-lock.json"))?;
    let pinned: std::collections::BTreeSet<_> = lockfile::read(std::path::Path::new("."), true)
        .into_iter()
        .map(|p| (p.name, p.version))
        .collect();
    let mut new: Vec<String> = lockfile::parse("package-lock.json", &resolved)
        .into_iter()
        .filter(|p| !pinned.contains(&(p.name.clone(), p.version.clone())))
        .map(|p| p.target())
        .collect();
    new.sort();
    new.dedup();
    Ok(Some(new))
}

/// For `pip install <specs>`: every distribution the install would add, at
/// the version pip picks. `--dry-run --only-binary :all:` resolves from wheel
/// metadata only, so no sdist is built and no setup.py runs; `--report -`
/// lists what is not installed yet. `None` for other commands, and when
/// pip cannot resolve that way (an sdist-only package, pip older than 22.2):
/// the named packages are scanned then, as before.
/// shortcut: a package with an sdist newer than its newest wheel resolves to
/// the wheel here and to the sdist at install; the named package is still
/// scanned at the version given.
async fn pip_tree(command: &[String]) -> anyhow::Result<Option<Vec<String>>> {
    let prog = std::path::Path::new(command.first().map_or("", String::as_str))
        .file_stem()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let args: Vec<&str> = command.iter().skip(1).map(String::as_str).collect();
    let rest = match (prog.as_str(), args.as_slice()) {
        ("pip" | "pip3", ["install", rest @ ..]) => rest,
        ("python" | "python3", ["-m", "pip", "install", rest @ ..]) => rest,
        _ => return Ok(None),
    };
    let verb = command.len() - rest.len();
    let out = tokio::process::Command::new(&command[0])
        .args(&command[1..verb])
        .args([
            "--dry-run",
            "--only-binary",
            ":all:",
            "--report",
            "-",
            "--quiet",
            "--disable-pip-version-check",
        ])
        .args(rest)
        .output()
        .await?;
    if !out.status.success() {
        eprintln!(
            "kalascan guard: pip could not resolve the install from wheels alone; scanning the named packages only"
        );
        return Ok(None);
    }
    Ok(Some(pip_report_targets(&String::from_utf8_lossy(
        &out.stdout,
    ))?))
}

/// `pypi:name==version` for each entry of a `pip install --report` document.
fn pip_report_targets(report: &str) -> anyhow::Result<Vec<String>> {
    let doc: serde_json::Value = serde_json::from_str(report)?;
    let mut out: Vec<String> = doc["install"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|i| {
            let m = &i["metadata"];
            Some(format!(
                "pypi:{}=={}",
                m["name"].as_str()?,
                m["version"].as_str()?
            ))
        })
        .collect();
    out.sort();
    out.dedup();
    Ok(out)
}

/// `left-pad`, `lodash@4.17.21`, `@scope/pkg@1.0.0`; paths, git and URLs are skipped.
fn npm_target(spec: &str) -> Option<String> {
    if spec.is_empty()
        || spec.starts_with(['.', '/', '~'])
        || spec.contains(':')
        || (spec.contains('/') && !spec.starts_with('@'))
    {
        return None;
    }
    let (name, version) = match spec[1..].find('@') {
        Some(i) => (&spec[..i + 1], &spec[i + 2..]),
        None => (spec, ""),
    };
    // A dist-tag (`latest`, `next`) or a range is resolved by npm, not here.
    let exact = version.starts_with(|c: char| c.is_ascii_digit())
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-+".contains(c));
    Some(if exact {
        format!("npm:{name}@{version}")
    } else {
        format!("npm:{name}")
    })
}

/// `requests`, `requests==2.32.3`, `requests[socks]>=2`; paths and URLs are skipped.
fn pypi_target(spec: &str) -> Option<String> {
    if spec.starts_with(['.', '/', '~']) || spec.contains("://") || spec.ends_with(".whl") {
        return None;
    }
    let name_end = spec
        .find(|c: char| "=<>!~[;@ ".contains(c))
        .unwrap_or(spec.len());
    let name = &spec[..name_end];
    if name.is_empty() {
        return None;
    }
    match spec.split_once("==") {
        Some((_, v)) if !v.contains([',', '*', ';']) => Some(format!("pypi:{name}=={}", v.trim())),
        _ => Some(format!("pypi:{name}")),
    }
}

/// `kalascan guard -- npm install x`: scan first, install only if nothing
/// reaches `fail_on_risk`. A package that cannot be scanned blocks the
/// install too: the guard fails closed.
pub(crate) async fn run_guard_command(
    command: &[String],
    fail_on_risk: u8,
    jobs: usize,
) -> anyhow::Result<()> {
    match install_targets(command)? {
        None => {}
        Some(targets) if targets.is_empty() => {
            if lockfile::read(std::path::Path::new("."), true).is_empty() {
                eprintln!(
                    "kalascan guard: nothing named and no lockfile here, so nothing to check"
                );
            } else {
                // Exits 1 itself when a locked package reaches the threshold.
                run_deps_command(
                    std::path::Path::new("."),
                    "text",
                    true,
                    fail_on_risk,
                    Some(fail_on_risk),
                    jobs,
                    usize::MAX, // every locked package: one past a cap would install unscanned
                    false,
                    None,
                )
                .await?;
            }
        }
        Some(named) => {
            let targets = match npm_tree(command).await? {
                Some(tree) => tree,
                None => pip_tree(command).await?.unwrap_or(named),
            };
            eprintln!(
                "kalascan guard: scanning {} before install...",
                targets.len()
            );
            let permits = Arc::new(tokio::sync::Semaphore::new(jobs.max(1)));
            let mut tasks = tokio::task::JoinSet::new();
            for target in targets {
                let permits = permits.clone();
                tasks.spawn(async move {
                    let _permit = permits.acquire_owned().await;
                    let mut req: ScanRequest = serde_json::from_value(serde_json::json!({
                        "repo_url": target,
                        "check_cve": false,
                    }))
                    .expect("static request");
                    req.third_party = true;
                    (target, execute_scan(req).await)
                });
            }
            let mut blocked = false;
            while let Some(joined) = tasks.join_next().await {
                match joined? {
                    (target, Ok(r)) => {
                        let bad = r.risk_score >= fail_on_risk;
                        blocked |= bad;
                        println!(
                            "{:>4}  {:<48} {}",
                            r.risk_score,
                            target,
                            if bad {
                                strong_findings(&r).join(", ")
                            } else {
                                String::new()
                            }
                        );
                    }
                    (target, Err(e)) => {
                        blocked = true;
                        println!("   ?  {:<48} not scanned: {}", target, e);
                    }
                }
            }
            if blocked {
                eprintln!(
                    "\nkalascan guard: not installing. A package reached risk {} or could not be scanned;\nrun the command without `kalascan guard --` to install anyway.",
                    fail_on_risk
                );
                std::process::exit(1);
            }
        }
    }
    let status = std::process::Command::new(&command[0])
        .args(&command[1..])
        .status()
        .map_err(|e| anyhow::anyhow!("cannot run {}: {}", command[0], e))?;
    std::process::exit(status.code().unwrap_or(1));
}

pub(crate) async fn run_diff_command(
    old: &str,
    new: &str,
    format: &str,
    fail_on_new: Option<&str>,
    cve: bool,
) -> anyhow::Result<()> {
    let request = |target: &str| -> anyhow::Result<ScanRequest> {
        let mut req: ScanRequest = serde_json::from_value(serde_json::json!({
            "repo_url": target,
            "check_cve": cve,
        }))?;
        // Both versions are someone else's code, even as local directories.
        req.third_party = true;
        Ok(req)
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

pub(crate) fn run_rules_command(name: Option<String>, coverage: bool) -> anyhow::Result<()> {
    if coverage {
        print!("{}", crate::taxonomy::coverage_markdown());
        return Ok(());
    }
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
                    let techniques = crate::attack::for_finding(&rule.name);
                    for t in &techniques {
                        let objective = crate::taxonomy::mbc_objective(t)
                            .map(|(id, name)| format!("  [MBC {} {}]", id, name))
                            .unwrap_or_default();
                        println!("ATT&CK: {} {} ({}){}", t.id, t.name, t.tactic, objective);
                    }
                    for vector in crate::taxonomy::vectors_for(&rule.name) {
                        println!("Supply-chain vector: {}", vector);
                    }
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
        "stix" => export::export_stix(&result)?,
        "osv" => export::export_osv(&result)?,
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
    use export::inert;
    let mut out = String::new();
    out.push_str("============================================================\n");
    out.push_str("🛡️  KalaScan Security & Malware Audit Report\n");
    out.push_str("============================================================\n");
    out.push_str(&format!("Target:        {}\n", inert(&result.repo_url)));
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
    if let Some(parts) = export::score_parts(result) {
        out.push_str(&format!("Score Parts:   {}\n", parts));
    }
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
                inert(&m.matched_pattern),
                inert(&m.file_path),
                m.line_number,
                inert(m.context.trim())
            ));
        }
    }

    if let Some(ai) = &result.ai_analysis {
        out.push_str("\n------------------------------------------------------------\n");
        out.push_str("AI DEEP ANALYSIS:\n");
        out.push_str(&format!("Malware Type:   {}\n", inert(&ai.malware_type)));
        out.push_str(&format!("Threat Summary: {}\n", inert(&ai.threat_summary)));
        out.push_str(&format!("Recommendation: {}\n", inert(&ai.recommendation)));
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
                inert(&binary.path),
                binary.file_type,
                binary.architecture.as_deref().unwrap_or("unknown"),
                binary.entropy
            ));
            out.push_str(&format!("  SHA-256: {}\n", binary.sha256));
            if let Some(packer) = &binary.packer {
                out.push_str(&format!(
                    "  Packer:  {} ({}) - {}\n",
                    packer.name,
                    packer.confidence,
                    inert(&packer.evidence)
                ));
            }
            if !binary.indicators.is_empty() {
                out.push_str(&format!(
                    "  Indicators: {}\n",
                    inert(&binary.indicators.join("; "))
                ));
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
                inert(&artifact.file_path),
                artifact.line_number,
                artifact.encoding
            ));
            out.push_str(&format!(
                "  Decoded: {}\n",
                inert(&artifact.decoded.replace('\n', " "))
            ));
            if !artifact.indicators.is_empty() {
                out.push_str(&format!(
                    "  Indicators: {}\n",
                    inert(&artifact.indicators.join("; "))
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
                inert(&trace.file_path),
                trace.architecture,
                trace.entrypoint,
                trace.instructions
            ));
            out.push_str(&format!("  Stopped: {}\n", inert(&trace.stopped_reason)));
            if !trace.api_calls.is_empty() {
                out.push_str(&format!(
                    "  API Calls: {}\n",
                    inert(&trace.api_calls.join(", "))
                ));
            }
            if !trace.recovered_strings.is_empty() {
                out.push_str(&format!(
                    "  Recovered Strings: {}\n",
                    inert(&trace.recovered_strings.join(" | "))
                ));
            }
            if !trace.indicators.is_empty() {
                out.push_str(&format!(
                    "  Indicators: {}\n",
                    inert(&trace.indicators.join("; "))
                ));
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
                inert(&execution.file_path),
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
                    inert(&execution.processes.join(", "))
                ));
            }
            if !execution.network_attempts.is_empty() {
                out.push_str(&format!(
                    "  Network Attempts: {}\n",
                    inert(&execution.network_attempts.join(" | "))
                ));
            }
            if !execution.file_accesses.is_empty() {
                out.push_str(&format!(
                    "  Sensitive Files: {}\n",
                    inert(&execution.file_accesses.join(" | "))
                ));
            }
            if !execution.indicators.is_empty() {
                out.push_str(&format!(
                    "  Indicators: {}\n",
                    inert(&execution.indicators.join("; "))
                ));
            }
        }
        for note in &sandbox.notes {
            out.push_str(&format!("  Note: {}\n", inert(note)));
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
            out.push_str(&format!(
                "  Sources: {}\n",
                inert(&technique.sources.join(", "))
            ));
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
                inert(&ioc.value),
                inert(&ioc.files.join(", "))
            ));
        }
        if result.iocs.len() > 30 {
            out.push_str("  … see --format json for the full list\n");
        }
    }

    out.push_str("============================================================\n");
    export::no_workflow_commands(&out)
}

#[cfg(test)]
mod text_report_tests {
    use super::*;

    #[test]
    fn scanned_content_is_printed_inert() {
        let result: ScanResult = serde_json::from_value(serde_json::json!({
            "id": "x", "repo_url": "fx", "timestamp": "t", "status": "completed",
            "total_files": 1, "scanned_files": 1, "total_matches": 1, "risk_score": 10,
            "ai_analysis": null,
            "rule_matches": [{
                "file_path": "c\n::error::y", "line_number": 1, "severity": "high",
                "matched_pattern": "eval() Usage",
                "context": "\u{1b}[2K\n::warning::x\r>>> eval( <<<"
            }],
            "iocs": [{
                "kind": "url", "value": "http://x.invalid/\u{7}", "host": "x.invalid",
                "files": ["c\n::error::y"]
            }]
        }))
        .unwrap();
        let text = format_cli_text(&result);
        assert!(!text.contains(['\u{1b}', '\r', '\u{7}']), "{:?}", text);
        assert!(
            text.lines().all(|l| !l.trim_start().starts_with("::")),
            "{}",
            text
        );
        assert!(
            text.contains("     | ::warning::x\\r>>> eval( <<<"),
            "{}",
            text
        );
    }
}

#[cfg(test)]
mod guard_tests {
    use super::*;

    fn targets(cmd: &str) -> Option<Vec<String>> {
        let argv: Vec<String> = cmd.split_whitespace().map(String::from).collect();
        install_targets(&argv).unwrap()
    }

    #[test]
    fn install_commands_become_scan_targets() {
        assert_eq!(
            targets(
                "npm install --save-dev left-pad lodash@4.17.21 @scope/pkg@1.0.0 react@^19 -w app"
            ),
            Some(vec![
                "npm:left-pad".to_string(),
                "npm:lodash@4.17.21".to_string(),
                "npm:@scope/pkg@1.0.0".to_string(),
                "npm:react".to_string(),
            ])
        );
        assert_eq!(
            targets("pnpm add zod@latest"),
            Some(vec!["npm:zod".to_string()])
        );
        assert_eq!(targets("npm ci"), Some(vec![]));
        assert_eq!(targets("npm test"), None);
        assert_eq!(
            targets("/usr/bin/pip3 install -i https://pypi.org/simple requests==2.32.3 rich[jupyter]>=13"),
            Some(vec!["pypi:requests==2.32.3".to_string(), "pypi:rich".to_string()])
        );
        assert_eq!(
            targets("uv add httpx"),
            Some(vec!["pypi:httpx".to_string()])
        );
        assert_eq!(
            targets("cursor --install-extension ms-python.python --install-extension ./evil.vsix"),
            Some(vec![
                "ms-python.python".to_string(),
                "./evil.vsix".to_string()
            ])
        );
        assert_eq!(targets("code --list-extensions"), None);
        assert!(install_targets(&["cargo".to_string(), "install".to_string()]).is_err());
    }

    #[test]
    fn requirement_files_are_read() {
        let dir = tempfile::tempdir().unwrap();
        let req = dir.path().join("requirements.txt");
        std::fs::write(&req, "# deps\nflask==3.1.0  # web\nrequests>=2\n\n").unwrap();
        let cmd = format!("pip install -r {}", req.display());
        assert_eq!(
            targets(&cmd),
            Some(vec![
                "pypi:flask==3.1.0".to_string(),
                "pypi:requests".to_string()
            ])
        );
        // An option line installs something the guard cannot scan.
        std::fs::write(&req, "flask==3.1.0\n-e .\n").unwrap();
        assert!(
            install_targets(&cmd.split_whitespace().map(String::from).collect::<Vec<_>>()).is_err()
        );
    }

    fn refused(cmd: &str) -> bool {
        let argv: Vec<String> = cmd.split_whitespace().map(String::from).collect();
        install_targets(&argv).is_err()
    }

    #[test]
    fn unscannable_installs_are_refused() {
        // Specs that cannot become a scan target would install unscanned.
        assert!(refused("npm install lodash@npm:evil-pkg@1.0.0"));
        assert!(refused("npm install ./local"));
        assert!(refused("npm install git+https://x/y.git"));
        assert!(refused("pip install ./dist/x.whl"));
        assert!(refused("pip install https://evil.example/x.tar.gz"));
        // Commands that fetch or run packages the guard cannot name.
        for cmd in [
            "npm update",
            "npm exec evil-pkg",
            "pnpm dlx x",
            "yarn create x",
            "pip download x",
            "uv pip sync r.txt",
        ] {
            assert!(refused(cmd), "{cmd}");
        }
        // Lockfile installs go through the lockfile audit.
        for cmd in [
            "yarn",
            "pnpm",
            "bun",
            "npm install-test",
            "npm cit",
            "uv sync",
            "uv run app.py",
        ] {
            assert_eq!(targets(cmd), Some(vec![]), "{cmd}");
        }
        // Scripts and queries fetch nothing; `pip install wheel` installs `wheel`.
        assert_eq!(targets("npm run build"), None);
        assert_eq!(targets("yarn build"), None);
        assert_eq!(targets("pip list"), None);
        assert_eq!(
            targets("pip install wheel"),
            Some(vec!["pypi:wheel".to_string()])
        );
    }

    #[test]
    fn pip_report_lists_what_the_install_adds() {
        let report = r#"{"version": "1", "install": [
            {"download_info": {}, "metadata": {"name": "requests", "version": "2.32.3"}},
            {"metadata": {"name": "urllib3", "version": "2.2.3"}},
            {"metadata": {"name": "broken"}}]}"#;
        assert_eq!(
            super::pip_report_targets(report).unwrap(),
            ["pypi:requests==2.32.3", "pypi:urllib3==2.2.3"]
        );
        assert!(super::pip_report_targets("not json").is_err());
    }
}
