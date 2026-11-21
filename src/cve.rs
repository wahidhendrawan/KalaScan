use crate::RuleMatch;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyPackage {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub manifest_file: String,
}

#[derive(Serialize)]
struct OsvBatchQuery {
    queries: Vec<OsvSingleQuery>,
}

#[derive(Serialize)]
struct OsvSingleQuery {
    package: OsvPackageInfo,
    version: String,
}

#[derive(Serialize)]
struct OsvPackageInfo {
    name: String,
    ecosystem: String,
}

#[derive(Deserialize)]
struct OsvBatchResponse {
    results: Option<Vec<OsvQueryResult>>,
}

#[derive(Deserialize)]
struct OsvQueryResult {
    vulns: Option<Vec<OsvVuln>>,
}

#[derive(Deserialize)]
struct OsvVuln {
    id: String,
    summary: Option<String>,
    details: Option<String>,
}

/// Extract dependency packages from standard manifest files in a directory
pub fn extract_manifest_packages(root_path: &Path) -> Vec<DependencyPackage> {
    let mut packages = Vec::new();

    // 1. package.json (npm)
    let pkg_json_path = root_path.join("package.json");
    if pkg_json_path.is_file() {
        if let Ok(content) = std::fs::read_to_string(&pkg_json_path) {
            packages.extend(parse_package_json(&content, "package.json"));
        }
    }

    // Also check extension/package.json for VSIX packages
    let ext_pkg_json = root_path.join("extension").join("package.json");
    if ext_pkg_json.is_file() {
        if let Ok(content) = std::fs::read_to_string(&ext_pkg_json) {
            packages.extend(parse_package_json(&content, "extension/package.json"));
        }
    }

    // 2. Cargo.lock (Rust)
    let cargo_lock_path = root_path.join("Cargo.lock");
    if cargo_lock_path.is_file() {
        if let Ok(content) = std::fs::read_to_string(&cargo_lock_path) {
            packages.extend(parse_cargo_lock(&content, "Cargo.lock"));
        }
    }

    // 3. requirements.txt (Python)
    let req_path = root_path.join("requirements.txt");
    if req_path.is_file() {
        if let Ok(content) = std::fs::read_to_string(&req_path) {
            packages.extend(parse_requirements_txt(&content, "requirements.txt"));
        }
    }

    packages
}

pub fn parse_package_json(content: &str, file_name: &str) -> Vec<DependencyPackage> {
    let mut packages = Vec::new();
    let parsed: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return packages,
    };

    let parse_deps = |dep_obj: &serde_json::Value, pkgs: &mut Vec<DependencyPackage>| {
        if let Some(map) = dep_obj.as_object() {
            for (name, ver_val) in map {
                if let Some(raw_ver) = ver_val.as_str() {
                    let clean_ver = raw_ver
                        .trim_start_matches('^')
                        .trim_start_matches('~')
                        .trim_start_matches(">=")
                        .trim();
                    if !clean_ver.is_empty()
                        && clean_ver.chars().next().is_some_and(|c| c.is_ascii_digit())
                    {
                        pkgs.push(DependencyPackage {
                            name: name.clone(),
                            version: clean_ver.to_string(),
                            ecosystem: "npm".to_string(),
                            manifest_file: file_name.to_string(),
                        });
                    }
                }
            }
        }
    };

    if let Some(deps) = parsed.get("dependencies") {
        parse_deps(deps, &mut packages);
    }
    if let Some(dev_deps) = parsed.get("devDependencies") {
        parse_deps(dev_deps, &mut packages);
    }

    packages
}

pub fn parse_cargo_lock(content: &str, file_name: &str) -> Vec<DependencyPackage> {
    let mut packages = Vec::new();
    let mut current_name: Option<String> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("name = \"") && line.ends_with('"') {
            current_name = Some(line[8..line.len() - 1].to_string());
        } else if line.starts_with("version = \"") && line.ends_with('"') {
            if let Some(name) = current_name.take() {
                let ver = line[11..line.len() - 1].to_string();
                packages.push(DependencyPackage {
                    name,
                    version: ver,
                    ecosystem: "crates.io".to_string(),
                    manifest_file: file_name.to_string(),
                });
            }
        }
    }

    packages
}

pub fn parse_requirements_txt(content: &str, file_name: &str) -> Vec<DependencyPackage> {
    let mut packages = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((name, ver)) = line.split_once("==") {
            packages.push(DependencyPackage {
                name: name.trim().to_string(),
                version: ver.trim().to_string(),
                ecosystem: "PyPI".to_string(),
                manifest_file: file_name.to_string(),
            });
        }
    }

    packages
}

/// Typo-squat targets that are not among the most downloaded but are what
/// attackers copy (`discord.js`, `web3`, `electron`); the top 1,000 by
/// downloads come from rules/popular_packages.tsv (`popular`).
const POPULAR_NPM: &[&str] = &[
    "react",
    "react-dom",
    "lodash",
    "express",
    "axios",
    "chalk",
    "commander",
    "debug",
    "moment",
    "request",
    "webpack",
    "typescript",
    "eslint",
    "prettier",
    "jquery",
    "vue",
    "cross-env",
    "dotenv",
    "colors",
    "uuid",
    "yargs",
    "inquirer",
    "body-parser",
    "mongoose",
    "socket.io",
    "babel-core",
    "node-fetch",
    "electron",
    "discord.js",
    "ethers",
    "web3",
    "jsonwebtoken",
    "bcrypt",
    "nodemailer",
    "puppeteer",
    "redux",
    "next",
    "glob",
    "rimraf",
    "mkdirp",
    "semver",
    "minimist",
    "async",
    "bluebird",
    "underscore",
    "classnames",
    "coffee-script",
];
const POPULAR_PYPI: &[&str] = &[
    "requests",
    "urllib3",
    "numpy",
    "pandas",
    "boto3",
    "botocore",
    "setuptools",
    "django",
    "flask",
    "pyyaml",
    "cryptography",
    "pillow",
    "colorama",
    "beautifulsoup4",
    "selenium",
    "matplotlib",
    "scipy",
    "tensorflow",
    "torch",
    "openai",
    "python-dateutil",
    "jinja2",
    "click",
    "pytest",
    "paramiko",
    "pycryptodome",
    "discord.py",
    "web3",
    "httpx",
    "aiohttp",
    "asyncio",
    "pynacl",
];

/// The names a typo-squat imitates in `ecosystem`: the generated top 1,000
/// (rules/gen_popular_packages.py) and the hand-picked targets above.
fn popular(ecosystem: &str) -> &'static [String] {
    static LISTS: std::sync::LazyLock<[Vec<String>; 2]> = std::sync::LazyLock::new(|| {
        let mut lists = [Vec::new(), Vec::new()];
        for (i, (eco, extra)) in [("npm", POPULAR_NPM), ("PyPI", POPULAR_PYPI)]
            .into_iter()
            .enumerate()
        {
            let generated = include_str!("../rules/popular_packages.tsv")
                .lines()
                .filter_map(|l| l.strip_prefix(eco)?.strip_prefix('\t'));
            let mut names: Vec<String> = generated
                .chain(extra.iter().copied())
                .map(str::to_lowercase)
                .collect();
            names.sort();
            names.dedup();
            lists[i] = names;
        }
        lists
    });
    match ecosystem {
        "npm" => &LISTS[0],
        "PyPI" => &LISTS[1],
        _ => &[],
    }
}

/// `parser-json` for `json-parser`: the words of a popular name, reordered.
fn same_words(name: &str, popular: &str) -> bool {
    fn words(s: &str) -> Vec<&str> {
        let mut w: Vec<&str> = s.split(['-', '_', '.']).collect();
        w.sort_unstable();
        w
    }
    name != popular && name.split(['-', '_', '.']).count() >= 2 && words(name) == words(popular)
}

/// `client-s3` for `@aws-sdk/client-s3`: a popular scoped name without its
/// scope. Only compound names of 8 characters or more: `core` for
/// `@babel/core` is a different, real package.
fn scope_dropped(name: &str, popular: &str) -> bool {
    !name.starts_with('@')
        && name.len() >= 8
        && name.contains('-')
        && popular.starts_with('@')
        && popular
            .split_once('/')
            .is_some_and(|(_, rest)| rest == name)
}

/// Real packages that happen to sit one edit from a popular name.
const KNOWN_NEIGHBORS: &[&str] = &[
    "preact",
    "color",
    "ether",
    "chalk-cli",
    "requests-oauthlib",
    "tslint",
    "rsync",
];

/// Dependencies that imitate a popular package they are not: one edit (or
/// one swap of neighbours) away, the same words reordered, or a scoped name
/// without its scope. Names under 6 chars are skipped: `vue`/`vuex`,
/// `async`/`rsync`, `eslint`/`tslint` style pairs are mostly all real.
pub fn typosquat_matches(packages: &[DependencyPackage]) -> Vec<RuleMatch> {
    packages
        .iter()
        .filter_map(|p| {
            let popular = popular(&p.ecosystem);
            let name = p.name.to_lowercase();
            if name.len() < 6
                || popular.contains(&name)
                || KNOWN_NEIGHBORS.contains(&name.as_str())
            {
                return None;
            }
            let target = popular
                .iter()
                .find(|t| t.len() >= 6 && edit_distance(&name, t) == 1)
                .or_else(|| popular.iter().find(|t| same_words(&name, t)))
                .or_else(|| popular.iter().find(|t| scope_dropped(&name, t)))?;
            Some(RuleMatch {
                file_path: p.manifest_file.clone(),
                line_number: 1,
                matched_pattern: format!("Typo-squat Suspect: {} (looks like {})", p.name, target),
                severity: "high".to_string(),
                context: format!(
                    "Dependency '{}' looks like the popular package '{}' (one edit, the same words reordered, or its scope dropped)",
                    p.name, target
                ),
            })
        })
        .collect()
}

/// Optimal-string-alignment distance: Levenshtein plus adjacent swaps
/// (`asyncoi` → `asyncio` is one edit, the classic typo-squat).
fn edit_distance(a: &str, b: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = (a[i - 1] != b[j - 1]) as usize;
            d[i][j] = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[a.len()][b.len()]
}

/// The scanned package's own identity: a typo-squatted name, or a version
/// like 99.0.0 / 999.9.9 that exists only to outrank a private package of
/// the same name (dependency confusion).
pub fn own_package_matches(root: &Path) -> Vec<RuleMatch> {
    let Some(own) = own_package(root) else {
        return Vec::new();
    };
    let mut out = typosquat_matches(std::slice::from_ref(&own));
    for m in &mut out {
        m.context = m
            .context
            .replacen("Dependency", "This package's own name", 1);
    }
    let major: u64 = own
        .version
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    // CalVer (2026.4.1, as ms-python ships) is a year, not a land grab.
    if major >= 99 && !(1990..=2100).contains(&major) {
        out.push(RuleMatch {
            file_path: own.manifest_file.clone(),
            line_number: 1,
            matched_pattern: crate::correlate::DEP_CONFUSION_VERSION.to_string(),
            severity: "medium".to_string(),
            context: format!(
                "{}@{}: an implausibly high version is how dependency-confusion packages win resolution",
                own.name, own.version
            ),
        });
    }
    out.extend(remote_url_dependencies(root));
    out
}

pub const WEB_PAGE_ENTRY: &str = "Package Entry Point Is a Web Page";

/// An npm package whose entry point is an HTML or SVG document is not a
/// library: it is a page, served under a trusted host name by the CDNs that
/// mirror the registry (unpkg, jsDelivr). With script in it this is how
/// phishing pages, cloned sites and SVG-wrapped pages are hosted
/// (`"main": "index.svg", "unpkg": "index.svg"`).
pub fn web_page_entry(root: &Path) -> Vec<RuleMatch> {
    let Some(text) = std::fs::read_to_string(root.join("package.json")).ok() else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Vec::new();
    };
    let page = ["main", "unpkg", "jsdelivr", "browser"]
        .iter()
        .filter_map(|field| v[field].as_str())
        .find(|entry| {
            let lower = entry.to_ascii_lowercase();
            [".html", ".htm", ".svg"]
                .iter()
                .any(|ext| lower.ends_with(ext))
        });
    let Some(entry) = page else {
        return Vec::new();
    };
    // Script written into the page itself. A Polymer element's `index.html`
    // (HTML Imports, `<script src=…>` only) is its demo page, and it was the
    // entry point of that generation of components (responsive-embed 1.0.0).
    static INLINE_SCRIPT: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?i)<script(?:\s[^>]*)?>\s*(?:(?://\s*)?<!\[CDATA\[|[^<\s])").unwrap()
    });
    // The entry is a path inside the package; anything else is not read.
    let scripted = !entry.contains("..")
        && std::fs::read(root.join(entry.trim_start_matches("./"))).is_ok_and(|bytes| {
            let page = String::from_utf8_lossy(&bytes);
            INLINE_SCRIPT.is_match(&page) && !page.contains("rel=\"import\"")
        });
    let (name, severity, what) = if scripted {
        (
            crate::correlate::WEB_PAGE_PACKAGE,
            "critical",
            "a web page with script",
        )
    } else {
        (WEB_PAGE_ENTRY, "medium", "a web page")
    };
    vec![RuleMatch {
        file_path: "package.json".to_string(),
        line_number: text
            .find(entry)
            .map_or(1, |i| text[..i].lines().count().max(1)),
        matched_pattern: name.to_string(),
        severity: severity.to_string(),
        context: format!("the package's entry point \"{entry}\" is {what}, not a module"),
    }]
}

pub const REMOTE_URL_DEP: &str = "Remote URL Dependency";

/// npm dependencies given as an http(s) tarball URL on someone's own server:
/// the code is fetched at install time and never seen by the registry or a
/// scan of the package (PhantomRaven, 2025). Source hosts are left alone.
fn remote_url_dependencies(root: &Path) -> Vec<RuleMatch> {
    const SOURCE_HOSTS: &[&str] = &[
        "github.com",
        "codeload.github.com",
        "gitlab.com",
        "bitbucket.org",
        "registry.npmjs.org",
        "registry.yarnpkg.com",
        // SheetJS left the npm registry: its documented install is
        // `"xlsx": "https://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz"`.
        "cdn.sheetjs.com",
    ];
    let Some(text) = std::fs::read_to_string(root.join("package.json")).ok() else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Vec::new();
    };
    // An extension ships its node_modules; nothing is fetched on install.
    if v["engines"]["vscode"].is_string() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for section in ["dependencies", "optionalDependencies", "peerDependencies"] {
        let Some(deps) = v[section].as_object() else {
            continue;
        };
        for (name, spec) in deps {
            let Some(url) = spec.as_str() else { continue };
            let Some(rest) = url.strip_prefix("https://").or(url.strip_prefix("http://")) else {
                continue;
            };
            let host = rest.split(['/', ':', '?']).next().unwrap_or_default();
            if SOURCE_HOSTS.contains(&host.to_ascii_lowercase().as_str()) {
                continue;
            }
            out.push(RuleMatch {
                file_path: "package.json".to_string(),
                line_number: text
                    .find(url)
                    .map_or(1, |i| text[..i].lines().count().max(1)),
                matched_pattern: REMOTE_URL_DEP.to_string(),
                severity: "critical".to_string(),
                context: format!("{section}: \"{name}\": \"{url}\""),
            });
        }
    }
    out
}

/// A VS Code extension root: package.json with `engines.vscode`.
pub fn is_vscode_extension(root: &Path) -> bool {
    std::fs::read_to_string(root.join("package.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .is_some_and(|v| v["engines"]["vscode"].is_string())
}

fn own_package(root: &Path) -> Option<DependencyPackage> {
    let read = |f: &str| std::fs::read_to_string(root.join(f)).ok();
    let pkg = |name: &str, version: &str, ecosystem: &str, file: &str| DependencyPackage {
        name: name.trim().to_string(),
        version: version.trim().to_string(),
        ecosystem: ecosystem.to_string(),
        manifest_file: file.to_string(),
    };
    if let Some(json) = read("package.json") {
        let v: serde_json::Value = serde_json::from_str(&json).ok()?;
        return Some(pkg(
            v["name"].as_str()?,
            v["version"].as_str().unwrap_or("0"),
            "npm",
            "package.json",
        ));
    }
    // A wheel (what pip installs, and what a registry scan downloads when
    // one exists) has no PKG-INFO: its identity is `<name>.dist-info/METADATA`.
    let wheel = || {
        let dir = std::fs::read_dir(root).ok()?.flatten().find(|e| {
            e.file_name().to_string_lossy().ends_with(".dist-info")
                && e.path().join("METADATA").is_file()
        })?;
        let file = format!("{}/METADATA", dir.file_name().to_string_lossy());
        Some((
            std::fs::read_to_string(dir.path().join("METADATA")).ok()?,
            file,
        ))
    };
    if let Some((info, file)) = read("PKG-INFO")
        .map(|info| (info, "PKG-INFO".to_string()))
        .or_else(wheel)
    {
        let field = |k: &str| info.lines().find_map(|l| l.strip_prefix(k));
        return Some(pkg(
            field("Name: ")?,
            field("Version: ").unwrap_or("0"),
            "PyPI",
            &file,
        ));
    }
    let setup = read("setup.py")?;
    let field = |k: &str| {
        let re = regex::Regex::new(&format!(r#"\b{}\s*=\s*['"]([^'"]+)['"]"#, k)).ok()?;
        Some(re.captures(&setup)?[1].to_string())
    };
    Some(pkg(
        &field("name")?,
        &field("version").unwrap_or_default(),
        "PyPI",
        "setup.py",
    ))
}

pub const BUILTIN_NAME_DEP: &str = "Dependency on a Node Built-in Name";
pub const UNCLAIMED_DEP: &str = "Dependency Name Unclaimed on the Registry";

/// Node core modules whose npm name is a placeholder or a dead package
/// (checked 2026-11-19). Depending on one is a mistake, typically in a
/// generated `package.json`; `readline`, `path`, `os` and the like are real
/// packages and are left out.
const NODE_BUILTIN_PLACEHOLDERS: &[&str] = &[
    "async_hooks",
    "child_process",
    "crypto",
    "dgram",
    "fs",
    "http",
    "perf_hooks",
    "trace_events",
    "worker_threads",
];

/// Most names one project's manifests are checked against the registry for.
const MAX_UNCLAIMED_LOOKUPS: usize = 50;

/// Hygiene of the operator's own manifests, not malware evidence (severity
/// low, so the v1 score ignores it): a dependency on a Node built-in's name,
/// and, with `online`, an unscoped dependency name nobody has registered.
/// Anyone can publish that name and it gets installed, which is what
/// dependency confusion and names an AI assistant made up (slopsquatting)
/// rely on. Popular names are not looked up.
pub async fn own_manifest_matches(packages: &[DependencyPackage], online: bool) -> Vec<RuleMatch> {
    let hit = |p: &DependencyPackage, pattern: &str, context: String| RuleMatch {
        file_path: p.manifest_file.clone(),
        line_number: 1,
        matched_pattern: pattern.to_string(),
        severity: "low".to_string(),
        context,
    };
    let mut out: Vec<RuleMatch> = packages
        .iter()
        .filter(|p| p.ecosystem == "npm" && NODE_BUILTIN_PLACEHOLDERS.contains(&p.name.as_str()))
        .map(|p| {
            hit(p, BUILTIN_NAME_DEP, format!(
                "'{}' is a Node core module; the npm package of that name is a placeholder, so the dependency installs nothing useful and should be removed",
                p.name
            ))
        })
        .collect();
    if !online {
        return out;
    }
    let Ok(client) = crate::vsix::http_client() else {
        return out;
    };
    let candidates: Vec<&DependencyPackage> = packages
        .iter()
        .filter(|p| matches!(p.ecosystem.as_str(), "npm" | "PyPI") && !p.name.starts_with('@'))
        .filter(|p| !popular(&p.ecosystem).contains(&p.name.to_lowercase()))
        .take(MAX_UNCLAIMED_LOOKUPS)
        .collect();
    let mut lookups = tokio::task::JoinSet::new();
    for (i, p) in candidates.iter().enumerate() {
        let url = if p.ecosystem == "npm" {
            format!("https://registry.npmjs.org/{}", p.name)
        } else {
            format!("https://pypi.org/pypi/{}/json", p.name)
        };
        let client = client.clone();
        lookups.spawn(async move { (i, client.head(url).send().await.ok().map(|r| r.status())) });
    }
    let mut missing: Vec<usize> = Vec::new();
    while let Some(Ok((i, status))) = lookups.join_next().await {
        // Only a definite 404: an error or a rate limit says nothing.
        if status == Some(reqwest::StatusCode::NOT_FOUND) {
            missing.push(i);
        }
    }
    missing.sort_unstable();
    for p in missing.into_iter().map(|i| candidates[i]) {
        out.push(hit(p, UNCLAIMED_DEP, format!(
                "No package named '{}' on the public {} registry: whoever registers it first is what this manifest installs",
                p.name, p.ecosystem
            )));
    }
    out
}

/// Query OSV (Open Source Vulnerabilities) API for known vulnerabilities
pub async fn check_vulnerabilities(packages: &[DependencyPackage]) -> Vec<RuleMatch> {
    if packages.is_empty() {
        return Vec::new();
    }

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    // OSV accepts up to 1000 queries per batch; the old `take(100)` silently
    // dropped the rest of any real Cargo.lock / package tree.
    let mut matches = Vec::new();
    for batch in packages.chunks(OSV_BATCH_LIMIT) {
        if let Some(results) = query_batch(&client, batch).await {
            matches.extend(osv_matches(batch, results));
        }
    }
    matches
}

const OSV_BATCH_LIMIT: usize = 1000;

async fn query_batch(
    client: &reqwest::Client,
    batch: &[DependencyPackage],
) -> Option<Vec<OsvQueryResult>> {
    let queries: Vec<OsvSingleQuery> = batch
        .iter()
        .map(|p| OsvSingleQuery {
            package: OsvPackageInfo {
                name: p.name.clone(),
                ecosystem: p.ecosystem.clone(),
            },
            version: p.version.clone(),
        })
        .collect();

    let payload = OsvBatchQuery { queries };

    let resp = match client
        .post("https://api.osv.dev/v1/querybatch")
        .json(&payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("Failed to query OSV vulnerability API: {}", e);
            return None;
        }
    };

    match resp.json::<OsvBatchResponse>().await {
        Ok(res) => res.results,
        Err(e) => {
            warn!("Failed to decode OSV API response: {}", e);
            None
        }
    }
}

/// Turn OSV results (index-aligned with `batch`) into findings. `MAL-*`
/// advisories are known malicious packages, so they are malware evidence,
/// not dependency hygiene.
fn osv_matches(batch: &[DependencyPackage], results: Vec<OsvQueryResult>) -> Vec<RuleMatch> {
    let mut matches = Vec::new();
    for (result, pkg) in results.into_iter().zip(batch) {
        for v in result.vulns.unwrap_or_default() {
            let malicious = v.id.starts_with("MAL-");
            let summary = v.summary.or(v.details).unwrap_or_else(|| {
                if malicious {
                    "Package is listed as malicious in the OSV database".to_string()
                } else {
                    "Known vulnerability detected".to_string()
                }
            });

            let short_summary = if summary.chars().count() > 140 {
                format!("{}...", summary.chars().take(140).collect::<String>())
            } else {
                summary
            };

            info!("OSV CVE Match: {} in {}@{}", v.id, pkg.name, pkg.version);

            let (label, severity) = if malicious {
                ("Malicious Package", "critical")
            } else {
                ("Known Vulnerability", "high")
            };
            matches.push(RuleMatch {
                file_path: pkg.manifest_file.clone(),
                line_number: 1,
                matched_pattern: format!("{}: {} in {}@{}", label, v.id, pkg.name, pkg.version),
                severity: severity.to_string(),
                context: short_summary,
            });
        }
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reordered_words_and_dropped_scope_look_alike() {
        let json = r#"{"dependencies": {"styles-ansi": "1.0.0", "ansi-styles": "6.2.1", "trace-mapping": "1.0.0", "@jridgewell/trace-mapping": "0.3.25", "fs": "0.0.1", "path": "0.12.7"}}"#;
        let deps = parse_package_json(json, "package.json");
        let found: Vec<String> = typosquat_matches(&deps)
            .into_iter()
            .map(|m| m.matched_pattern)
            .collect();
        assert_eq!(
            found,
            [
                "Typo-squat Suspect: styles-ansi (looks like ansi-styles)",
                "Typo-squat Suspect: trace-mapping (looks like @jridgewell/trace-mapping)",
            ]
        );
        // Offline: only the built-in placeholder name; `path` is a real package.
        let own = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(own_manifest_matches(&deps, false));
        assert_eq!(own.len(), 1);
        assert_eq!(
            (own[0].matched_pattern.as_str(), own[0].severity.as_str()),
            (BUILTIN_NAME_DEP, "low")
        );
        assert!(own[0].context.contains("'fs'"));
    }

    #[test]
    fn test_typosquat_matches() {
        let json = r#"{"dependencies": {"crossenv": "1.0.0", "cross-env": "7.0.3", "vuex": "4.0.0", "preact": "10.0.0", "expresss": "1.0.0"}}"#;
        let found: Vec<String> = typosquat_matches(&parse_package_json(json, "package.json"))
            .into_iter()
            .map(|m| m.matched_pattern)
            .collect();
        assert_eq!(
            found,
            vec![
                "Typo-squat Suspect: crossenv (looks like cross-env)".to_string(),
                "Typo-squat Suspect: expresss (looks like express)".to_string(),
            ]
        );
        let py = parse_requirements_txt("reqeusts==1.0\nrequest==2.0\nrequests==2.31\n", "r.txt");
        let py_found: Vec<_> = typosquat_matches(&py)
            .into_iter()
            .map(|m| m.matched_pattern)
            .collect();
        // `reqeusts` is a swap of neighbours: one edit under OSA distance.
        assert_eq!(
            py_found,
            vec![
                "Typo-squat Suspect: reqeusts (looks like requests)".to_string(),
                "Typo-squat Suspect: request (looks like requests)".to_string(),
            ]
        );
    }

    #[test]
    fn test_own_package_identity() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name": "ebay-tester", "version": "999.9.9", "scripts": {"preinstall": "node index.js"}}"#,
        )
        .unwrap();
        let names: Vec<String> = own_package_matches(dir.path())
            .into_iter()
            .map(|m| m.matched_pattern)
            .collect();
        assert_eq!(
            names,
            vec![crate::correlate::DEP_CONFUSION_VERSION.to_string()]
        );

        let py = tempfile::tempdir().unwrap();
        std::fs::write(
            py.path().join("PKG-INFO"),
            "Metadata-Version: 2.1\nName: asyncoi\nVersion: 0.1\n",
        )
        .unwrap();
        let names: Vec<String> = own_package_matches(py.path())
            .into_iter()
            .map(|m| m.matched_pattern)
            .collect();
        assert_eq!(
            names,
            vec!["Typo-squat Suspect: asyncoi (looks like asyncio)".to_string()]
        );

        // A wheel: no PKG-INFO, the identity is in `<name>.dist-info/METADATA`.
        let wheel = tempfile::tempdir().unwrap();
        let info = wheel.path().join("keystackutilities-99.99.1.dist-info");
        std::fs::create_dir(&info).unwrap();
        std::fs::write(
            info.join("METADATA"),
            "Metadata-Version: 2.1\nName: keystackutilities\nVersion: 99.99.1\n",
        )
        .unwrap();
        let found = own_package_matches(wheel.path());
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].matched_pattern,
            crate::correlate::DEP_CONFUSION_VERSION
        );
        assert_eq!(
            found[0].file_path,
            "keystackutilities-99.99.1.dist-info/METADATA"
        );

        // A page served from the registry's CDNs, not a module.
        let page = tempfile::tempdir().unwrap();
        let manifest = |main: &str| {
            std::fs::write(
                page.path().join("package.json"),
                format!(r#"{{"name": "kambx", "version": "1.0.0", "main": "{main}", "unpkg": "{main}"}}"#),
            )
            .unwrap();
            web_page_entry(page.path())
                .into_iter()
                .map(|m| m.matched_pattern)
                .collect::<Vec<_>>()
        };
        std::fs::write(
            page.path().join("index.svg"),
            "<svg><foreignObject/><SCRIPT>\n<![CDATA[ go() ]]></SCRIPT></svg>",
        )
        .unwrap();
        std::fs::write(page.path().join("about.html"), "<h1>docs</h1>").unwrap();
        // A Polymer element's demo page: scripts by reference, HTML Imports.
        std::fs::write(
            page.path().join("element.html"),
            "<!doctype html><html><script src=\"../webcomponentsjs/webcomponents-lite.js\"></script>\
             <link rel=\"import\" href=\"x.html\"><script>Polymer({})</script></html>",
        )
        .unwrap();
        assert_eq!(manifest("element.html"), vec![WEB_PAGE_ENTRY]);
        assert_eq!(
            manifest("index.svg"),
            vec![crate::correlate::WEB_PAGE_PACKAGE]
        );
        assert_eq!(manifest("./about.html"), vec![WEB_PAGE_ENTRY]);
        assert_eq!(manifest("../../etc/x.html"), vec![WEB_PAGE_ENTRY]);
        assert!(manifest("index.js").is_empty());

        let setup = tempfile::tempdir().unwrap();
        std::fs::write(
            setup.path().join("setup.py"),
            "setup(name='manda-tu-cv-a-secureit',\n      version='88.88.88')",
        )
        .unwrap();
        assert!(own_package_matches(setup.path()).is_empty(), "88 < 99");

        let calver = tempfile::tempdir().unwrap();
        std::fs::write(
            calver.path().join("package.json"),
            r#"{"name": "vscode-pylance", "version": "2026.4.1", "engines": {"vscode": "^1.90.0"}}"#,
        )
        .unwrap();
        assert!(own_package_matches(calver.path()).is_empty(), "CalVer year");
        assert!(is_vscode_extension(calver.path()));
        assert!(!is_vscode_extension(dir.path()));
        assert_eq!(edit_distance("asyncoi", "asyncio"), 1);
        assert_eq!(edit_distance("lodash", "lodahs"), 1);
        assert_eq!(edit_distance("kitten", "sitting"), 3);
    }

    #[test]
    fn test_malicious_package_advisory_is_critical() {
        let pkgs = parse_requirements_txt("evilpkg==1.0\nrequests==2.25.1\n", "requirements.txt");
        let vuln = |id: &str| OsvVuln {
            id: id.to_string(),
            summary: None,
            details: None,
        };
        let results = vec![
            OsvQueryResult {
                vulns: Some(vec![vuln("MAL-2024-1234")]),
            },
            OsvQueryResult {
                vulns: Some(vec![vuln("GHSA-j8r2-6x86-q33q")]),
            },
        ];
        let matches = osv_matches(&pkgs, results);
        assert_eq!(matches.len(), 2);
        assert_eq!(
            matches[0].matched_pattern,
            "Malicious Package: MAL-2024-1234 in evilpkg@1.0"
        );
        assert_eq!(matches[0].severity, "critical");
        assert!(matches[1]
            .matched_pattern
            .starts_with("Known Vulnerability: GHSA-"));
        assert_eq!(matches[1].severity, "high");
    }

    #[test]
    fn test_parse_package_json() {
        let json_str = r#"{
            "name": "sample",
            "dependencies": {
                "axios": "^0.21.1",
                "lodash": "4.17.20"
            },
            "devDependencies": {
                "mocha": "~8.0.0"
            }
        }"#;

        let pkgs = parse_package_json(json_str, "package.json");
        assert_eq!(pkgs.len(), 3);
        assert!(pkgs
            .iter()
            .any(|p| p.name == "axios" && p.version == "0.21.1"));
        assert!(pkgs
            .iter()
            .any(|p| p.name == "lodash" && p.version == "4.17.20"));
        assert!(pkgs
            .iter()
            .any(|p| p.name == "mocha" && p.version == "8.0.0"));
    }

    #[test]
    fn test_parse_cargo_lock() {
        let lock_str = r#"
[[package]]
name = "serde"
version = "1.0.104"

[[package]]
name = "tokio"
version = "1.20.0"
"#;
        let pkgs = parse_cargo_lock(lock_str, "Cargo.lock");
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "serde");
        assert_eq!(pkgs[0].version, "1.0.104");
        assert_eq!(pkgs[1].name, "tokio");
        assert_eq!(pkgs[1].version, "1.20.0");
    }

    #[test]
    fn test_parse_requirements_txt() {
        let req_str = "requests==2.25.1\nflask==1.1.2\n# comment\n";
        let pkgs = parse_requirements_txt(req_str, "requirements.txt");
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "requests");
        assert_eq!(pkgs[0].version, "2.25.1");
    }

    #[test]
    fn dependency_fetched_from_a_private_server() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name": "pear-wrk-wdk", "version": "0.0.5",
  "dependencies": {"ui-styles-pkg": "http://npm.artifacts-cdn.example/npm/pear-wrk-wdk",
    "fork": "https://github.com/a/b/tarball/v1", "semver": "^7.0.0"},
  "homepage": "https://example.com"}"#,
        )
        .unwrap();
        let found: Vec<RuleMatch> = own_package_matches(dir.path())
            .into_iter()
            .filter(|m| m.matched_pattern == REMOTE_URL_DEP)
            .collect();
        assert_eq!(found.len(), 1, "{:?}", found);
        assert_eq!(found[0].line_number, 2);
        assert!(found[0].context.contains("npm.artifacts-cdn.example"));
    }

    #[test]
    fn sheetjs_from_its_own_cdn_is_its_documented_install() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name": "report-export", "version": "1.0.0",
  "dependencies": {"xlsx": "https://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz",
    "xlsx-style": "https://cdn.sheetjs.com.pkg-mirror.example/xlsx-0.20.3.tgz"}}"#,
        )
        .unwrap();
        let found: Vec<RuleMatch> = own_package_matches(dir.path())
            .into_iter()
            .filter(|m| m.matched_pattern == REMOTE_URL_DEP)
            .collect();
        assert_eq!(found.len(), 1, "{:?}", found);
        assert!(found[0].context.contains("pkg-mirror.example"));
    }
}
