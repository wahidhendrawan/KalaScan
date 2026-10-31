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

/// Most-downloaded packages, the usual typo-squat targets.
/// shortcut: hand-picked top names; swap for a generated top-N list if misses show up.
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
];

/// Real packages that happen to sit one edit from a popular name.
const KNOWN_NEIGHBORS: &[&str] = &["preact", "color", "ether", "chalk-cli", "requests-oauthlib"];

/// Dependencies one edit away from a popular package they are not.
/// Names under 5 chars are skipped: `vue`/`vuex`, `next`/`nest` are all real.
pub fn typosquat_matches(packages: &[DependencyPackage]) -> Vec<RuleMatch> {
    packages
        .iter()
        .filter_map(|p| {
            let popular = match p.ecosystem.as_str() {
                "npm" => POPULAR_NPM,
                "PyPI" => POPULAR_PYPI,
                _ => return None,
            };
            let name = p.name.to_lowercase();
            if name.len() < 5
                || popular.contains(&name.as_str())
                || KNOWN_NEIGHBORS.contains(&name.as_str())
            {
                return None;
            }
            let target = popular
                .iter()
                .find(|t| t.len() >= 5 && levenshtein(&name, t) == 1)?;
            Some(RuleMatch {
                file_path: p.manifest_file.clone(),
                line_number: 1,
                matched_pattern: format!("Typo-squat Suspect: {} (looks like {})", p.name, target),
                severity: "high".to_string(),
                context: format!(
                    "Dependency '{}' is one edit away from the popular package '{}'",
                    p.name, target
                ),
            })
        })
        .collect()
}

fn levenshtein(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            cur.push(
                (prev[j] + (ca != *cb) as usize)
                    .min(prev[j + 1] + 1)
                    .min(cur[j] + 1),
            );
        }
        prev = cur;
    }
    prev[b.len()]
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
        assert_eq!(
            py_found,
            vec!["Typo-squat Suspect: request (looks like requests)".to_string()]
        );
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
}
