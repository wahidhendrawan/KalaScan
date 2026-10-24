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

/// Query OSV (Open Source Vulnerabilities) API for known vulnerabilities
pub async fn check_vulnerabilities(packages: &[DependencyPackage]) -> Vec<RuleMatch> {
    if packages.is_empty() {
        return Vec::new();
    }

    // Limit batch size to max 100 packages to keep request responsive
    let batch: Vec<DependencyPackage> = packages.iter().take(100).cloned().collect();

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

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let resp = match client
        .post("https://api.osv.dev/v1/querybatch")
        .json(&payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("Failed to query OSV vulnerability API: {}", e);
            return Vec::new();
        }
    };

    let batch_res: OsvBatchResponse = match resp.json().await {
        Ok(res) => res,
        Err(e) => {
            warn!("Failed to decode OSV API response: {}", e);
            return Vec::new();
        }
    };

    let mut matches = Vec::new();
    if let Some(results) = batch_res.results {
        for (idx, result) in results.into_iter().enumerate() {
            if let Some(vulns) = result.vulns {
                if let Some(pkg) = batch.get(idx) {
                    for v in vulns {
                        let summary = v
                            .summary
                            .or(v.details)
                            .unwrap_or_else(|| "Known vulnerability detected".to_string());

                        let short_summary = if summary.chars().count() > 140 {
                            format!("{}...", summary.chars().take(140).collect::<String>())
                        } else {
                            summary
                        };

                        info!("OSV CVE Match: {} in {}@{}", v.id, pkg.name, pkg.version);

                        matches.push(RuleMatch {
                            file_path: pkg.manifest_file.clone(),
                            line_number: 1,
                            matched_pattern: format!(
                                "Known Vulnerability: {} in {}@{}",
                                v.id, pkg.name, pkg.version
                            ),
                            severity: "high".to_string(),
                            context: short_summary,
                        });
                    }
                }
            }
        }
    }

    matches
}

#[cfg(test)]
mod tests {
    use super::*;

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
