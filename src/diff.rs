//! Version diff: which capabilities appear in the new release that the old
//! one did not have. Update hijacks (a trusted extension or package whose
//! next version adds a stealer) show up here even when the absolute score of
//! a large codebase hides them.

use crate::{RuleMatch, ScanResult};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Serialize)]
pub struct VersionDiff {
    pub old_target: String,
    pub new_target: String,
    pub old_risk: u8,
    pub new_risk: u8,
    /// Rules that fire in the new version and never fired in the old one.
    pub new_capabilities: Vec<Capability>,
    /// Rules that fired in the old version and are gone.
    pub removed_capabilities: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Capability {
    pub rule: String,
    pub severity: String,
    pub files: Vec<String>,
    pub example: String,
}

/// Rule identity for diffing. Per-advisory and per-entropy names collapse so
/// a version bump of one dependency is not a "new capability".
fn capability_key(m: &RuleMatch) -> String {
    let p = &m.matched_pattern;
    for prefix in ["Known Vulnerability", "High-Entropy Suspicious Blob"] {
        if p.starts_with(prefix) {
            return prefix.to_string();
        }
    }
    p.clone()
}

fn by_capability(result: &ScanResult) -> BTreeMap<String, Vec<&RuleMatch>> {
    let mut map: BTreeMap<String, Vec<&RuleMatch>> = BTreeMap::new();
    for m in &result.rule_matches {
        map.entry(capability_key(m)).or_default().push(m);
    }
    map
}

pub fn diff(old: &ScanResult, new: &ScanResult) -> VersionDiff {
    let (old_caps, new_caps) = (by_capability(old), by_capability(new));
    let mut new_capabilities: Vec<Capability> = new_caps
        .iter()
        .filter(|(key, _)| !old_caps.contains_key(*key))
        .map(|(key, hits)| {
            let mut files: Vec<String> = hits.iter().map(|m| m.file_path.clone()).collect();
            files.dedup();
            files.truncate(5);
            Capability {
                rule: key.clone(),
                severity: hits[0].severity.clone(),
                files,
                example: hits[0].context.chars().take(160).collect(),
            }
        })
        .collect();
    new_capabilities.sort_by_key(|c| severity_rank(&c.severity));
    VersionDiff {
        old_target: old.repo_url.clone(),
        new_target: new.repo_url.clone(),
        old_risk: old.risk_score,
        new_risk: new.risk_score,
        new_capabilities,
        removed_capabilities: old_caps
            .keys()
            .filter(|k| !new_caps.contains_key(*k))
            .cloned()
            .collect(),
    }
}

/// Lower is more severe, for sorting and for `--fail-on-new`.
pub fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        _ => 3,
    }
}

pub fn format_text(d: &VersionDiff) -> String {
    let mut out = format!(
        "KalaScan version diff\n  old: {} (risk {})\n  new: {} (risk {})\n\n",
        d.old_target, d.old_risk, d.new_target, d.new_risk
    );
    if d.new_capabilities.is_empty() {
        out.push_str("No new capabilities in the new version.\n");
    } else {
        out.push_str(&format!(
            "New capabilities ({}):\n",
            d.new_capabilities.len()
        ));
        for c in &d.new_capabilities {
            out.push_str(&format!("  [{}] {}\n", c.severity.to_uppercase(), c.rule));
            for f in &c.files {
                out.push_str(&format!("      {}\n", f));
            }
        }
    }
    if !d.removed_capabilities.is_empty() {
        out.push_str(&format!(
            "\nNo longer present: {}\n",
            d.removed_capabilities.join(", ")
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(target: &str, risk: u8, hits: &[(&str, &str, &str)]) -> ScanResult {
        let mut r: ScanResult = serde_json::from_value(serde_json::json!({
            "id": "x", "repo_url": target, "timestamp": "", "total_files": 0, "scanned_files": 0,
            "total_matches": hits.len(), "risk_score": risk, "ai_analysis": null, "rule_matches": [],
            "status": "completed"
        }))
        .unwrap();
        r.rule_matches = hits
            .iter()
            .map(|(file, rule, sev)| RuleMatch {
                file_path: file.to_string(),
                line_number: 1,
                matched_pattern: rule.to_string(),
                severity: sev.to_string(),
                context: String::new(),
            })
            .collect();
        r
    }

    #[test]
    fn reports_capabilities_added_by_the_update() {
        let old = result(
            "npm:lib@1.0.0",
            10,
            &[
                ("index.js", "URL Fetch Command", "medium"),
                ("package.json", "Known Vulnerability: GHSA-1 in a@1", "high"),
                ("index.js", "eval() Usage", "high"),
            ],
        );
        let new = result(
            "npm:lib@1.0.1",
            90,
            &[
                ("index.js", "URL Fetch Command", "medium"),
                ("package.json", "Known Vulnerability: GHSA-2 in a@2", "high"),
                (
                    "lib/telemetry.js",
                    "Chain: Credential Exfiltration",
                    "critical",
                ),
                ("lib/telemetry.js", "Host Reconnaissance", "medium"),
            ],
        );
        let d = diff(&old, &new);
        let rules: Vec<&str> = d.new_capabilities.iter().map(|c| c.rule.as_str()).collect();
        // Critical first; a different advisory ID is not a new capability.
        assert_eq!(
            rules,
            vec!["Chain: Credential Exfiltration", "Host Reconnaissance"]
        );
        assert_eq!(d.new_capabilities[0].files, vec!["lib/telemetry.js"]);
        assert_eq!(d.removed_capabilities, vec!["eval() Usage"]);
        assert!(format_text(&d).contains("[CRITICAL] Chain: Credential Exfiltration"));
    }
}
