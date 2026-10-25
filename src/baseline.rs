//! Finding suppression: stable fingerprints, baseline files, and `.kalascanignore` path globs.
//!
//! Baseline flow for CI:
//!   1. `kalascan scan ... --baseline .kalascan.baseline.json` records every finding.
//!   2. Next run with `--new-only` reports only findings absent from the baseline.
//!
//! Path globs in `.kalascanignore` are matched against repo-relative paths
//! (`*` = any sequence, `?` = one char). Lines starting with `#` are comments.

use crate::RuleMatch;
use anyhow::{Context, Result};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;

/// Stable per-finding id: rule + file + line. Survives unrelated file edits.
pub fn fingerprint(m: &RuleMatch) -> String {
    let mut hasher = Sha256::new();
    hasher.update(m.matched_pattern.as_bytes());
    hasher.update(b"\0");
    hasher.update(m.file_path.trim_start_matches("./").as_bytes());
    hasher.update(b"\0");
    hasher.update(m.line_number.to_string().as_bytes());
    hex::encode(&hasher.finalize()[..16])
}

pub struct IgnoreSet {
    patterns: Vec<Regex>,
}

impl IgnoreSet {
    pub fn load(path: &Path) -> Self {
        let patterns = std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter_map(|glob| glob_to_regex(glob).ok())
            .collect();
        Self { patterns }
    }

    pub fn is_ignored(&self, path: &str) -> bool {
        let path = path.trim_start_matches("./");
        self.patterns.iter().any(|re| re.is_match(path))
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

fn glob_to_regex(glob: &str) -> Result<Regex> {
    let mut out = String::from("^(?:.*/)?");
    for ch in glob.chars() {
        match ch {
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            c => out.push_str(&regex::escape(&c.to_string())),
        }
    }
    out.push('$');
    Regex::new(&out).context("invalid ignore pattern")
}

/// Read fingerprints from a baseline JSON file. Accepts either a bare array or
/// `{ "fingerprints": [...] }`.
pub fn load_baseline(path: &Path) -> Result<BTreeSet<String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read baseline {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse baseline {}", path.display()))?;
    let entries = match value {
        serde_json::Value::Array(items) => items,
        serde_json::Value::Object(obj) => obj
            .get("fingerprints")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    Ok(entries
        .into_iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect())
}

/// Write all current finding fingerprints as a baseline.
pub fn save_baseline(path: &Path, matches: &[RuleMatch]) -> Result<()> {
    let fingerprints: BTreeSet<String> = matches.iter().map(fingerprint).collect();
    write_baseline(path, fingerprints)
}

/// Merge current findings into an existing baseline (union), preserving
/// previously recorded fingerprints. Used so `--new-only --baseline` records
/// the newly surfaced findings without dropping the old ones.
pub fn merge_baseline(path: &Path, matches: &[RuleMatch]) -> Result<()> {
    let mut fingerprints = load_baseline(path).unwrap_or_default();
    fingerprints.extend(matches.iter().map(fingerprint));
    write_baseline(path, fingerprints)
}

fn write_baseline(path: &Path, fingerprints: BTreeSet<String>) -> Result<()> {
    let payload = serde_json::json!({
        "version": 1,
        "tool": "kalascan",
        "fingerprints": fingerprints,
    });
    std::fs::write(path, serde_json::to_string_pretty(&payload)?)
        .with_context(|| format!("failed to write baseline {}", path.display()))
}

/// Drop findings ignored by path globs, then (optionally) anything already baselined.
pub fn apply_filters(
    matches: Vec<RuleMatch>,
    ignore: &IgnoreSet,
    baseline: Option<&BTreeSet<String>>,
) -> Vec<RuleMatch> {
    matches
        .into_iter()
        .filter(|m| !ignore.is_ignored(&m.file_path))
        .filter(|m| baseline.is_none_or(|b| !b.contains(&fingerprint(m))))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(rule: &str, file: &str, line: usize) -> RuleMatch {
        RuleMatch {
            file_path: file.to_string(),
            line_number: line,
            matched_pattern: rule.to_string(),
            severity: "high".to_string(),
            context: String::new(),
        }
    }

    #[test]
    fn fingerprint_is_stable_and_location_scoped() {
        assert_eq!(
            fingerprint(&m("eval", "src/a.js", 3)),
            fingerprint(&m("eval", "src/a.js", 3))
        );
        assert_ne!(
            fingerprint(&m("eval", "src/a.js", 3)),
            fingerprint(&m("eval", "src/a.js", 4))
        );
        assert_ne!(
            fingerprint(&m("eval", "src/a.js", 3)),
            fingerprint(&m("exec", "src/a.js", 3))
        );
    }

    #[test]
    fn ignore_globs_match_relative_paths() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".kalascanignore");
        std::fs::write(&path, "# comment\nsrc/generated/*\n*.min.js\n").unwrap();
        let set = IgnoreSet::load(&path);
        assert!(set.is_ignored("src/generated/client.ts"));
        assert!(set.is_ignored("./src/generated/deep/x.ts"));
        assert!(set.is_ignored("assets/app.min.js"));
        assert!(!set.is_ignored("src/app.ts"));
    }

    #[test]
    fn baseline_roundtrip_suppresses_known_findings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");
        let known = vec![m("eval", "src/a.js", 3)];
        save_baseline(&path, &known).unwrap();

        let loaded = load_baseline(&path).unwrap();
        assert_eq!(loaded.len(), 1);

        let input = vec![m("eval", "src/a.js", 3), m("exec", "src/b.js", 10)];
        let filtered = apply_filters(
            input,
            &IgnoreSet::load(&dir.path().join("missing")),
            Some(&loaded),
        );
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].file_path, "src/b.js");
    }

    #[test]
    fn merge_baseline_preserves_existing_fingerprints() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");
        save_baseline(&path, &[m("eval", "src/a.js", 3)]).unwrap();

        // A `--new-only` run surfaces a different finding; merging must keep both.
        merge_baseline(&path, &[m("exec", "src/b.js", 10)]).unwrap();
        let merged = load_baseline(&path).unwrap();
        assert_eq!(merged.len(), 2);
    }
}
