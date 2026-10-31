//! Finding suppression: stable fingerprints, baseline files, and `.kalascanignore` path globs.
//!
//! Baseline flow for CI:
//!   1. `kalascan scan ... --baseline F --update-baseline` records every finding.
//!   2. `kalascan scan ... --baseline F --new-only` reports only findings absent
//!      from the baseline and never writes it: accepting a finding is a
//!      deliberate step 1, not a side effect of the run that reported it.
//!
//! Path globs in `.kalascanignore` are matched against repo-relative paths
//! (`*` = any sequence, `?` = one char). Lines starting with `#` are comments.

use crate::RuleMatch;
use anyhow::{Context, Result};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;

/// Baseline file format. Version 1 keyed findings by line number.
const BASELINE_VERSION: u64 = 2;

/// The text a finding was found in: the matched line as the context shows
/// it (`before\n>>> match <<<\nafter`), whitespace collapsed. Findings whose
/// context has no marker (entropy, YARA) use the whole context.
fn matched_text(context: &str) -> String {
    let line = context.split_once("\n>>> ").and_then(|(before, rest)| {
        let (matched, after) = rest.split_once(" <<<")?;
        let left = before.rsplit('\n').next().unwrap_or_default();
        let right = after.strip_prefix('\n').unwrap_or(after);
        let right = right.split('\n').next().unwrap_or_default();
        Some(format!("{}{}{}", left, matched, right))
    });
    line.as_deref()
        .unwrap_or(context)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Stable per-finding ids, aligned with `matches`: rule, file, matched text,
/// and which occurrence of that text in the file it is (by line order). No
/// line number: inserting a line above used to re-key every finding below
/// it, so `--new-only` reported them all as new. The occurrence index keeps a
/// second, newly added copy of a known line from hiding behind the first.
pub fn fingerprints(matches: &[RuleMatch]) -> Vec<String> {
    let keys: Vec<String> = matches
        .iter()
        .map(|m| {
            format!(
                "{}\0{}\0{}",
                m.matched_pattern,
                m.file_path.trim_start_matches("./"),
                matched_text(&m.context)
            )
        })
        .collect();
    let mut order: Vec<usize> = (0..matches.len()).collect();
    order.sort_by(|&a, &b| {
        keys[a]
            .cmp(&keys[b])
            .then(matches[a].line_number.cmp(&matches[b].line_number))
            .then(a.cmp(&b))
    });
    let mut out = vec![String::new(); matches.len()];
    let mut occurrence = 0usize;
    for (pos, &i) in order.iter().enumerate() {
        occurrence = match pos.checked_sub(1).map(|p| order[p]) {
            Some(prev) if keys[prev] == keys[i] => occurrence + 1,
            _ => 0,
        };
        let mut hasher = Sha256::new();
        hasher.update(keys[i].as_bytes());
        hasher.update(b"\0");
        hasher.update(occurrence.to_string().as_bytes());
        out[i] = hex::encode(&hasher.finalize()[..16]);
    }
    out
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

/// Read fingerprints from a baseline JSON file written by `save_baseline`.
/// An older file is refused rather than read: its line-number fingerprints
/// match nothing, and every known finding would be reported as new.
pub fn load_baseline(path: &Path) -> Result<BTreeSet<String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read baseline {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse baseline {}", path.display()))?;
    if value.get("version").and_then(|v| v.as_u64()) != Some(BASELINE_VERSION) {
        anyhow::bail!(
            "baseline {} was written by an older KalaScan; rebuild it with \
             `--baseline {} --update-baseline`",
            path.display(),
            path.display()
        );
    }
    Ok(value
        .get("fingerprints")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect())
}

/// Write all current finding fingerprints as a baseline.
pub fn save_baseline(path: &Path, matches: &[RuleMatch]) -> Result<()> {
    let payload = serde_json::json!({
        "version": BASELINE_VERSION,
        "tool": "kalascan",
        "fingerprints": fingerprints(matches).into_iter().collect::<BTreeSet<_>>(),
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
    let kept: Vec<RuleMatch> = matches
        .into_iter()
        .filter(|m| !ignore.is_ignored(&m.file_path))
        .collect();
    let Some(baseline) = baseline else {
        return kept;
    };
    // Fingerprints of the whole set: occurrence numbers depend on it.
    let ids = fingerprints(&kept);
    kept.into_iter()
        .zip(ids)
        .filter(|(_, id)| !baseline.contains(id))
        .map(|(m, _)| m)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(rule: &str, file: &str, line: usize) -> RuleMatch {
        at(rule, file, line, &format!("code line {}", line))
    }

    /// A finding whose matched line reads `line_text`, as the scanner formats it.
    fn at(rule: &str, file: &str, line: usize, line_text: &str) -> RuleMatch {
        RuleMatch {
            file_path: file.to_string(),
            line_number: line,
            matched_pattern: rule.to_string(),
            severity: "high".to_string(),
            context: format!("prev line\n{}\n>>> eval( <<<\nx)\nnext line", line_text),
        }
    }

    #[test]
    fn fingerprint_survives_line_shifts_but_not_new_copies() {
        let before = [at("eval", "src/a.js", 3, "run  =")];
        // A line inserted above: same text, new line number.
        let shifted = [at("eval", "src/a.js", 4, "run =")];
        assert_eq!(fingerprints(&before), fingerprints(&shifted));
        // Other rule or other text: other finding.
        assert_ne!(
            fingerprints(&before),
            fingerprints(&[at("exec", "src/a.js", 3, "run =")])
        );
        assert_ne!(
            fingerprints(&before),
            fingerprints(&[at("eval", "src/a.js", 3, "go =")])
        );
        // A second identical line is a new finding, not covered by the first.
        let two = [
            at("eval", "src/a.js", 3, "run ="),
            at("eval", "src/a.js", 9, "run ="),
        ];
        let ids = fingerprints(&two);
        assert_ne!(ids[0], ids[1]);
        assert!(ids.contains(&fingerprints(&before)[0]));
    }

    #[test]
    fn old_baselines_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");
        std::fs::write(&path, r#"{"version":1,"fingerprints":["abc"]}"#).unwrap();
        let err = load_baseline(&path).unwrap_err().to_string();
        assert!(err.contains("--update-baseline"), "{}", err);
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
}
