//! Risk score: how the findings of one scan become a number from 0 to 100.

use crate::{
    agent, correlate, cve, deobfuscate, emulate, git_history, iocs, registry, reputation, sandbox,
    scanner, triage, AiAnalysis, RuleMatch,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScorePart {
    pub name: String,
    pub points: u8,
}

/// What the score is made of, so a reader can see why a scan got its number.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    pub model: String,
    pub parts: Vec<ScorePart>,
    /// v2: dependencies with a known vulnerability. Hygiene, counted here
    /// and kept out of the score, which is about malice.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub known_vulnerabilities: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

impl ScoreBreakdown {
    fn new<const N: usize>(model: &str, parts: [(&str, u16); N]) -> Self {
        Self {
            model: model.to_string(),
            parts: parts
                .into_iter()
                .filter(|(_, points)| *points > 0)
                .map(|(name, points)| ScorePart {
                    name: name.to_string(),
                    points: points.min(100) as u8,
                })
                .collect(),
            known_vulnerabilities: 0,
        }
    }

    /// The risk score: the parts added up, capped at 100.
    pub fn total(&self) -> u8 {
        self.parts
            .iter()
            .map(|p| p.points as u16)
            .sum::<u16>()
            .min(100) as u8
    }
}

/// `model`: `Some("v2")` for the fitted weights (`--score-model v2`),
/// anything else for v1.
pub fn calculate(
    model: Option<&str>,
    matches: &[RuleMatch],
    ai: &Option<AiAnalysis>,
    triage: Option<&triage::TriageReport>,
    deobfuscation: Option<&deobfuscate::DeobfuscationReport>,
    emulation: Option<&emulate::EmulationReport>,
    sandbox: Option<&sandbox::SandboxReport>,
) -> ScoreBreakdown {
    // The deep passes overlap heavily. One shared budget keeps them from
    // stacking five separate ceilings on the same evidence.
    let dynamic = (triage.map_or(0, |r| triage::risk_contribution(r) as u16)
        + deobfuscation.map_or(0, |r| deobfuscate::risk_contribution(r) as u16)
        + emulation.map_or(0, |r| emulate::risk_contribution(r) as u16)
        + sandbox.map_or(0, |r| sandbox::risk_contribution(r) as u16))
    .min(20);
    // AI corroborates the static result; a benign verdict never raises it.
    let ai = ai.as_ref().map_or(0, |a| {
        if a.is_malicious {
            (a.risk_score as u16 / 2).min(25)
        } else {
            0
        }
    });
    if model == Some("v2") {
        v2(matches, dynamic, ai)
    } else {
        v1(matches, dynamic, ai)
    }
}

/// A chain is two corroborating hard signals by construction. Listing
/// spoofs (invisible characters, look-alike publisher, a popular
/// extension's repository under a stranger's name), an install script
/// hidden from the registry's manifest, text hidden in Unicode tags and
/// code decoded straight into exec (none of 526 clean packages) have no
/// benign reading at all, so they weigh the same.
fn decisive(name: &str) -> bool {
    name.starts_with(correlate::CHAIN_PREFIX)
        || [
            reputation::INVISIBLE_NAME,
            reputation::PUBLISHER_LOOKALIKE,
            reputation::REPACKAGED_COPY,
            reputation::AI_VENDOR_REPO,
            registry::MANIFEST_CONFUSION,
            iocs::URLHAUS_HIT,
            agent::TAG_TEXT,
            scanner::B64_EXEC,
            scanner::IMPORT_LOADER,
            cve::REMOTE_URL_DEP,
        ]
        .contains(&name)
}

const KNOWN_VULNERABILITY: &str = "Known Vulnerability";

/// v1: tiers with caps, weights set by hand.
fn v1(matches: &[RuleMatch], dynamic_score: u16, ai_score: u16) -> ScoreBreakdown {
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
        if m.matched_pattern.starts_with(KNOWN_VULNERABILITY) {
            cve += 1;
            continue;
        }
        if decisive(&m.matched_pattern) {
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

    // Vulnerable dependencies are a hygiene issue, not malware evidence.
    let cve_score = cve.min(5);

    ScoreBreakdown::new(
        "v1",
        [
            ("critical findings", critical_score),
            ("high findings", (high * 5).min(15)),
            ("medium findings", medium.min(5)),
            ("known vulnerabilities", cve_score),
            ("deep analysis", dynamic_score),
            ("AI verdict", ai_score),
        ],
    )
}

/// `rules/weights.toml`: a weight per finding, fitted by eval/fit_weights.py.
#[derive(Deserialize)]
struct Weights {
    default: std::collections::HashMap<String, u8>,
    #[serde(default)]
    finding: Vec<FindingWeight>,
}

#[derive(Deserialize)]
struct FindingWeight {
    name: String,
    weight: u8,
}

static WEIGHTS: std::sync::LazyLock<(
    std::collections::HashMap<String, u8>,
    std::collections::HashMap<String, u8>,
)> = std::sync::LazyLock::new(|| {
    let w: Weights =
        toml::from_str(include_str!("../rules/weights.toml")).expect("rules/weights.toml is valid");
    let findings = w.finding.into_iter().map(|f| (f.name, f.weight)).collect();
    (w.default, findings)
});

/// Finding names that carry a value: the weight is for the name alone.
const VALUED: &[&str] = &[
    KNOWN_VULNERABILITY,
    "Malicious Package",
    "Typo-squat Suspect",
    "High-Entropy Suspicious Blob",
];

fn key(name: &str) -> &str {
    VALUED
        .iter()
        .copied()
        .find(|v| name.starts_with(v))
        .unwrap_or(name)
}

/// Below "danger" (70) unless one finding alone is this strong: several
/// leads are not a verdict (THOR requires the same of an alert).
const HARD_SIGNAL: u8 = 75;

/// v2: every finding present in the package has a weight, the probability
/// in percent that a package showing it is malicious, fitted on the eval
/// corpus (rules/weights.toml). Weights combine largest first, each later
/// one counting half as much as the one before:
///
///   score = 100 * (1 - prod_i (1 - w_i / 100 / 2^i))
///
/// so the strongest evidence sets the score and the rest corroborates.
/// Known vulnerabilities are counted apart, not scored.
fn v2(matches: &[RuleMatch], dynamic_score: u16, ai_score: u16) -> ScoreBreakdown {
    let (defaults, findings) = &*WEIGHTS;
    let mut subs: Vec<(&str, u8)> = Vec::new();
    let mut vulnerable = std::collections::HashSet::new();
    for m in matches {
        let name = key(&m.matched_pattern);
        if name == KNOWN_VULNERABILITY {
            vulnerable.insert(m.matched_pattern.as_str());
            continue;
        }
        if subs.iter().any(|(seen, _)| *seen == name) {
            continue;
        }
        let class = if decisive(name) {
            "chain"
        } else {
            m.severity.as_str()
        };
        let weight = findings
            .get(name)
            .or_else(|| defaults.get(class))
            .copied()
            .unwrap_or(0);
        subs.push((name, weight));
    }
    // The passes the corpus was not scanned with keep their v1 budgets,
    // doubled onto the 0-100 scale: neither reaches "danger" by itself.
    subs.push(("deep analysis", (dynamic_score * 2).min(100) as u8));
    subs.push(("AI verdict", (ai_score * 2).min(100) as u8));
    subs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));

    let cap = if subs.first().is_some_and(|(_, w)| *w >= HARD_SIGNAL) {
        100.0
    } else {
        69.0
    };
    let mut rest = 1.0f64;
    let mut so_far = 0u8;
    let mut parts = Vec::new();
    for (i, (name, weight)) in subs.iter().enumerate() {
        rest *= 1.0 - f64::from(*weight) / 100.0 / 2f64.powi(i as i32);
        let total = (100.0 * (1.0 - rest)).min(cap).round() as u8;
        if total > so_far {
            parts.push(ScorePart {
                name: (*name).to_string(),
                points: total - so_far,
            });
            so_far = total;
        }
    }
    ScoreBreakdown {
        model: "v2".to_string(),
        parts,
        known_vulnerabilities: vulnerable.len(),
    }
}

#[cfg(test)]
mod tests {
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

        let score = calculate(None, &matches, &benign_ai(), None, None, None, None).total();
        assert!(score < 70, "benign extension scored {}", score);
    }

    #[test]
    fn single_hit_per_rule_per_file() {
        let many: Vec<_> = (0..50)
            .map(|_| hit("a.js", "Environment Variable Dump", "medium"))
            .collect();
        let one = vec![hit("a.js", "Environment Variable Dump", "medium")];
        assert_eq!(
            calculate(None, &many, &None, None, None, None, None).total(),
            calculate(None, &one, &None, None, None, None, None).total()
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
        let score = calculate(None, &matches, &benign_ai(), None, None, None, None).total();
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
            calculate(None, &vuln, &None, None, None, None, None).total(),
            1
        );
        assert_eq!(
            calculate(None, &mal, &None, None, None, None, None).total(),
            20
        );
    }

    #[test]
    fn listing_spoof_alone_is_high_risk() {
        let m = vec![hit("package.json", reputation::INVISIBLE_NAME, "critical")];
        assert_eq!(
            calculate(None, &m, &None, None, None, None, None).total(),
            70
        );
    }

    #[test]
    fn one_unchained_critical_is_a_lead_not_a_verdict() {
        let one = vec![hit("db.js", "Shadow Copy Deletion", "critical")];
        assert_eq!(
            calculate(None, &one, &None, None, None, None, None).total(),
            20
        );
        let two = vec![
            hit("db.js", "Shadow Copy Deletion", "critical"),
            hit("enc.js", "Discord Webhook", "critical"),
        ];
        assert_eq!(
            calculate(None, &two, &None, None, None, None, None).total(),
            70
        );
        let chained = vec![hit("enc.js", correlate::RANSOMWARE, "critical")];
        assert_eq!(
            calculate(None, &chained, &None, None, None, None, None).total(),
            70
        );
    }

    fn v2(matches: &[RuleMatch]) -> ScoreBreakdown {
        calculate(Some("v2"), matches, &None, None, None, None, None)
    }

    #[test]
    fn v2_parts_add_up_and_more_evidence_never_lowers_the_score() {
        assert_eq!(v2(&[]).total(), 0);
        let mut matches = Vec::new();
        let mut last = 0;
        for (rule, severity) in [
            ("Environment Variable Dump", "medium"),
            ("exec() Usage", "high"),
            ("Discord Webhook", "critical"),
            (correlate::CREDENTIAL_EXFIL, "critical"),
            ("A Rule Nobody Fitted", "high"),
        ] {
            matches.push(hit("a.js", rule, severity));
            let score = v2(&matches);
            let sum: u16 = score.parts.iter().map(|p| p.points as u16).sum();
            assert_eq!(sum, score.total() as u16, "parts of {:?}", score.parts);
            assert!(score.total() >= last, "{rule} lowered the score");
            last = score.total();
        }
        // The same finding in forty files is one piece of evidence.
        let one = v2(&[hit("a.js", "exec() Usage", "high")]).total();
        let many: Vec<_> = (0..40)
            .map(|i| hit(&format!("{i}.js"), "exec() Usage", "high"))
            .collect();
        assert_eq!(v2(&many).total(), one);
    }

    #[test]
    fn v2_needs_one_strong_finding_for_a_verdict() {
        // Every weak signal a large legitimate extension shows, and nothing strong.
        let weak: Vec<_> = (0..30)
            .map(|i| hit("out/main.js", &format!("Soft Signal {i}"), "medium"))
            .collect();
        let score = v2(&weak).total();
        assert!(score < 70, "leads alone scored {score}");
    }

    #[test]
    fn v2_counts_known_vulnerabilities_apart() {
        let vulns = [
            hit(
                "package.json",
                "Known Vulnerability: GHSA-1 in lodash@4.17.15",
                "high",
            ),
            hit(
                "package.json",
                "Known Vulnerability: GHSA-2 in minimist@0.0.8",
                "high",
            ),
        ];
        let score = v2(&vulns);
        assert_eq!(score.total(), 0);
        assert_eq!(score.known_vulnerabilities, 2);
    }

    #[test]
    fn benign_ai_never_raises_score() {
        let base = vec![hit("a.js", "exec() Usage", "high")];
        let without = calculate(None, &base, &None, None, None, None, None).total();
        let with = calculate(None, &base, &benign_ai(), None, None, None, None).total();
        assert_eq!(without, with);
    }
}
