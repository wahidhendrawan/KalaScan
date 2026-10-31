use crate::attack::{self, AttackTechnique};
use crate::deobfuscate::DeobfuscationReport;
use crate::emulate::EmulationReport;
use crate::sandbox::SandboxReport;
use crate::triage::TriageReport;
use crate::RuleMatch;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const ENGINE: &str = concat!("kalascan-ttp/", env!("CARGO_PKG_VERSION"));

const TACTIC_ORDER: &[&str] = &[
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TtpReport {
    pub engine: String,
    pub techniques: Vec<TtpTechnique>,
    pub tactics: Vec<TacticSummary>,
    pub coverage_score: u8,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtpTechnique {
    pub id: String,
    pub name: String,
    pub tactic: String,
    pub sources: Vec<String>,
    pub observations: usize,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TacticSummary {
    pub tactic: String,
    pub techniques: Vec<String>,
    pub observations: usize,
}

pub fn build(
    rule_matches: &[RuleMatch],
    triage: Option<&TriageReport>,
    deobfuscation: Option<&DeobfuscationReport>,
    emulation: Option<&EmulationReport>,
    sandbox: Option<&SandboxReport>,
) -> TtpReport {
    let mut report = TtpReport {
        engine: ENGINE.to_string(),
        ..Default::default()
    };
    let mut techniques: BTreeMap<String, TtpTechnique> = BTreeMap::new();

    for rule_match in rule_matches {
        // Map the rule name only. The context is surrounding source code, and
        // words in it ("service", "schedule", "registry") turned every bundle
        // into Windows Service / Scheduled Task / Run Keys. Low findings are
        // hygiene hints, not observed behaviour.
        if rule_match.severity == "low" {
            continue;
        }
        let source = format!("rule:{}", rule_match.matched_pattern);
        for technique in attack::map_text(&rule_match.matched_pattern) {
            record(&mut techniques, technique, &source, &rule_match.severity);
        }
    }

    // Binary capabilities only. `triage.attack_techniques` is derived from
    // these, and `source == "rule"` capabilities are the rule matches above:
    // recording them again listed one match as three observations.
    if let Some(triage) = triage {
        for capability in triage.capabilities.iter().filter(|c| c.source != "rule") {
            let source = format!("capability:{}", capability.name);
            for technique in &capability.attack {
                record(
                    &mut techniques,
                    technique.clone(),
                    &source,
                    &capability.severity,
                );
            }
        }
    }

    if let Some(deobfuscation) = deobfuscation {
        let severity = if deobfuscation
            .artifacts
            .iter()
            .any(|artifact| artifact.confidence == "high")
        {
            "high"
        } else {
            "medium"
        };
        for technique in &deobfuscation.attack_techniques {
            record(
                &mut techniques,
                technique.clone(),
                "deobfuscation",
                severity,
            );
        }
    }

    if let Some(emulation) = emulation {
        let severity = if emulation
            .traces
            .iter()
            .any(|trace| !trace.api_calls.is_empty() || !trace.indicators.is_empty())
        {
            "high"
        } else {
            "medium"
        };
        for technique in &emulation.attack_techniques {
            record(&mut techniques, technique.clone(), "emulation", severity);
        }
    }

    if let Some(sandbox) = sandbox {
        for execution in &sandbox.executions {
            let severity = if !execution.network_attempts.is_empty()
                || execution.indicators.iter().any(|indicator| {
                    indicator.contains("credential")
                        || indicator.contains("persistence")
                        || indicator.contains("network")
                }) {
                "high"
            } else {
                "medium"
            };
            for technique in &execution.attack {
                record(&mut techniques, technique.clone(), "sandbox", severity);
            }
        }
    }

    report.techniques = techniques.into_values().collect();
    report.techniques.sort_by(|left, right| {
        tactic_rank(&left.tactic)
            .cmp(&tactic_rank(&right.tactic))
            .then(left.id.cmp(&right.id))
    });

    let mut tactics: BTreeMap<String, TacticSummary> = BTreeMap::new();
    for technique in &report.techniques {
        let entry = tactics
            .entry(technique.tactic.clone())
            .or_insert_with(|| TacticSummary {
                tactic: technique.tactic.clone(),
                techniques: Vec::new(),
                observations: 0,
            });
        if !entry.techniques.contains(&technique.id) {
            entry.techniques.push(technique.id.clone());
        }
        entry.observations += technique.observations;
    }
    report.tactics = tactics.into_values().collect();
    report.tactics.sort_by_key(|left| tactic_rank(&left.tactic));

    report.coverage_score = if report.tactics.is_empty() {
        0
    } else {
        ((report.tactics.len() * 100) / TACTIC_ORDER.len()) as u8
    };

    if report.techniques.is_empty() {
        report
            .notes
            .push("No ATT&CK techniques were observed.".to_string());
    } else {
        report.notes.push(format!(
            "{} techniques across {} tactics observed.",
            report.techniques.len(),
            report.tactics.len()
        ));
    }

    report
}

fn record(
    techniques: &mut BTreeMap<String, TtpTechnique>,
    technique: AttackTechnique,
    source: &str,
    severity: &str,
) {
    let entry = techniques
        .entry(technique.id.clone())
        .or_insert_with(|| TtpTechnique {
            id: technique.id.clone(),
            name: technique.name.clone(),
            tactic: technique.tactic.clone(),
            sources: Vec::new(),
            observations: 0,
            severity: "low".to_string(),
        });
    if !entry.sources.iter().any(|existing| existing == source) {
        entry.sources.push(source.to_string());
    }
    entry.observations += 1;
    if severity_rank(severity) > severity_rank(&entry.severity) {
        entry.severity = severity.to_string();
    }
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn tactic_rank(tactic: &str) -> usize {
    TACTIC_ORDER
        .iter()
        .position(|candidate| *candidate == tactic)
        .unwrap_or(TACTIC_ORDER.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attack::AttackTechnique;

    fn technique(id: &str, name: &str, tactic: &str) -> AttackTechnique {
        AttackTechnique {
            id: id.to_string(),
            name: name.to_string(),
            tactic: tactic.to_string(),
        }
    }

    #[test]
    fn empty_report_has_no_coverage() {
        let report = build(&[], None, None, None, None);
        assert!(report.techniques.is_empty());
        assert!(report.tactics.is_empty());
        assert_eq!(report.coverage_score, 0);
    }

    #[test]
    fn aggregates_and_deduplicates_techniques() {
        let rule_matches = vec![RuleMatch {
            file_path: "app.py".into(),
            line_number: 1,
            matched_pattern: "PowerShell Encoded Command".into(),
            severity: "high".into(),
            context: "powershell -EncodedCommand ...".into(),
        }];
        let capability = |source: &str| crate::triage::CapabilityFinding {
            name: "PowerShell launcher".into(),
            namespace: "capa".into(),
            description: String::new(),
            severity: "medium".into(),
            source: source.into(),
            file_path: "dropper.exe".into(),
            attack: vec![technique("T1059.001", "PowerShell", "Execution")],
        };
        let triage = TriageReport {
            // Derived from the capabilities: must not count on its own.
            attack_techniques: vec![technique("T1059.001", "PowerShell", "Execution")],
            // The rule match above, mirrored by triage: must not count again.
            capabilities: vec![capability("capa"), capability("rule")],
            ..Default::default()
        };
        let report = build(&rule_matches, Some(&triage), None, None, None);
        let powershell = report
            .techniques
            .iter()
            .find(|item| item.id == "T1059.001")
            .unwrap();
        assert_eq!(powershell.observations, 2);
        assert_eq!(powershell.sources.len(), 2);
        assert_eq!(powershell.severity, "high");
    }

    #[test]
    fn surrounding_code_does_not_invent_techniques() {
        // Real noise: a Vue bundle line mentioning services and schedulers.
        let rule_matches = vec![RuleMatch {
            file_path: "dist/app.js".into(),
            line_number: 1,
            matched_pattern: "Dynamic Import/Load".into(),
            severity: "medium".into(),
            context: "registerService(scheduler, registry.startup, persistence)".into(),
        }];
        let report = build(&rule_matches, None, None, None, None);
        for id in ["T1543", "T1543.003", "T1053.005", "T1547.001"] {
            assert!(
                !report.techniques.iter().any(|t| t.id == id),
                "{} from context",
                id
            );
        }
    }

    #[test]
    fn orders_tactics_by_kill_chain() {
        let triage = TriageReport {
            capabilities: vec![crate::triage::CapabilityFinding {
                name: "encrypt files and run shell".into(),
                namespace: "capa".into(),
                description: String::new(),
                severity: "high".into(),
                source: "capa".into(),
                file_path: "x.exe".into(),
                attack: vec![
                    technique("T1486", "Data Encrypted for Impact", "Impact"),
                    technique("T1059", "Command and Scripting Interpreter", "Execution"),
                ],
            }],
            ..Default::default()
        };
        let report = build(&[], Some(&triage), None, None, None);
        assert_eq!(report.tactics[0].tactic, "Execution");
        assert_eq!(report.tactics[1].tactic, "Impact");
    }
}
