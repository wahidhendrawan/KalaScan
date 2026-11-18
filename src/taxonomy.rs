//! Where findings sit in published taxonomies, next to their ATT&CK
//! techniques (`attack.rs`):
//!
//! - the MBC v3.1 objective (Malware Behavior Catalog), which follows the
//!   technique's tactic;
//! - the attack vector of Ladisa et al., "SoK: Taxonomy of Attacks on
//!   Open-Source Software Supply Chains" (IEEE S&P 2023), ids as in
//!   SAP/risk-explorer-for-software-supply-chains. Only findings that are
//!   evidence of *how* malicious code reached a package have one: most
//!   findings describe what the code does, whichever way it got there.
//!
//! `kalascan rules --coverage` prints the tables (docs/coverage.md).

use crate::attack::{self, AttackTechnique};
use crate::{
    agent, correlate, cve, iocs, obfuscator, registry, reputation, sandbox, scanner, workflow,
};

/// MBC objective a technique serves, `(id, name)`.
pub fn mbc_objective(technique: &AttackTechnique) -> Option<(&'static str, &'static str)> {
    // MBC keeps two objectives ATT&CK has no tactic for.
    if technique.id.starts_with("T1027") || technique.id == "T1140" {
        return Some(("OB0002", "Anti-Static Analysis"));
    }
    if technique.id.starts_with("T1497") {
        return Some(("OB0001", "Anti-Behavioral Analysis"));
    }
    Some(match technique.tactic.as_str() {
        "Collection" => ("OB0003", "Collection"),
        "Command and Control" => ("OB0004", "Command and Control"),
        "Credential Access" => ("OB0005", "Credential Access"),
        // ATT&CK v20 split Defense Evasion in two; MBC still has the one.
        "Stealth" | "Defense Impairment" => ("OB0006", "Defense Evasion"),
        "Discovery" => ("OB0007", "Discovery"),
        "Impact" => ("OB0008", "Impact"),
        "Execution" => ("OB0009", "Execution"),
        "Exfiltration" => ("OB0010", "Exfiltration"),
        "Lateral Movement" => ("OB0011", "Lateral Movement"),
        "Persistence" => ("OB0012", "Persistence"),
        "Privilege Escalation" => ("OB0013", "Privilege Escalation"),
        _ => return None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// A check looks for the vector itself.
    Direct,
    /// A check sees a side effect of the vector, or one form of it.
    Partial,
    /// Visible in a package or its listing, and nothing checks it yet.
    Gap,
    /// A published package does not show how the code got in: only what the
    /// injected code does can be seen (behaviour rules, chains, `diff`).
    Payload,
    /// Happens where a package scan does not look: a network path, a build
    /// host, a person.
    Outside,
}

impl Coverage {
    fn label(self) -> &'static str {
        match self {
            Coverage::Direct => "direct",
            Coverage::Partial => "partial",
            Coverage::Gap => "gap",
            Coverage::Payload => "payload only",
            Coverage::Outside => "out of scope",
        }
    }
}

pub struct Vector {
    pub id: &'static str,
    pub name: &'static str,
    pub coverage: Coverage,
    /// Finding names (or their prefix, for names that carry a value).
    pub evidence: &'static [&'static str],
    pub note: &'static str,
}

const TYPOSQUAT: &str = "Typo-squat Suspect";
const BIDI: &str = "Trojan Source Bi-Directional Character (CVE-2021-42574)";
const HOMOGLYPH: &str = "Confusable Homoglyph Character (Supply Chain Spoofing)";
const ENTROPY_BLOB: &str = "High-Entropy Suspicious Blob";
const MALICIOUS_PACKAGE: &str = "Malicious Package";

use Coverage::{Direct, Gap, Outside, Partial, Payload};

#[rustfmt::skip]
pub const VECTORS: &[Vector] = &[
    Vector { id: "AV-100", name: "Develop and Advertise Distinct Malicious Package from Scratch", coverage: Partial,
        evidence: &[correlate::NPM_SPAM, correlate::WEB_PAGE_PACKAGE, reputation::UNVERIFIED_PUBLISHER, reputation::LOW_INSTALLS, reputation::RECENTLY_PUBLISHED],
        note: "The package is the payload: it is judged by what its code does. Listing age and reach are hints, for IDE extensions only." },
    Vector { id: "AV-200", name: "Create Name Confusion with Legitimate Package", coverage: Partial,
        evidence: &[TYPOSQUAT, reputation::BRAND_IMPERSONATION], note: "See the forms below." },
    Vector { id: "AV-201", name: "Combosquatting", coverage: Gap, evidence: &[],
        note: "A popular name plus a word (`lodash-utils`) is not compared." },
    Vector { id: "AV-202", name: "Altering Word Order", coverage: Gap, evidence: &[], note: "" },
    Vector { id: "AV-203", name: "Manipulating Word Separators", coverage: Partial, evidence: &[TYPOSQUAT],
        note: "One separator added, dropped or changed is one edit." },
    Vector { id: "AV-204", name: "Typosquatting", coverage: Direct, evidence: &[TYPOSQUAT],
        note: "One edit or one swap away from a most-downloaded npm / PyPI name; the package's own name and its dependencies." },
    Vector { id: "AV-205", name: "Built-In Package", coverage: Gap, evidence: &[],
        note: "Standard-library names are not in the comparison list." },
    Vector { id: "AV-206", name: "Brandjacking", coverage: Partial,
        evidence: &[reputation::BRAND_IMPERSONATION, reputation::REPACKAGED_COPY, reputation::AI_VENDOR_REPO],
        note: "IDE extensions only." },
    Vector { id: "AV-207", name: "Similarity Attack", coverage: Partial,
        evidence: &[reputation::PUBLISHER_LOOKALIKE, reputation::INVISIBLE_NAME], note: "IDE extensions only." },
    Vector { id: "AV-208", name: "Namespace Omission or Change", coverage: Gap, evidence: &[], note: "" },
    Vector { id: "AV-209", name: "AI Package Hallucination", coverage: Gap, evidence: &[], note: "" },
    Vector { id: "AV-300", name: "Inject into Sources of Legitimate Package", coverage: Payload, evidence: &[], note: "" },
    Vector { id: "AV-301", name: "Introduce Malicious Code through Hypocrite Merge Request", coverage: Payload, evidence: &[],
        note: "`--changed-only` scans what a pull request changes." },
    Vector { id: "AV-304", name: "Make Immature Vulnerability Exploitable", coverage: Outside, evidence: &[],
        note: "The change is a bug, not malicious-looking code." },
    Vector { id: "AV-305", name: "Exploit Rendering Weakness", coverage: Direct, evidence: &[BIDI, HOMOGLYPH], note: "" },
    Vector { id: "AV-306", name: "Exploit Unicode Bidirectional Algorithm", coverage: Direct, evidence: &[BIDI], note: "" },
    Vector { id: "AV-307", name: "Use Homoglyphs", coverage: Direct, evidence: &[HOMOGLYPH, reputation::PUBLISHER_LOOKALIKE], note: "" },
    Vector { id: "AV-308", name: "Prevent Display of File Differences", coverage: Payload, evidence: &[],
        note: "Files are read whole, whatever a diff view shows." },
    Vector { id: "AV-309", name: "Hide in Generated/Compiled/Minified Code", coverage: Partial,
        evidence: &[scanner::OBFUSCATOR_IO, ENTROPY_BLOB, correlate::OBFUSCATED_EXEC, obfuscator::OBFUSCATED_DOWNLOAD_EXEC],
        note: "Bundles and obfuscated scripts are scanned; compiled binaries get metadata triage on every scan and capa / FLOSS only with `--deep-triage`." },
    Vector { id: "AV-302", name: "Contribute as Maintainer", coverage: Payload, evidence: &[], note: "" },
    Vector { id: "AV-303", name: "Tamper with Version Control System", coverage: Payload, evidence: &[],
        note: "`--git-history` scans earlier commits." },
    Vector { id: "AV-400", name: "Inject During the Build of Legitimate Package", coverage: Partial,
        evidence: &[workflow::PWN_REQUEST, workflow::SCRIPT_INJECTION], note: "GitHub Actions workflows only." },
    Vector { id: "AV-401", name: "Run Malicious Build", coverage: Partial,
        evidence: &[workflow::PWN_REQUEST, workflow::SCRIPT_INJECTION], note: "" },
    Vector { id: "AV-402", name: "Tamper Build Job as Maintainer", coverage: Outside, evidence: &[], note: "" },
    Vector { id: "AV-403", name: "Tamper with Exposed Build System", coverage: Partial,
        evidence: &[workflow::UNPINNED_ACTION, workflow::SPOOFABLE_BOT_CHECK], note: "" },
    Vector { id: "AV-500", name: "Distribute Malicious Version of Legitimate Package", coverage: Partial,
        evidence: &[registry::INSTALL_SCRIPT_ADDED, registry::NEW_DEPENDENCIES, registry::PROVENANCE_DROPPED],
        note: "What changed against the previous version (npm, PyPI); `kalascan diff` lists new capabilities." },
    Vector { id: "AV-501", name: "Dangling Reference", coverage: Partial, evidence: &[cve::REMOTE_URL_DEP],
        note: "A dependency fetched from a URL instead of the registry." },
    Vector { id: "AV-502", name: "Mask Legitimate Package", coverage: Partial,
        evidence: &[correlate::DEP_CONFUSION_VERSION, correlate::DEP_CONFUSION_HOOK], note: "" },
    Vector { id: "AV-506", name: "MITM Attack", coverage: Outside, evidence: &[], note: "" },
    Vector { id: "AV-507", name: "DNS Cache Poisoning", coverage: Outside, evidence: &[], note: "" },
    Vector { id: "AV-508", name: "Tamper Legitimate URL", coverage: Outside, evidence: &[], note: "" },
    Vector { id: "AV-509", name: "Abuse Dependency Resolution Mechanism", coverage: Partial,
        evidence: &[correlate::DEP_CONFUSION_VERSION, correlate::DEP_CONFUSION_HOOK],
        note: "The version-number form of dependency confusion (99.x), from package.json, PKG-INFO or a wheel's METADATA." },
    Vector { id: "AV-503", name: "Prevent Update to Non-Vulnerable Version", coverage: Outside, evidence: &[], note: "" },
    Vector { id: "AV-504", name: "Distribute as Package Maintainer", coverage: Partial,
        evidence: &[registry::PROVENANCE_DROPPED, registry::INSTALL_SCRIPT_ADDED, registry::NEW_DEPENDENCIES], note: "" },
    Vector { id: "AV-505", name: "Inject into Hosting System", coverage: Outside, evidence: &[], note: "" },
    Vector { id: "AV-600", name: "Compromise User (Project Maintainer/Administrator)", coverage: Outside, evidence: &[], note: "" },
    Vector { id: "AV-601", name: "Bribe or Blackmail Legitimate User", coverage: Outside, evidence: &[], note: "" },
    Vector { id: "AV-602", name: "Take-over Legitimate Account", coverage: Partial,
        evidence: &[registry::PROVENANCE_DROPPED, registry::INSTALL_SCRIPT_ADDED],
        note: "A release that drops provenance or gains an install script is what a taken-over account publishes." },
    Vector { id: "AV-603", name: "Reuse of Compromised Credentials", coverage: Outside, evidence: &[], note: "" },
    Vector { id: "AV-604", name: "Bruteforce", coverage: Outside, evidence: &[], note: "" },
    Vector { id: "AV-605", name: "Reuse of Leaked API Tokens", coverage: Partial, evidence: &[],
        note: "Preventive: `--secrets` finds tokens committed to your own repository." },
    Vector { id: "AV-606", name: "Social Engineering to Obtain Credentials", coverage: Outside, evidence: &[], note: "" },
    Vector { id: "AV-607", name: "Reuse of Existing Session", coverage: Outside, evidence: &[], note: "" },
    Vector { id: "AV-608", name: "Resurrect Expired Domain Associated With Legitimate Account", coverage: Direct,
        evidence: &[registry::EMAIL_DOMAIN_UNREGISTERED], note: "npm maintainers." },
    Vector { id: "AV-700", name: "Compromise System (Maintainer, Version Control, Build, Hosting)", coverage: Outside, evidence: &[], note: "" },
    Vector { id: "AV-701", name: "Exploit Weak Configuration", coverage: Partial,
        evidence: &[workflow::PWN_REQUEST, workflow::SCRIPT_INJECTION, workflow::UNPINNED_ACTION, workflow::SPOOFABLE_BOT_CHECK],
        note: "GitHub Actions workflows only." },
    Vector { id: "AV-702", name: "Exploit Vulnerabilities", coverage: Outside, evidence: &[], note: "" },
    Vector { id: "AV-703", name: "Infect through Malicious Component", coverage: Direct, evidence: &[MALICIOUS_PACKAGE],
        note: "What `guard`, `deps` and `installed` are for: scan a component before it runs on the maintainer's machine." },
    Vector { id: "AV-800", name: "Become a Maintainer", coverage: Outside, evidence: &[], note: "" },
    Vector { id: "AV-801", name: "Change Ethos", coverage: Payload, evidence: &[], note: "Protestware is the maintainer's own code." },
];

/// Vectors a finding is evidence of.
pub fn vectors_for(finding: &str) -> Vec<&'static str> {
    VECTORS
        .iter()
        .filter(|v| v.evidence.iter().any(|e| finding.starts_with(e)))
        .map(|v| v.id)
        .collect()
}

/// Findings raised by code rather than by a rule in `rules/builtin.toml`.
#[rustfmt::skip]
pub const CODE_FINDINGS: &[&str] = &[
    agent::TAG_TEXT, agent::INVISIBLE, agent::COMMENT_DIRECTIVE, agent::CONCEAL, agent::OVERRIDE,
    agent::SECRET_PATH, agent::MALICIOUS_INSTRUCTION, agent::CONFIG_REMOTE_CODE,
    correlate::ZIP_SLIP, correlate::CREDENTIAL_EXFIL, correlate::DOWNLOAD_EXECUTE, correlate::REMOTE_FILE_WRITE,
    correlate::REVERSE_SHELL, correlate::DROP_EXECUTE, correlate::INSTALL_EXFIL, correlate::RECON_BEACON,
    correlate::OBFUSCATED_EXEC, correlate::INSTALL_PAYLOAD, correlate::INSTALL_RECON_CHAIN, correlate::REMOTE_CODE,
    correlate::EXTENSION_SIDELOAD, correlate::SYSTEM_DISCOVERY, correlate::AI_TRAFFIC_HIJACK, correlate::NPM_SPAM,
    correlate::OBFUSCATED_RECON, correlate::RANSOMWARE, correlate::PHISHING_REDIRECT, correlate::DEP_CONFUSION_VERSION,
    correlate::DEP_CONFUSION_HOOK, correlate::WEB_PAGE_PACKAGE, cve::WEB_PAGE_ENTRY,
    cve::REMOTE_URL_DEP, iocs::URLHAUS_HIT,
    reputation::INVISIBLE_NAME, reputation::PUBLISHER_LOOKALIKE, reputation::BRAND_IMPERSONATION,
    reputation::UNVERIFIED_PUBLISHER, reputation::LOW_INSTALLS, reputation::RECENTLY_PUBLISHED,
    reputation::REPACKAGED_COPY, reputation::AI_VENDOR_REPO,
    obfuscator::OBFUSCATED_CREDENTIAL_THEFT, obfuscator::OBFUSCATED_DOWNLOAD_EXEC,
    registry::MANIFEST_CONFUSION, registry::INSTALL_SCRIPT_ADDED, registry::NEW_DEPENDENCIES,
    registry::PROVENANCE_DROPPED, registry::EMAIL_DOMAIN_UNREGISTERED,
    sandbox::INSTALL_CREDENTIAL_ACCESS,
    workflow::PWN_REQUEST, workflow::SCRIPT_INJECTION, workflow::UNPINNED_ACTION, workflow::SPOOFABLE_BOT_CHECK,
    TYPOSQUAT, BIDI, HOMOGLYPH, ENTROPY_BLOB, MALICIOUS_PACKAGE,
    "Invisible Zero-Width Character (Steganography/Obfuscation)",
];

fn cell(items: Vec<String>) -> String {
    if items.is_empty() {
        "-".to_string()
    } else {
        items.join(", ")
    }
}

fn finding_row(name: &str, kind: &str) -> String {
    let techniques = attack::for_finding(name);
    let mut objectives: Vec<String> = Vec::new();
    for t in &techniques {
        if let Some((id, label)) = mbc_objective(t) {
            let entry = format!("{} {}", id, label);
            if !objectives.contains(&entry) {
                objectives.push(entry);
            }
        }
    }
    format!(
        "| {} | {} | {} | {} | {} |\n",
        name.replace('|', "\\|"),
        kind,
        cell(techniques.iter().map(|t| t.id.clone()).collect()),
        cell(objectives),
        cell(vectors_for(name).into_iter().map(String::from).collect()),
    )
}

/// docs/coverage.md: the vectors KalaScan covers and where every finding sits.
pub fn coverage_markdown() -> String {
    let mut md = String::from(concat!(
        "# Detection coverage\n\n",
        "Generated by `kalascan rules --coverage`; do not edit by hand.\n\n",
        "## Supply-chain attack vectors\n\n",
        "The attack tree of Ladisa et al., *SoK: Taxonomy of Attacks on Open-Source Software Supply Chains* ",
        "(IEEE S&P 2023), ids as in [SAP/risk-explorer-for-software-supply-chains](https://github.com/SAP/risk-explorer-for-software-supply-chains).\n\n",
        "- **direct**: a check looks for the vector itself.\n",
        "- **partial**: a check sees a side effect of the vector, or one form of it.\n",
        "- **gap**: visible in a package or its listing, and nothing checks it yet.\n",
        "- **payload only**: a published package does not show how the code got in. ",
        "Only what the injected code does can be seen (behaviour rules, chains, `kalascan diff`).\n",
        "- **out of scope**: happens where a package scan does not look (a network path, a build host, a person).\n\n",
    ));
    let count = |c: Coverage| VECTORS.iter().filter(|v| v.coverage == c).count();
    md.push_str(&format!(
        "{} vectors: {} direct, {} partial, {} gap, {} payload only, {} out of scope.\n\n",
        VECTORS.len(),
        count(Direct),
        count(Partial),
        count(Gap),
        count(Payload),
        count(Outside)
    ));
    md.push_str("| Vector | Name | Coverage | Evidence | Note |\n|---|---|---|---|---|\n");
    for v in VECTORS {
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            v.id,
            v.name,
            v.coverage.label(),
            cell(v.evidence.iter().map(|e| e.to_string()).collect()),
            v.note
        ));
    }

    md.push_str(concat!(
        "\n## Findings\n\n",
        "ATT&CK technique ids follow Enterprise ATT&CK v20.1. The MBC objective (Malware Behavior Catalog v3.1) ",
        "follows the technique's tactic; obfuscation is Anti-Static Analysis. A vector is listed only when the ",
        "finding is evidence of how the code reached the package.\n\n",
        "| Finding | Source | ATT&CK | MBC objective | Vector |\n|---|---|---|---|---|\n",
    ));
    for rule in scanner::build_rules().iter() {
        md.push_str(&finding_row(&rule.name, &rule.id));
    }
    for name in CODE_FINDINGS {
        md.push_str(&finding_row(name, "code"));
    }
    md
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Notices about the scan itself: they describe no behaviour. Neither
    /// does a known-vulnerable dependency (`Known Vulnerability: …`).
    const DIAGNOSTICS: &[&str] = &[
        scanner::OVERSIZED_FINDING,
        scanner::SCAN_ERROR_FINDING,
        scanner::UNREADABLE_FINDING,
    ];

    #[test]
    fn every_finding_has_a_written_out_mapping() {
        let rules = scanner::build_rules();
        let names = rules
            .iter()
            .map(|r| r.name.as_str())
            .chain(CODE_FINDINGS.iter().copied());
        let unmapped: Vec<&str> = names.filter(|n| !attack::is_mapped(n)).collect();
        assert!(
            unmapped.is_empty(),
            "not in attack::FINDING_TABLE: {unmapped:?}"
        );
    }

    /// A finding constant added to a module must be listed here, or the
    /// coverage tables silently miss it.
    #[test]
    fn code_findings_list_is_complete() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let constant =
            regex::Regex::new(r#"pub(?:\(crate\))? const [A-Z0-9_]+: &str =\s*"([^"]+)";"#)
                .unwrap();
        let skip = [correlate::CHAIN_PREFIX, scanner::RULESET_VERSION];
        let rules = scanner::build_rules();
        for module in [
            "agent",
            "correlate",
            "cve",
            "iocs",
            "reputation",
            "obfuscator",
            "registry",
            "sandbox",
            "workflow",
            "scanner",
        ] {
            let text = std::fs::read_to_string(src.join(format!("{module}.rs"))).unwrap();
            for name in constant
                .captures_iter(&text)
                .map(|c| c.get(1).unwrap().as_str())
            {
                let known = CODE_FINDINGS.contains(&name)
                    || DIAGNOSTICS.contains(&name)
                    || skip.contains(&name)
                    || rules.iter().any(|r| r.name == name);
                assert!(
                    known,
                    "{module}.rs: `{name}` is not in taxonomy::CODE_FINDINGS"
                );
            }
        }
    }

    #[test]
    fn vector_ids_are_unique_and_evidence_is_known() {
        let rules = scanner::build_rules();
        for (i, v) in VECTORS.iter().enumerate() {
            assert!(!VECTORS[..i].iter().any(|w| w.id == v.id), "{} twice", v.id);
            for e in v.evidence {
                assert!(
                    CODE_FINDINGS.contains(e) || rules.iter().any(|r| r.name == *e),
                    "{}: unknown finding `{}`",
                    v.id,
                    e
                );
            }
        }
    }

    #[test]
    fn docs_coverage_is_up_to_date() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/coverage.md");
        let committed = std::fs::read_to_string(path).unwrap_or_default();
        assert!(
            committed == coverage_markdown(),
            "docs/coverage.md is stale: run `kalascan rules --coverage > docs/coverage.md`"
        );
    }
}
