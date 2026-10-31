//! Correlation of individual rule hits into behaviour chains.
//!
//! A single `fetch(` or `Login Data` string is weak evidence; a credential
//! source and an exfiltration sink in the same file is how stealers actually
//! look. Chain findings carry the `Chain: ` prefix and are weighted as two
//! critical hits by the risk score.

use crate::scanner::{ARCHIVE_EXTRACTION, LOCAL_SERVER, UPLOAD_HANDLER};
use crate::RuleMatch;
use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

pub const CHAIN_PREFIX: &str = "Chain: ";
pub const ZIP_SLIP: &str = "Zip Slip: Archive Extraction Without Path Validation";
pub const CREDENTIAL_EXFIL: &str = "Chain: Credential Exfiltration";
pub const DOWNLOAD_EXECUTE: &str = "Chain: Download and Execute";
pub const REMOTE_FILE_WRITE: &str = "Chain: Remote File Write via Local Server";

/// Reads that only a stealer needs: browser stores, wallets, tokens, keys.
const STRONG_SOURCES: &[&str] = &[
    "Browser Profile Access",
    "Crypto Wallet Access",
    "Browser Database Access",
    "Discord Token Harvesting",
    "SSH Key Access",
    "VS Code Session/Token Stealing",
    "Browser Extension Cookie/Token Theft",
];

/// Reads with common legitimate uses (dotenv, clipboard helpers, hotkeys).
const WEAK_SOURCES: &[&str] = &[
    "Password Manager Access",
    "VS Code Clipboard Harvesting",
    "Browser Extension Keystroke Logger",
];

/// Channels that exist mainly to receive stolen data.
const HARD_SINKS: &[&str] = &[
    "Discord Webhook",
    "Telegram Bot API Token",
    "Slack Webhook",
    "Generic Webhook URL",
    "YARA Rule: DiscordWebhookStealer",
];

/// Generic network calls; only damning next to a strong source.
const SOFT_SINKS: &[&str] = &["URL Fetch Command", "JetBrains Raw Socket Exfiltration"];

const EXECUTORS: &[&str] = &[
    "child_process (Node.js)",
    "subprocess (Python)",
    "os.system",
    "os.popen",
    "exec() Usage",
    "eval() Usage",
    "PowerShell Encoded Command",
    "JetBrains Process Execution",
];

static ARCHIVE_WRITE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:writeFile|createWriteStream|\.extractall\s*\(|\.extractAllTo\s*\(|\.extract\s*\(|open\s*\([^)]*['\x22]wb)").unwrap()
});

/// Any of these anywhere in the file means the author thought about `../`.
/// shortcut: file-wide, not data-flow; a guard on an unrelated path hides a real slip.
static TRAVERSAL_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:['"`]\.\.['"`/\\]|\.\.\/|\.\.\\\\|startsWith\s*\(|startswith\s*\(|isAbsolute|path\.relative\s*\(|commonpath|is_relative_to|filter\s*=\s*['"]data['"])"#).unwrap()
});

/// Chains visible inside one file. `file_matches` are this file's hits.
pub fn correlate_file(rel_path: &str, content: &str, file_matches: &[RuleMatch]) -> Vec<RuleMatch> {
    let has = |names: &[&str]| {
        file_matches
            .iter()
            .find(|m| names.contains(&m.matched_pattern.as_str()))
    };
    let mut out = Vec::new();

    let exfil = match (has(STRONG_SOURCES), has(WEAK_SOURCES)) {
        (Some(src), _) => has(HARD_SINKS).or(has(SOFT_SINKS)).map(|sink| (src, sink)),
        (None, Some(src)) => has(HARD_SINKS).map(|sink| (src, sink)),
        _ => None,
    };
    if let Some((src, sink)) = exfil {
        out.push(chain(rel_path, CREDENTIAL_EXFIL, src, sink));
    }

    if let (Some(dl), Some(ex)) = (has(&["Remote Script Download"]), has(EXECUTORS)) {
        out.push(chain(rel_path, DOWNLOAD_EXECUTE, dl, ex));
    }

    if let Some(extract) = has(&[ARCHIVE_EXTRACTION]) {
        if ARCHIVE_WRITE.is_match(content) && !TRAVERSAL_GUARD.is_match(content) {
            out.push(RuleMatch {
                file_path: rel_path.to_string(),
                line_number: extract.line_number,
                matched_pattern: ZIP_SLIP.to_string(),
                severity: "high".to_string(),
                context: "Archive entry names are written to disk with no `..` / prefix check — \
                          a crafted archive can overwrite files outside the target directory"
                    .to_string(),
            });
        }
    }
    out
}

/// Chains that span files: an unauthenticated listener in one module feeding
/// a zip-slip extractor in another is remote code execution.
pub fn correlate_package(matches: &[RuleMatch]) -> Vec<RuleMatch> {
    let files_with = |name: &str| -> HashSet<&str> {
        matches
            .iter()
            .filter(|m| m.matched_pattern == name)
            .map(|m| m.file_path.as_str())
            .collect()
    };
    let servers = files_with(LOCAL_SERVER);
    let uploads = files_with(UPLOAD_HANDLER);
    let Some(slip) = matches.iter().find(|m| m.matched_pattern == ZIP_SLIP) else {
        return Vec::new();
    };
    // The listener must also take uploads, or archives never arrive over it.
    let Some(server) = servers.intersection(&uploads).min() else {
        return Vec::new();
    };
    vec![RuleMatch {
        file_path: slip.file_path.clone(),
        line_number: slip.line_number,
        matched_pattern: REMOTE_FILE_WRITE.to_string(),
        severity: "critical".to_string(),
        context: format!(
            "{} accepts uploads on a network listener; {} extracts archives without path validation",
            server, slip.file_path
        ),
    }]
}

fn chain(rel_path: &str, name: &str, a: &RuleMatch, b: &RuleMatch) -> RuleMatch {
    RuleMatch {
        file_path: rel_path.to_string(),
        line_number: a.line_number,
        matched_pattern: name.to_string(),
        severity: "critical".to_string(),
        context: format!(
            "{} (line {}) + {} (line {})",
            a.matched_pattern, a.line_number, b.matched_pattern, b.line_number
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(file: &str, rule: &str, line: usize) -> RuleMatch {
        RuleMatch {
            file_path: file.to_string(),
            line_number: line,
            matched_pattern: rule.to_string(),
            severity: "high".to_string(),
            context: String::new(),
        }
    }

    #[test]
    fn strong_source_plus_any_sink_is_exfil() {
        let m = [
            hit("a.js", "Browser Database Access", 3),
            hit("a.js", "URL Fetch Command", 9),
        ];
        let out = correlate_file("a.js", "", &m);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].matched_pattern, CREDENTIAL_EXFIL);
        assert_eq!(out[0].line_number, 3);
    }

    #[test]
    fn weak_source_needs_hard_sink() {
        let soft = [
            hit("a.js", "Password Manager Access", 1),
            hit("a.js", "URL Fetch Command", 2),
        ];
        assert!(correlate_file("a.js", "", &soft).is_empty());
        let hard = [
            hit("a.js", "Password Manager Access", 1),
            hit("a.js", "Discord Webhook", 2),
        ];
        assert_eq!(correlate_file("a.js", "", &hard).len(), 1);
    }

    #[test]
    fn zip_slip_requires_missing_guard() {
        let m = [hit("assets.js", ARCHIVE_EXTRACTION, 5)];
        let unsafe_js = "for (let f in zip.files) { await fs.writeFile(path.resolve(base, f), d) }";
        let out = correlate_file("assets.js", unsafe_js, &m);
        assert_eq!(out[0].matched_pattern, ZIP_SLIP);

        let guarded = "for (let f in zip.files) { const p = path.resolve(base, f);\n\
                       if (!p.startsWith(base)) throw 'bad'; await fs.writeFile(p, d) }";
        assert!(correlate_file("assets.js", guarded, &m).is_empty());

        let py_safe = "with tarfile.open(p) as t:\n    t.extractall(dest, filter='data')";
        assert!(correlate_file("x.py", py_safe, &[hit("x.py", ARCHIVE_EXTRACTION, 1)]).is_empty());
    }

    #[test]
    fn upload_server_plus_zip_slip_is_remote_file_write() {
        let m = vec![
            hit("src/service.js", LOCAL_SERVER, 70),
            hit("src/service.js", UPLOAD_HANDLER, 95),
            hit("src/assets.js", ZIP_SLIP, 88),
        ];
        let out = correlate_package(&m);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].matched_pattern, REMOTE_FILE_WRITE);
        assert_eq!(out[0].file_path, "src/assets.js");

        // A server without an upload route is not enough.
        assert!(
            correlate_package(&m[..1].iter().chain(&m[2..]).cloned().collect::<Vec<_>>())
                .is_empty()
        );
    }
}
