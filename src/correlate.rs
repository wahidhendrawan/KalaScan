//! Correlation of individual rule hits into behaviour chains.
//!
//! A single `fetch(` or `Login Data` string is weak evidence; a credential
//! source and an exfiltration sink in the same file is how stealers actually
//! look. Chain findings carry the `Chain: ` prefix and are weighted as two
//! critical hits by the risk score.

use crate::scanner::{
    ARCHIVE_EXTRACTION, DETACHED_SPAWN, DOWNLOAD_CRADLE, EXFIL_SERVICE, HOST_RECON,
    INSTALL_HOOK_OVERRIDE, IP_LOOKUP, IP_URL, LOCAL_SERVER, MAKE_EXECUTABLE, OBFUSCATOR_IO,
    RAW_SOCKET, REMOTE_BINARY, SEED_ACCESS, SETUP_PY_EXEC, SETUP_PY_STAGER, SHELL_START,
    UPLOAD_HANDLER,
};
use crate::RuleMatch;
use regex::Regex;
use std::collections::{BTreeMap, HashSet};
use std::sync::LazyLock;

pub const CHAIN_PREFIX: &str = "Chain: ";
pub const ZIP_SLIP: &str = "Zip Slip: Archive Extraction Without Path Validation";
pub const CREDENTIAL_EXFIL: &str = "Chain: Credential Exfiltration";
pub const DOWNLOAD_EXECUTE: &str = "Chain: Download and Execute";
pub const REMOTE_FILE_WRITE: &str = "Chain: Remote File Write via Local Server";
pub const REVERSE_SHELL: &str = "Chain: Reverse Shell";
pub const DROP_EXECUTE: &str = "Chain: Drop and Execute Binary";
pub const INSTALL_EXFIL: &str = "Chain: Install-time Exfiltration";
pub const RECON_BEACON: &str = "Chain: Reconnaissance Beacon";
pub const OBFUSCATED_EXEC: &str = "Chain: Obfuscated Process Execution";
pub const INSTALL_PAYLOAD: &str = "Chain: Install-time Payload Execution";
/// Emitted by `cve::own_package_matches` for versions like 99.0.0 / 999.9.9.
pub const DEP_CONFUSION_VERSION: &str = "Dependency Confusion Version";

/// Reads that only a stealer needs: browser stores, wallets, tokens, keys.
const STRONG_SOURCES: &[&str] = &[
    "Browser Profile Access",
    "Crypto Wallet Access",
    "Browser Database Access",
    "Discord Token Harvesting",
    "VS Code Session/Token Stealing",
    "Browser Extension Cookie/Token Theft",
];

/// Reads with common legitimate uses (dotenv, clipboard helpers, hotkeys).
const WEAK_SOURCES: &[&str] = &[
    "Password Manager Access",
    "VS Code Clipboard Harvesting",
    "Browser Extension Keystroke Logger",
    // Git and SSH tooling reads ~/.ssh as its job.
    "SSH Key Access",
    SEED_ACCESS,
];

/// Channels that exist mainly to receive stolen data.
const HARD_SINKS: &[&str] = &[
    "Discord Webhook",
    "Telegram Bot API Token",
    "Slack Webhook",
    "Generic Webhook URL",
    "YARA Rule: DiscordWebhookStealer",
    EXFIL_SERVICE,
    IP_URL,
];

/// Generic network calls; only damning next to a strong source.
const SOFT_SINKS: &[&str] = &[
    "URL Fetch Command",
    "JetBrains Raw Socket Exfiltration",
    RAW_SOCKET,
];

const DOWNLOADERS: &[&str] = &["Remote Script Download", REMOTE_BINARY, DOWNLOAD_CRADLE];

/// Second-stage loaders: decode, fetch or hide a payload before running it.
const STAGERS: &[&str] = &[
    SETUP_PY_STAGER,
    "PowerShell Encoded Command",
    "b64decode + exec Chain",
    "nested b64decode",
    DOWNLOAD_CRADLE,
    REMOTE_BINARY,
    // Not SHELL_START: `cmd /c` is in every Windows build script (node-pty).
    OBFUSCATOR_IO,
];

/// Signals that code runs when the package is installed.
const INSTALL_HOOKS: &[&str] = &["Post-Install Script", INSTALL_HOOK_OVERRIDE, SETUP_PY_EXEC];

/// Where install-time code sends what it collected.
const EXFIL_CHANNELS: &[&str] = &[
    EXFIL_SERVICE,
    IP_URL,
    IP_LOOKUP,
    RAW_SOCKET,
    REMOTE_BINARY,
    "Discord Webhook",
    "Telegram Bot API Token",
    "Slack Webhook",
];

const EXECUTORS: &[&str] = &[
    "child_process (Node.js)",
    "subprocess (Python)",
    "os.system",
    "os.popen",
    "exec() Usage",
    "eval() Usage",
    "PowerShell Encoded Command",
    "JetBrains Process Execution",
    SHELL_START,
    DETACHED_SPAWN,
];

/// Process output wired to a socket: the defining move of a reverse shell.
static SHELL_PIPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\.stdout\.pipe\(|\.pipe\(\s*[\w.]*stdin\b|os\.dup2\(|pty\.spawn\()").unwrap()
});

/// Chain parts must sit this close (bytes). Bundlers put a whole extension in
/// one file, so "same file" alone paired a socket in one module with a
/// child_process in another (Remote Containers, Ansible).
const NEAR: usize = 4096;

/// Chains visible inside one file. `file_matches` are this file's hits and
/// `offsets[i]` the byte offset of `file_matches[i]`.
pub fn correlate_file(
    rel_path: &str,
    content: &str,
    file_matches: &[RuleMatch],
    offsets: &[usize],
) -> Vec<RuleMatch> {
    let has = |names: &[&str]| {
        file_matches
            .iter()
            .find(|m| names.contains(&m.matched_pattern.as_str()))
    };
    let indexed = |names: &[&str]| -> Vec<(usize, &RuleMatch)> {
        file_matches
            .iter()
            .enumerate()
            .filter(|(_, m)| names.contains(&m.matched_pattern.as_str()))
            .map(|(i, m)| (offsets.get(i).copied().unwrap_or(0), m))
            .collect()
    };
    // First (a, b) pair within NEAR bytes of each other.
    let near = |a: &[&str], b: &[&str]| -> Option<(usize, &RuleMatch, &RuleMatch)> {
        let bs = indexed(b);
        indexed(a).into_iter().find_map(|(oa, ma)| {
            bs.iter()
                .find(|(ob, _)| oa.abs_diff(*ob) <= NEAR)
                .map(|(_, mb)| (oa, ma, *mb))
        })
    };
    let mut out = Vec::new();

    let exfil = near(STRONG_SOURCES, HARD_SINKS)
        .or_else(|| near(STRONG_SOURCES, SOFT_SINKS))
        .or_else(|| near(WEAK_SOURCES, HARD_SINKS));
    if let Some((_, src, sink)) = exfil {
        out.push(chain(rel_path, CREDENTIAL_EXFIL, src, sink));
    }

    if let Some((_, dl, ex)) = near(DOWNLOADERS, EXECUTORS) {
        out.push(chain(rel_path, DOWNLOAD_EXECUTE, dl, ex));
    }

    if let Some((at, sock, ex)) = near(&[RAW_SOCKET], EXECUTORS) {
        if SHELL_PIPE.is_match(around(content, at)) {
            out.push(chain(rel_path, REVERSE_SHELL, sock, ex));
        }
    }

    if let Some((_, chmod, spawn)) = near(&[MAKE_EXECUTABLE], &[DETACHED_SPAWN]) {
        out.push(chain(rel_path, DROP_EXECUTE, chmod, spawn));
    }

    // File-wide on purpose: javascript-obfuscator output is a property of the
    // whole file, and legitimate extensions are minified, not obfuscated.
    if let (Some(obf), Some(ex)) = (has(&[OBFUSCATOR_IO]), has(EXECUTORS)) {
        out.push(chain(rel_path, OBFUSCATED_EXEC, obf, ex));
    }

    if has(&[ARCHIVE_EXTRACTION]).is_some() {
        if let Some(line) = crate::zipslip::find(content) {
            out.push(RuleMatch {
                file_path: rel_path.to_string(),
                line_number: line,
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

/// The `NEAR`-byte neighbourhood of `at`, clamped to char boundaries.
fn around(content: &str, at: usize) -> &str {
    let mut lo = at.saturating_sub(NEAR).min(content.len());
    let mut hi = (at + NEAR).min(content.len());
    while !content.is_char_boundary(lo) {
        lo -= 1;
    }
    while !content.is_char_boundary(hi) {
        hi += 1;
    }
    &content[lo..hi]
}

/// The package a file belongs to: `""` for the scanned package itself, or
/// the `…/node_modules/<name>` (or `@scope/name`) prefix of a bundled dep.
fn package_unit(path: &str) -> &str {
    let p = path.trim_start_matches("./");
    let Some(i) = p.rfind("node_modules/") else {
        return "";
    };
    let rest = &p[i + "node_modules/".len()..];
    let mut parts = rest.splitn(3, '/');
    let first = parts.next().unwrap_or_default();
    let len = if first.starts_with('@') {
        first.len() + 1 + parts.next().map_or(0, str::len)
    } else {
        first.len()
    };
    &p[..i + "node_modules/".len() + len]
}

/// Chains that span files (and manifest findings), run once per scan after
/// every pass has added its findings. Evidence only combines within one
/// package: two unrelated bundled deps (an IP-lookup lib and a LAN-address
/// lib) are not one beacon.
#[cfg(test)]
pub fn correlate_package(matches: &[RuleMatch]) -> Vec<RuleMatch> {
    correlate_package_with(matches, true)
}

/// `install_hooks_run`: false for a VS Code extension root, whose
/// package.json scripts are the author's build steps and never run when a
/// user installs the extension (Remote Containers, carbon-now-sh).
pub fn correlate_package_with(matches: &[RuleMatch], install_hooks_run: bool) -> Vec<RuleMatch> {
    let mut units: BTreeMap<&str, Vec<&RuleMatch>> = BTreeMap::new();
    for m in matches {
        units.entry(package_unit(&m.file_path)).or_default().push(m);
    }
    units
        .into_iter()
        .flat_map(|(unit, ms)| correlate_unit(&ms, unit.is_empty() && install_hooks_run))
        .collect()
}

/// `hooks_run`: this unit is the scanned package and its install hooks run.
fn correlate_unit(matches: &[&RuleMatch], hooks_run: bool) -> Vec<RuleMatch> {
    let first = |names: &[&str]| {
        matches
            .iter()
            .copied()
            .find(|m| names.contains(&m.matched_pattern.as_str()))
    };
    let mut out = remote_file_write(matches);

    // Install hook + anything that ships data out = dependency-confusion probe
    // or install-time stealer. Recon + a plain HTTP call also counts here:
    // legitimate install scripts do not need the hostname and username.
    // Root only: a bundled dep's own install script never runs for the user.
    if let Some(hook) = first(INSTALL_HOOKS).filter(|_| hooks_run) {
        let sink = first(EXFIL_CHANNELS)
            .or_else(|| first(&[HOST_RECON]).and(first(&["URL Fetch Command"])));
        if let Some(sink) = sink {
            out.push(chain(&sink.file_path, INSTALL_EXFIL, hook, sink));
        }
        if let Some(stager) = first(STAGERS) {
            out.push(chain(&stager.file_path, INSTALL_PAYLOAD, hook, stager));
        }
    }

    // An IP-lookup service alone is a legitimate "what is my IP" feature;
    // pair recon with channels that only receive data.
    if let Some(recon) = first(&[HOST_RECON]) {
        let beacon = first(&[
            EXFIL_SERVICE,
            IP_URL,
            "Discord Webhook",
            "Telegram Bot API Token",
        ])
        .or_else(|| first(&[DEP_CONFUSION_VERSION]).and(first(&["URL Fetch Command"])));
        if let Some(sink) = beacon {
            out.push(chain(&recon.file_path, RECON_BEACON, recon, sink));
        }
    }
    out
}

/// An unauthenticated listener in one module feeding a zip-slip extractor in
/// another is remote code execution.
fn remote_file_write(matches: &[&RuleMatch]) -> Vec<RuleMatch> {
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
        let out = correlate_file("a.js", "", &m, &[]);
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
        assert!(correlate_file("a.js", "", &soft, &[]).is_empty());
        let hard = [
            hit("a.js", "Password Manager Access", 1),
            hit("a.js", "Discord Webhook", 2),
        ];
        assert_eq!(correlate_file("a.js", "", &hard, &[]).len(), 1);
    }

    #[test]
    fn zip_slip_requires_missing_guard() {
        let m = [hit("assets.js", ARCHIVE_EXTRACTION, 5)];
        let unsafe_js = "for (let f in zip.files) { await fs.writeFile(path.resolve(base, f), d) }";
        let out = correlate_file("assets.js", unsafe_js, &m, &[]);
        assert_eq!(out[0].matched_pattern, ZIP_SLIP);

        let guarded = "for (let f in zip.files) { const p = path.resolve(base, f);\n\
                       if (!p.startsWith(base)) throw 'bad'; await fs.writeFile(p, d) }";
        assert!(correlate_file("assets.js", guarded, &m, &[]).is_empty());

        let py_safe = "with tarfile.open(p) as t:\n    t.extractall(dest, filter='data')";
        assert!(
            correlate_file("x.py", py_safe, &[hit("x.py", ARCHIVE_EXTRACTION, 1)], &[]).is_empty()
        );
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

    fn names(out: &[RuleMatch]) -> Vec<&str> {
        out.iter().map(|m| m.matched_pattern.as_str()).collect()
    }

    #[test]
    fn reverse_shell_needs_socket_exec_and_pipe() {
        let m = [
            hit("x.js", RAW_SOCKET, 3),
            hit("x.js", "child_process (Node.js)", 1),
        ];
        let piped = "const sh = cp.spawn('/bin/sh'); const c = new net.Socket(); c.pipe(sh.stdin); sh.stdout.pipe(c);";
        assert_eq!(
            names(&correlate_file("x.js", piped, &m, &[])),
            vec![REVERSE_SHELL]
        );
        // A debug adapter that spawns a process and talks over a socket is not one.
        assert!(correlate_file("x.js", "spawn(adapter); net.connect(port)", &m, &[]).is_empty());
    }

    #[test]
    fn chmod_plus_detached_spawn_is_drop_and_execute() {
        let m = [
            hit("i.mjs", MAKE_EXECUTABLE, 5),
            hit("i.mjs", DETACHED_SPAWN, 9),
        ];
        assert_eq!(
            names(&correlate_file("i.mjs", "", &m, &[])),
            vec![DROP_EXECUTE]
        );
    }

    #[test]
    fn binary_download_plus_start_is_download_execute() {
        let m = [
            hit("run.bat", REMOTE_BINARY, 9),
            hit("run.bat", SHELL_START, 20),
        ];
        assert_eq!(
            names(&correlate_file("run.bat", "", &m, &[])),
            vec![DOWNLOAD_EXECUTE]
        );
    }

    #[test]
    fn install_hook_plus_exfil_channel_is_install_exfil() {
        let m = vec![
            hit("package.json", "Post-Install Script", 3),
            hit("index.js", EXFIL_SERVICE, 12),
        ];
        assert_eq!(names(&correlate_package(&m)), vec![INSTALL_EXFIL]);

        // Recon + plain HTTP at install time also counts.
        let m = vec![
            hit("package.json", "Post-Install Script", 3),
            hit("index.js", HOST_RECON, 5),
            hit("index.js", "URL Fetch Command", 20),
        ];
        assert_eq!(names(&correlate_package(&m)), vec![INSTALL_EXFIL]);

        // An install script that only downloads from a CDN with fetch is not.
        let m = vec![
            hit("package.json", "Post-Install Script", 3),
            hit("install.js", "URL Fetch Command", 20),
        ];
        assert!(correlate_package(&m).is_empty());
    }

    #[test]
    fn recon_plus_beacon_target_is_recon_beacon() {
        let m = vec![hit("a.js", HOST_RECON, 2), hit("b.js", EXFIL_SERVICE, 7)];
        assert_eq!(names(&correlate_package(&m)), vec![RECON_BEACON]);
        // "What is my IP" alone is a feature, not a beacon.
        let m = vec![hit("a.js", HOST_RECON, 2), hit("b.js", IP_LOOKUP, 7)];
        assert!(correlate_package(&m).is_empty());
        // Telemetry that reads the hostname and posts to its own API is not.
        let m = vec![
            hit("a.js", HOST_RECON, 2),
            hit("a.js", "URL Fetch Command", 7),
        ];
        assert!(correlate_package(&m).is_empty());
        // ...unless the package carries a dependency-confusion version.
        let m = vec![
            hit("a.js", HOST_RECON, 2),
            hit("a.js", "URL Fetch Command", 7),
            hit("package.json", DEP_CONFUSION_VERSION, 1),
        ];
        assert_eq!(names(&correlate_package(&m)), vec![RECON_BEACON]);
    }

    #[test]
    fn evidence_does_not_combine_across_bundled_packages() {
        assert_eq!(package_unit("src/index.js"), "");
        assert_eq!(
            package_unit("node_modules/ipify/index.js"),
            "node_modules/ipify"
        );
        assert_eq!(
            package_unit("node_modules/@scope/pkg/lib/a.js"),
            "node_modules/@scope/pkg"
        );
        assert_eq!(
            package_unit("node_modules/a/node_modules/b/x.js"),
            "node_modules/a/node_modules/b"
        );

        // Real LiveServer false positive: two unrelated bundled libs.
        let m = vec![
            hit("node_modules/internal-ip/index.js", HOST_RECON, 18),
            hit("node_modules/ipify/package.json", "Post-Install Script", 8),
            hit("node_modules/ipify/index.js", EXFIL_SERVICE, 4),
        ];
        assert!(correlate_package(&m).is_empty());

        // The same evidence inside one bundled package still chains.
        let m = vec![
            hit("node_modules/evil/a.js", HOST_RECON, 1),
            hit("node_modules/evil/b.js", EXFIL_SERVICE, 2),
        ];
        assert_eq!(names(&correlate_package(&m)), vec![RECON_BEACON]);
    }

    #[test]
    fn install_hook_plus_stager_is_install_payload() {
        // W4SP-style: setup.py runs subprocess with an encoded PowerShell blob.
        let m = vec![
            hit("setup.py", SETUP_PY_EXEC, 9),
            hit("setup.py", "PowerShell Encoded Command", 9),
        ];
        assert_eq!(names(&correlate_package(&m)), vec![INSTALL_PAYLOAD]);
        // cmdclass install override + base64 payload.
        let m = vec![
            hit("setup.py", INSTALL_HOOK_OVERRIDE, 20),
            hit("setup.py", SETUP_PY_STAGER, 6),
        ];
        assert_eq!(names(&correlate_package(&m)), vec![INSTALL_PAYLOAD]);
        // A stager with no install hook is left to the file-level score.
        assert!(correlate_package(&[hit("setup.py", SETUP_PY_STAGER, 6)]).is_empty());
    }

    #[test]
    fn obfuscated_code_that_spawns_processes_is_a_chain() {
        let m = [
            hit("ext.js", OBFUSCATOR_IO, 1),
            hit("ext.js", "exec() Usage", 1),
        ];
        assert_eq!(
            names(&correlate_file("ext.js", "", &m, &[])),
            vec![OBFUSCATED_EXEC]
        );
    }

    #[test]
    fn chain_parts_must_be_near_each_other() {
        // One webpack bundle: a socket module and an unrelated child_process
        // module 200 KB apart are not a reverse shell.
        let content = format!(
            "{}const c = new net.Socket();\n{}cp.exec(cmd); p.stdout.pipe(log);",
            "",
            " ".repeat(200_000)
        );
        let m = [
            hit("bundle.js", RAW_SOCKET, 1),
            hit("bundle.js", "exec() Usage", 2),
        ];
        assert!(correlate_file("bundle.js", &content, &m, &[0, 200_030]).is_empty());
        let close = "const c = new net.Socket(); cp.exec(sh); sh.stdout.pipe(c);";
        assert_eq!(
            names(&correlate_file("x.js", close, &m, &[10, 40])),
            vec![REVERSE_SHELL]
        );
    }

    #[test]
    fn extension_build_scripts_are_not_install_hooks() {
        let m = vec![
            hit("package.json", "Post-Install Script", 3),
            hit("dist/extension.js", RAW_SOCKET, 94),
        ];
        assert_eq!(names(&correlate_package(&m)), vec![INSTALL_EXFIL]);
        assert!(correlate_package_with(&m, false).is_empty());
    }
}
