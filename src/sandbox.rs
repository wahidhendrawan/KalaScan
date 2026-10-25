use crate::attack::{self, AttackTechnique};
use crate::triage::{BinaryArtifact, TriageReport};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::ffi::OsString;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::time::timeout;

const ENGINE: &str = "kalascan-sandbox/1.7.0";
const DEFAULT_IMAGE: &str = "kalascan-sandbox:latest";
const MAX_SAMPLES: usize = 3;
const MAX_TRACE_BYTES: usize = 2 * 1024 * 1024;
const MAX_EXCERPT: usize = 20;
const MAX_PROCESSES: usize = 20;
const MAX_NETWORK: usize = 20;
const MAX_FILES: usize = 30;
const MAX_INDICATORS: usize = 20;

const CREDENTIAL_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    ".ssh",
    "id_rsa",
    "authorized_keys",
    ".aws",
    ".npmrc",
    ".env",
    ".git-credentials",
    "wallet",
    "metamask",
    "keychain",
    "credentials",
    "token",
];

const PERSISTENCE_PATHS: &[&str] = &[
    "/etc/cron",
    "/etc/systemd",
    "/etc/rc",
    "autostart",
    "launchagents",
    "launchdaemons",
    "startup",
];

const SYSTEM_PATHS: &[&str] = &["/proc/", "/sys/", "/dev/"];

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub image: String,
    pub timeout: Duration,
    pub max_samples: usize,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            image: DEFAULT_IMAGE.to_string(),
            timeout: Duration::from_secs(20),
            max_samples: MAX_SAMPLES,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxReport {
    pub engine: String,
    pub available: bool,
    pub image: String,
    pub files_analyzed: usize,
    pub executions: Vec<SandboxExecution>,
    pub attack_techniques: Vec<AttackTechnique>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxExecution {
    pub file_path: String,
    pub file_type: String,
    pub architecture: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub duration_ms: u64,
    pub syscalls: usize,
    pub processes: Vec<String>,
    pub network_attempts: Vec<String>,
    pub file_accesses: Vec<String>,
    pub indicators: Vec<String>,
    pub attack: Vec<AttackTechnique>,
    pub trace_excerpt: Vec<String>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct StraceAnalysis {
    syscalls: usize,
    processes: Vec<String>,
    network_attempts: Vec<String>,
    file_accesses: Vec<String>,
    indicators: Vec<String>,
    trace_excerpt: Vec<String>,
}

pub async fn analyze_triage(
    dir: &Path,
    triage: &TriageReport,
    config: &SandboxConfig,
) -> SandboxReport {
    let mut report = SandboxReport {
        engine: ENGINE.to_string(),
        image: config.image.clone(),
        ..Default::default()
    };

    if !docker_available().await {
        report
            .notes
            .push("Docker daemon is unavailable; sandbox execution was skipped.".to_string());
        return report;
    }
    if !image_available(&config.image).await {
        report.notes.push(format!(
            "Sandbox image '{}' is not available. Build it with: docker build -t {} sandbox",
            config.image, config.image
        ));
        return report;
    }

    report.available = true;
    let root = match std::fs::canonicalize(dir) {
        Ok(root) => root,
        Err(error) => {
            report
                .notes
                .push(format!("Cannot resolve scan directory: {}", error));
            return report;
        }
    };
    let host_arch = host_arch();
    let mut selected = 0usize;

    for binary in &triage.binaries {
        if selected >= config.max_samples {
            break;
        }
        if binary.file_type != "ELF" {
            continue;
        }
        if !architecture_matches(binary.architecture.as_deref(), host_arch) {
            report.notes.push(format!(
                "Skipped {} because its architecture ({}) does not match the host ({}).",
                binary.path,
                binary.architecture.as_deref().unwrap_or("unknown"),
                host_arch
            ));
            continue;
        }
        let absolute = dir.join(&binary.path);
        let canonical = match std::fs::canonicalize(&absolute) {
            Ok(path) => path,
            Err(error) => {
                report
                    .notes
                    .push(format!("Cannot resolve {}: {}", binary.path, error));
                continue;
            }
        };
        if !canonical.starts_with(&root) {
            report.notes.push(format!(
                "Skipped {} because it resolves outside the scan directory.",
                binary.path
            ));
            continue;
        }

        selected += 1;
        report.files_analyzed += 1;
        match run_sample(&canonical, binary, config).await {
            Ok(execution) => report.executions.push(execution),
            Err(error) => report.notes.push(format!(
                "Sandbox execution failed for {}: {}",
                binary.path, error
            )),
        }
    }

    if report.files_analyzed == 0 {
        report.notes.push(
            "No host-compatible ELF samples were available for sandbox execution.".to_string(),
        );
    }

    report
        .executions
        .sort_by(|left, right| left.file_path.cmp(&right.file_path));
    for execution in &report.executions {
        attack::merge(&mut report.attack_techniques, execution.attack.clone());
    }
    report
        .attack_techniques
        .sort_by(|left, right| left.id.cmp(&right.id));
    report
}

pub fn risk_contribution(report: &SandboxReport) -> u8 {
    if !report.available {
        return 0;
    }
    let mut score = 0u16;
    for execution in &report.executions {
        score += (execution.network_attempts.len() as u16 * 4).min(12);
        score += (execution.indicators.len() as u16 * 2).min(12);
        if execution.timed_out {
            score += 2;
        }
    }
    score.min(30) as u8
}

async fn docker_available() -> bool {
    matches!(
        timeout(
            Duration::from_secs(5),
            Command::new("docker").arg("info").output()
        )
        .await,
        Ok(Ok(output)) if output.status.success()
    )
}

async fn image_available(image: &str) -> bool {
    matches!(
        timeout(
            Duration::from_secs(10),
            Command::new("docker")
                .args(["image", "inspect", image])
                .output()
        )
        .await,
        Ok(Ok(output)) if output.status.success()
    )
}

async fn run_sample(
    absolute: &Path,
    binary: &BinaryArtifact,
    config: &SandboxConfig,
) -> Result<SandboxExecution, String> {
    let name = format!("kalascan-sandbox-{}", uuid::Uuid::new_v4());
    let script = concat!(
        "set -eu; ",
        "cp /sample /tmp/sample; ",
        "chmod 700 /tmp/sample; ",
        "set +e; ",
        "timeout 10 strace -f -qq -e trace=process,file,network,memory -s 200 -o /tmp/trace /tmp/sample; ",
        "code=$?; ",
        "cat /tmp/trace 2>/dev/null || true; ",
        "exit $code"
    );
    let args: Vec<OsString> = vec![
        "run".into(),
        "--rm".into(),
        "--name".into(),
        name.clone().into(),
        "--network".into(),
        "none".into(),
        "--ipc".into(),
        "none".into(),
        "--read-only".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--pids-limit".into(),
        "64".into(),
        "--memory".into(),
        "256m".into(),
        "--memory-swap".into(),
        "256m".into(),
        "--cpus".into(),
        "0.5".into(),
        "--user".into(),
        "65534:65534".into(),
        "--tmpfs".into(),
        "/tmp:rw,exec,nosuid,size=64m".into(),
        "--ulimit".into(),
        "nofile=64:64".into(),
        "-v".into(),
        format!("{}:/sample:ro", absolute.display()).into(),
        config.image.clone().into(),
        "sh".into(),
        "-c".into(),
        script.into(),
    ];

    let started = Instant::now();
    let result = timeout(
        config.timeout,
        Command::new("docker")
            .args(&args)
            .kill_on_drop(true)
            .output(),
    )
    .await;
    let duration_ms = started.elapsed().as_millis() as u64;

    match result {
        Err(_) => {
            let _ = Command::new("docker")
                .args(["rm", "-f", &name])
                .output()
                .await;
            Ok(build_execution(
                binary,
                None,
                true,
                duration_ms,
                StraceAnalysis::default(),
            ))
        }
        Ok(Err(error)) => Err(error.to_string()),
        Ok(Ok(output)) => {
            let exit_code = output.status.code();
            let timed_out = exit_code == Some(124);
            let mut text = String::from_utf8_lossy(&output.stdout).to_string();
            if !output.stderr.is_empty() {
                text.push_str(&String::from_utf8_lossy(&output.stderr));
            }
            if text.len() > MAX_TRACE_BYTES {
                text.truncate(MAX_TRACE_BYTES);
            }
            let analysis = parse_strace(&text);
            if analysis.syscalls == 0 && !output.status.success() {
                let detail = text.trim();
                if !detail.is_empty() {
                    return Err(truncate(detail, 300));
                }
            }
            Ok(build_execution(
                binary,
                exit_code,
                timed_out,
                duration_ms,
                analysis,
            ))
        }
    }
}

fn build_execution(
    binary: &BinaryArtifact,
    exit_code: Option<i32>,
    timed_out: bool,
    duration_ms: u64,
    analysis: StraceAnalysis,
) -> SandboxExecution {
    let mut indicators = analysis.indicators.clone();
    let mut attack = Vec::new();
    let process_text = analysis.processes.join(" ").to_ascii_lowercase();

    if process_text.contains("/bin/sh")
        || process_text.contains("/bin/bash")
        || process_text.contains("/bin/dash")
    {
        push_unique(
            &mut indicators,
            "Sandbox: shell execution".to_string(),
            MAX_INDICATORS,
        );
        add_attack(&mut attack, "T1059.004");
    }
    if process_text.contains("curl") || process_text.contains("wget") {
        push_unique(
            &mut indicators,
            "Sandbox: ingress tool transfer".to_string(),
            MAX_INDICATORS,
        );
        add_attack(&mut attack, "T1105");
    }
    if !analysis.network_attempts.is_empty() {
        add_attack(&mut attack, "T1071");
        add_attack(&mut attack, "T1041");
    }
    if analysis
        .indicators
        .iter()
        .any(|indicator| indicator.contains("credential"))
    {
        add_attack(&mut attack, "T1552");
        add_attack(&mut attack, "T1552.001");
    }
    if analysis
        .indicators
        .iter()
        .any(|indicator| indicator.contains("persistence"))
    {
        add_attack(&mut attack, "T1053.005");
        add_attack(&mut attack, "T1547.001");
    }
    if analysis
        .indicators
        .iter()
        .any(|indicator| indicator.contains("executable memory"))
    {
        add_attack(&mut attack, "T1055");
        add_attack(&mut attack, "T1620");
    }
    if analysis
        .indicators
        .iter()
        .any(|indicator| indicator.contains("file deletion"))
    {
        add_attack(&mut attack, "T1070.004");
    }
    if analysis
        .indicators
        .iter()
        .any(|indicator| indicator.contains("permission modification"))
    {
        add_attack(&mut attack, "T1222");
    }
    if analysis
        .indicators
        .iter()
        .any(|indicator| indicator.contains("anti-analysis"))
    {
        add_attack(&mut attack, "T1622");
    }
    if analysis
        .indicators
        .iter()
        .any(|indicator| indicator.contains("environment discovery"))
    {
        add_attack(&mut attack, "T1083");
    }
    if timed_out {
        push_unique(
            &mut indicators,
            "Sandbox: execution timed out".to_string(),
            MAX_INDICATORS,
        );
    }

    let attack_text = format!(
        "{} {} {} {}",
        indicators.join(" "),
        analysis.processes.join(" "),
        analysis.network_attempts.join(" "),
        analysis.file_accesses.join(" ")
    );
    attack::merge(&mut attack, attack::map_text(&attack_text));
    indicators.sort();
    indicators.dedup();
    indicators.truncate(MAX_INDICATORS);
    attack.sort_by(|left, right| left.id.cmp(&right.id));
    attack.dedup_by(|left, right| left.id == right.id);

    SandboxExecution {
        file_path: binary.path.clone(),
        file_type: binary.file_type.clone(),
        architecture: binary
            .architecture
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        exit_code,
        timed_out,
        duration_ms,
        syscalls: analysis.syscalls,
        processes: analysis.processes,
        network_attempts: analysis.network_attempts,
        file_accesses: analysis.file_accesses,
        indicators,
        attack,
        trace_excerpt: analysis.trace_excerpt,
    }
}

fn parse_strace(text: &str) -> StraceAnalysis {
    let mut analysis = StraceAnalysis::default();
    let mut seen_files = HashSet::new();

    for raw in text.lines() {
        let line = strip_pid_prefix(raw.trim());
        if line.is_empty()
            || line.starts_with("+++")
            || line.starts_with("---")
            || line.starts_with("strace:")
        {
            continue;
        }
        let Some(open) = line.find('(') else {
            continue;
        };
        let name = &line[..open];
        if name.is_empty()
            || !name
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
        {
            continue;
        }
        analysis.syscalls += 1;
        if analysis.trace_excerpt.len() < MAX_EXCERPT {
            analysis.trace_excerpt.push(truncate(line, 300));
        }
        let args = &line[open + 1..];

        match name {
            "execve" | "execveat" => {
                if let Some(path) = first_quoted(args) {
                    push_unique(&mut analysis.processes, path, MAX_PROCESSES);
                }
            }
            "clone" | "clone3" | "fork" | "vfork" => {
                push_unique(
                    &mut analysis.processes,
                    format!("{}()", name),
                    MAX_PROCESSES,
                );
            }
            "socket" | "connect" | "sendto" | "recvfrom" | "bind" | "listen" | "accept"
            | "accept4" | "sendmsg" | "recvmsg" => {
                push_unique(
                    &mut analysis.network_attempts,
                    truncate(line, 240),
                    MAX_NETWORK,
                );
                push_unique(
                    &mut analysis.indicators,
                    "Sandbox: outbound network attempt".to_string(),
                    MAX_INDICATORS,
                );
            }
            "open" | "openat" | "openat2" | "creat" | "unlink" | "unlinkat" | "rename"
            | "renameat" | "chmod" | "fchmodat" | "mkdir" | "mkdirat" => {
                for path in quoted_strings(args) {
                    if !is_sensitive_path(&path) {
                        continue;
                    }
                    if seen_files.insert(path.clone()) {
                        push_unique(
                            &mut analysis.file_accesses,
                            format!("{}: {}", name, path),
                            MAX_FILES,
                        );
                    }
                    if is_credential_path(&path) {
                        push_unique(
                            &mut analysis.indicators,
                            "Sandbox: credential file access".to_string(),
                            MAX_INDICATORS,
                        );
                    }
                    if is_persistence_path(&path) {
                        push_unique(
                            &mut analysis.indicators,
                            "Sandbox: persistence path access".to_string(),
                            MAX_INDICATORS,
                        );
                    }
                }
            }
            "mprotect" | "mmap" => {
                if args.to_ascii_uppercase().contains("PROT_EXEC") {
                    push_unique(
                        &mut analysis.indicators,
                        "Sandbox: executable memory mapping".to_string(),
                        MAX_INDICATORS,
                    );
                }
            }
            "ptrace" => {
                push_unique(
                    &mut analysis.indicators,
                    "Sandbox: debugger/anti-analysis".to_string(),
                    MAX_INDICATORS,
                );
            }
            "uname" | "sysinfo" => {
                push_unique(
                    &mut analysis.indicators,
                    "Sandbox: environment discovery".to_string(),
                    MAX_INDICATORS,
                );
            }
            _ => {}
        }

        if name == "unlink" || name == "unlinkat" {
            push_unique(
                &mut analysis.indicators,
                "Sandbox: file deletion".to_string(),
                MAX_INDICATORS,
            );
        }
        if name == "chmod" || name == "fchmodat" {
            push_unique(
                &mut analysis.indicators,
                "Sandbox: permission modification".to_string(),
                MAX_INDICATORS,
            );
        }
    }

    analysis
}

fn strip_pid_prefix(line: &str) -> &str {
    if let Some(rest) = line.strip_prefix("[pid ") {
        if let Some(end) = rest.find("] ") {
            return rest[end + 2..].trim_start();
        }
    }
    let digits = line
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .count();
    if digits > 0 {
        let rest = &line[digits..];
        if rest.starts_with(' ') {
            return rest.trim_start();
        }
    }
    line
}

fn first_quoted(input: &str) -> Option<String> {
    quoted_strings(input).into_iter().next()
}

fn quoted_strings(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = input;
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('"') else {
            break;
        };
        out.push(after[..end].to_string());
        rest = &after[end + 1..];
    }
    out
}

fn is_sensitive_path(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    CREDENTIAL_PATHS
        .iter()
        .chain(PERSISTENCE_PATHS)
        .chain(SYSTEM_PATHS)
        .any(|needle| path.contains(needle))
}

fn is_credential_path(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    CREDENTIAL_PATHS.iter().any(|needle| path.contains(needle))
}

fn is_persistence_path(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    PERSISTENCE_PATHS.iter().any(|needle| path.contains(needle))
}

fn push_unique(values: &mut Vec<String>, value: String, limit: usize) {
    if values.len() < limit && !values.contains(&value) {
        values.push(value);
    }
}

fn add_attack(out: &mut Vec<AttackTechnique>, id: &str) {
    if let Some(technique) = attack::lookup(id) {
        attack::merge(out, [technique]);
    }
}

fn host_arch() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "aarch64",
        "x86_64" => "x86_64",
        "x86" => "x86",
        "arm" => "arm",
        other => other,
    }
}

fn architecture_matches(architecture: Option<&str>, host: &str) -> bool {
    let Some(architecture) = architecture else {
        return false;
    };
    let architecture = match architecture {
        "arm64" => "aarch64",
        other => other,
    };
    architecture == host
}

fn truncate(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_network_credential_and_exec_memory() {
        let trace = r#"
1234  execve("/tmp/sample", ["/tmp/sample"], 0x7ffd) = 0
1234  openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3
1234  socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
1234  connect(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("1.2.3.4")}, 16) = -1
1234  mprotect(0x7f000000, 4096, PROT_READ|PROT_EXEC) = 0
1234  chmod("/tmp/sample", 0700) = 0
1234  +++ exited with 0 +++
"#;
        let analysis = parse_strace(trace);
        assert_eq!(analysis.syscalls, 6);
        assert_eq!(analysis.processes, vec!["/tmp/sample"]);
        assert!(!analysis.network_attempts.is_empty());
        assert!(analysis
            .file_accesses
            .iter()
            .any(|path| path.contains("/etc/passwd")));
        assert!(analysis
            .indicators
            .iter()
            .any(|indicator| indicator.contains("network")));
        assert!(analysis
            .indicators
            .iter()
            .any(|indicator| indicator.contains("credential")));
        assert!(analysis
            .indicators
            .iter()
            .any(|indicator| indicator.contains("executable memory")));
    }

    #[test]
    fn ignores_noise_and_unrelated_paths() {
        let trace = r#"
strace: Process 1234 attached
+++ exited with 0 +++
1234  openat(AT_FDCWD, "/tmp/benign.txt", O_RDONLY) = 3
1234  close(3) = 0
"#;
        let analysis = parse_strace(trace);
        assert_eq!(analysis.syscalls, 2);
        assert!(analysis.file_accesses.is_empty());
        assert!(analysis.network_attempts.is_empty());
    }

    #[test]
    fn architecture_matching_handles_arm_alias() {
        assert!(architecture_matches(Some("arm64"), "aarch64"));
        assert!(architecture_matches(Some("x86_64"), "x86_64"));
        assert!(!architecture_matches(Some("x86"), "x86_64"));
        assert!(!architecture_matches(None, "x86_64"));
    }

    #[test]
    fn unavailable_report_has_zero_risk() {
        let report = SandboxReport::default();
        assert_eq!(risk_contribution(&report), 0);
    }
}
