use crate::attack::{self, AttackTechnique};
use crate::triage::{BinaryArtifact, TriageReport};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::ffi::OsString;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::time::timeout;

const ENGINE: &str = concat!("kalascan-sandbox/", env!("CARGO_PKG_VERSION"));
const DEFAULT_IMAGE: &str = "kalascan-sandbox:latest";
const MAX_SAMPLES: usize = 3;
const MAX_TRACE_BYTES: usize = 2 * 1024 * 1024;
const MAX_EXCERPT: usize = 20;
const MAX_PROCESSES: usize = 20;
const MAX_NETWORK: usize = 20;
const MAX_FILES: usize = 30;
const MAX_INDICATORS: usize = 20;

/// Path segments, not words: `token` matched Python's own `tokenize.py` on
/// every import, and libc reads /etc/passwd for getpwuid().
const CREDENTIAL_PATHS: &[&str] = &[
    "/etc/shadow",
    "/.ssh/",
    "id_rsa",
    "id_ed25519",
    "authorized_keys",
    "/.aws/",
    "/.npmrc",
    "/.pypirc",
    "/.netrc",
    "/.env",
    "/.git-credentials",
    "/.docker/config.json",
    "/.kube/config",
    "/.config/gh/",
    "wallet",
    "metamask",
    "keychain",
    "login data",
    "cookies.sqlite",
];

/// Planted in the install sandbox's home before tracing starts. No install
/// step needs them (the image has no npm, git, gh or aws CLI to read them);
/// a stealer goes straight for them.
const BAIT_FILES: &[&str] = &[
    ".ssh/id_rsa",
    ".aws/credentials",
    ".npmrc",
    ".git-credentials",
    ".config/gh/hosts.yml",
    ".env",
];
const SANDBOX_HOME: &str = "/tmp/home";
/// `file_type` of install-trace executions. They inform the report but do
/// not score: benign installs run shells, chmod and fetch prebuilt binaries.
const INSTALL_HOOKS: &str = "install hooks";

pub const INSTALL_CREDENTIAL_ACCESS: &str = "Chain: Install-time Credential Access (sandbox)";

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
    for execution in report
        .executions
        .iter()
        .filter(|e| e.file_type != INSTALL_HOOKS)
    {
        score += (execution.network_attempts.len() as u16 * 4).min(12);
        score += (execution.indicators.len() as u16 * 2).min(12);
        if execution.timed_out {
            score += 2;
        }
    }
    score.min(30) as u8
}

/// What installing the package at `dir` runs: npm lifecycle scripts, or
/// setup.py and `.pth` startup hooks. Returns (file that declares them,
/// label, shell steps); `None` when nothing runs at install.
fn install_plan(dir: &Path) -> Option<(String, String, String)> {
    let quote = |s: &str| format!("'{}'", s.replace('\'', r"'\''"));
    if let Some(pkg) = std::fs::read_to_string(dir.join("package.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
    {
        let steps: Vec<(&str, &str)> = ["preinstall", "install", "postinstall"]
            .into_iter()
            .filter_map(|s| pkg["scripts"][s].as_str().map(|cmd| (s, cmd)))
            .collect();
        if steps.is_empty() {
            return None;
        }
        let name = pkg["name"].as_str().unwrap_or("package");
        let mut script = format!("export npm_package_name={}\n", quote(name));
        for (event, cmd) in &steps {
            script.push_str(&format!(
                "npm_lifecycle_event={} sh -c {}\n",
                event,
                quote(cmd)
            ));
        }
        let events: Vec<&str> = steps.iter().map(|(s, _)| *s).collect();
        let label = format!("npm install: {}", events.join(", "));
        return Some(("package.json".to_string(), label, script));
    }
    let setup = dir.join("setup.py").is_file();
    let pth = std::fs::read_dir(dir).ok()?.flatten().find_map(|e| {
        let name = e.file_name().to_string_lossy().into_owned();
        name.ends_with(".pth").then_some(name)
    });
    let mut script = String::new();
    if setup {
        script.push_str("python3 setup.py -q install --root /tmp/root\n");
    }
    if pth.is_some() {
        // `.pth` lines starting with `import` run at every interpreter start.
        script.push_str("python3 -c \"import site; site.addsitedir('/tmp/pkg')\"\n");
    }
    match (setup, pth) {
        (true, None) => Some(("setup.py".into(), "pip install: setup.py".into(), script)),
        (true, Some(_)) => Some((
            "setup.py".into(),
            "pip install: setup.py, .pth hooks".into(),
            script,
        )),
        (false, Some(pth)) => Some((pth, "pip install: .pth hooks".into(), script)),
        (false, None) => None,
    }
}

/// Run the package's install hooks in the sandbox under strace, with bait
/// credentials in $HOME. The execution goes into `report`; opening a bait
/// file comes back as a finding.
pub async fn trace_install(
    dir: &Path,
    config: &SandboxConfig,
    report: &mut SandboxReport,
) -> Vec<crate::RuleMatch> {
    // Unavailable: analyze_triage already noted why.
    let Some((manifest, label, steps)) = install_plan(dir).filter(|_| report.available) else {
        return Vec::new();
    };
    let root = match std::fs::canonicalize(dir) {
        Ok(root) => root,
        Err(error) => {
            report
                .notes
                .push(format!("Install trace skipped: {}", error));
            return Vec::new();
        }
    };
    let bait: Vec<String> = BAIT_FILES
        .iter()
        .map(|f| format!("{}/{}", SANDBOX_HOME, f))
        .collect();
    // Bait is planted and the package copied before strace starts, so
    // neither shows in the trace. `-y` prints the path behind each returned
    // fd, which catches relative opens (`cd ~; cat .npmrc`). The steps come
    // in as $1: docker passes argv as is, no host shell in between.
    let script = format!(
        "export HOME={home}; \
         for f in {bait}; do mkdir -p \"$(dirname \"$f\")\"; echo kalascan-bait > \"$f\"; done; \
         printf '%s' \"$1\" > /tmp/steps.sh; \
         cp -r /pkg /tmp/pkg 2>/dev/null; cd /tmp/pkg || exit 1; \
         timeout 50 strace -f -qq -y -e trace=process,file,network -s 200 -o /tmp/trace sh /tmp/steps.sh >/dev/null 2>&1; \
         code=$?; cat /tmp/trace 2>/dev/null; exit $code",
        home = SANDBOX_HOME,
        bait = bait.join(" ")
    );
    let name = format!("kalascan-install-{}", uuid::Uuid::new_v4());
    let args = docker_run_args(
        &name,
        &INSTALL_LIMITS,
        &format!("{}:/pkg:ro", root.display()),
        &config.image,
        &script,
        &["install-trace", &steps],
    );
    let (exit_code, duration_ms, text, analysis) =
        match run_docker(&args, &name, Duration::from_secs(90)).await {
            Ok(run) => run,
            Err(error) => {
                report
                    .notes
                    .push(format!("Install trace failed: {}", error));
                return Vec::new();
            }
        };
    let opened = bait_accesses(&text, &bait);
    let execution = build_execution(
        &label,
        INSTALL_HOOKS,
        host_arch(),
        exit_code,
        exit_code == Some(124),
        duration_ms,
        analysis,
    );
    attack::merge(&mut report.attack_techniques, execution.attack.clone());
    report
        .attack_techniques
        .sort_by(|left, right| left.id.cmp(&right.id));
    report.executions.push(execution);
    report.files_analyzed += 1;
    if opened.is_empty() {
        return Vec::new();
    }
    vec![crate::RuleMatch {
        file_path: manifest,
        line_number: 1,
        matched_pattern: INSTALL_CREDENTIAL_ACCESS.to_string(),
        severity: "critical".to_string(),
        context: format!("{} opened {}", label, opened.join(", ")),
    }]
}

/// Bait files a trace opened. Only opens count: a stat or access() is an
/// existence check, which benign tooling does too.
fn bait_accesses(trace: &str, bait: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for line in trace.lines() {
        let line = strip_pid_prefix(line.trim());
        let Some((name, rest)) = line.split_once('(') else {
            continue;
        };
        if !matches!(name, "open" | "openat" | "openat2" | "creat") {
            continue;
        }
        // `= 3</tmp/home/.npmrc>` with -y; the quoted argument otherwise.
        let resolved = rest
            .rsplit_once(") = ")
            .and_then(|(_, ret)| ret.split_once('<'))
            .and_then(|(_, path)| path.strip_suffix('>'))
            .map(str::to_string);
        if let Some(path) = resolved.or_else(|| first_quoted(rest)) {
            if bait.contains(&path) {
                push_unique(&mut out, path, MAX_FILES);
            }
        }
    }
    out
}

struct Limits {
    pids: &'static str,
    memory: &'static str,
    cpus: &'static str,
    tmpfs: &'static str,
    nofile: &'static str,
}

const SAMPLE_LIMITS: Limits = Limits {
    pids: "64",
    memory: "256m",
    cpus: "0.5",
    tmpfs: "/tmp:rw,exec,nosuid,size=64m",
    nofile: "nofile=64:64",
};

/// Install hooks run node or python and may compile: more room than one ELF.
const INSTALL_LIMITS: Limits = Limits {
    pids: "128",
    memory: "512m",
    cpus: "1",
    tmpfs: "/tmp:rw,exec,nosuid,size=512m",
    nofile: "nofile=256:256",
};

/// `docker run` with the isolation every sandbox run shares: no network,
/// read-only root, no capabilities, `nobody`, one read-only mount.
fn docker_run_args(
    name: &str,
    limits: &Limits,
    mount: &str,
    image: &str,
    script: &str,
    script_args: &[&str],
) -> Vec<OsString> {
    [
        "run",
        "--rm",
        "--name",
        name,
        "--network",
        "none",
        "--ipc",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        limits.pids,
        "--memory",
        limits.memory,
        "--memory-swap",
        limits.memory,
        "--cpus",
        limits.cpus,
        "--user",
        "65534:65534",
        "--tmpfs",
        limits.tmpfs,
        "--ulimit",
        limits.nofile,
        "-v",
        mount,
        image,
        "sh",
        "-c",
        script,
    ]
    .into_iter()
    .chain(script_args.iter().copied())
    .map(OsString::from)
    .collect()
}

/// Run `docker` and parse the strace output it prints: exit code, duration,
/// raw trace and its analysis. The traced program is bounded by `timeout`
/// inside the container, so hitting `limit` means Docker itself is stuck:
/// an infrastructure failure, not behaviour worth risk points.
async fn run_docker(
    args: &[OsString],
    name: &str,
    limit: Duration,
) -> Result<(Option<i32>, u64, String, StraceAnalysis), String> {
    let started = Instant::now();
    let result = timeout(
        limit,
        Command::new("docker")
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await;
    let duration_ms = started.elapsed().as_millis() as u64;
    let output = match result {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => return Err(error.to_string()),
        Err(_) => {
            let _ = timeout(
                Duration::from_secs(10),
                Command::new("docker")
                    .args(["rm", "-f", name])
                    .kill_on_drop(true)
                    .output(),
            )
            .await;
            return Err(format!("docker did not finish within {}s", limit.as_secs()));
        }
    };
    // Cut the bytes, then decode: `String::truncate` panics inside a
    // multi-byte char.
    let trace = &output.stdout[..output.stdout.len().min(MAX_TRACE_BYTES)];
    let text = String::from_utf8_lossy(trace).into_owned();
    let analysis = parse_strace(&text);
    if analysis.syscalls == 0 && !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        let detail = detail.trim();
        if !detail.is_empty() {
            return Err(truncate(detail, 300));
        }
    }
    Ok((output.status.code(), duration_ms, text, analysis))
}

async fn docker_available() -> bool {
    matches!(
        timeout(
            Duration::from_secs(5),
            Command::new("docker")
                .arg("info")
                .kill_on_drop(true)
                .output()
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
                .kill_on_drop(true)
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
    // The sample's own output goes nowhere: stdout carries only the trace.
    // Mixed in, a sample could print fake `connect(...)` lines that parsed as
    // syscalls, or 2 MB of padding that pushed the real trace past the cap.
    let script = concat!(
        "set -eu; ",
        "cp /sample /tmp/sample; ",
        "chmod 700 /tmp/sample; ",
        "set +e; ",
        "timeout 10 strace -f -qq -e trace=process,file,network,memory -s 200 -o /tmp/trace /tmp/sample >/dev/null 2>&1; ",
        "code=$?; ",
        "cat /tmp/trace 2>/dev/null || true; ",
        "exit $code"
    );
    let args = docker_run_args(
        &name,
        &SAMPLE_LIMITS,
        &format!("{}:/sample:ro", absolute.display()),
        &config.image,
        script,
        &[],
    );
    let (exit_code, duration_ms, _, analysis) = run_docker(&args, &name, config.timeout).await?;
    Ok(build_execution(
        &binary.path,
        &binary.file_type,
        binary.architecture.as_deref().unwrap_or("unknown"),
        exit_code,
        exit_code == Some(124),
        duration_ms,
        analysis,
    ))
}

fn build_execution(
    file_path: &str,
    file_type: &str,
    architecture: &str,
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
        file_path: file_path.to_string(),
        file_type: file_type.to_string(),
        architecture: architecture.to_string(),
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
    std::env::consts::ARCH
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
1234  openat(AT_FDCWD, "/home/u/.ssh/id_rsa", O_RDONLY) = 3
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
            .any(|path| path.contains("/.ssh/id_rsa")));
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
    fn library_paths_are_not_credentials() {
        // Python opens tokenize.py on import; libc reads /etc/passwd for getpwuid.
        let trace = r#"
1  openat(AT_FDCWD, "/usr/lib/python3.11/tokenize.py", O_RDONLY) = 3
1  openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3
"#;
        let analysis = parse_strace(trace);
        assert!(!analysis.indicators.iter().any(|i| i.contains("credential")));
    }

    #[test]
    fn install_plans_and_bait_detection() {
        let npm = tempfile::tempdir().unwrap();
        std::fs::write(
            npm.path().join("package.json"),
            r#"{"name": "x", "scripts": {"postinstall": "node -e 'steal()'", "test": "jest"}}"#,
        )
        .unwrap();
        let (manifest, label, steps) = install_plan(npm.path()).unwrap();
        assert_eq!(
            (manifest.as_str(), label.as_str()),
            ("package.json", "npm install: postinstall")
        );
        assert!(
            steps.contains(r"sh -c 'node -e '\''steal()'\'''"),
            "{}",
            steps
        );
        std::fs::write(npm.path().join("package.json"), r#"{"name": "x"}"#).unwrap();
        assert!(install_plan(npm.path()).is_none());

        let py = tempfile::tempdir().unwrap();
        std::fs::write(py.path().join("evil.pth"), "import os").unwrap();
        assert_eq!(install_plan(py.path()).unwrap().0, "evil.pth");
        std::fs::write(py.path().join("setup.py"), "from setuptools import setup").unwrap();
        let (manifest, label, _) = install_plan(py.path()).unwrap();
        assert_eq!(
            (manifest.as_str(), label.as_str()),
            ("setup.py", "pip install: setup.py, .pth hooks")
        );

        let bait = vec![
            "/tmp/home/.ssh/id_rsa".to_string(),
            "/tmp/home/.npmrc".to_string(),
        ];
        let trace = r#"
7  openat(AT_FDCWD, ".npmrc", O_RDONLY|O_CLOEXEC) = 3</tmp/home/.npmrc>
7  newfstatat(AT_FDCWD, "/tmp/home/.ssh/id_rsa", {st_mode=S_IFREG|0644, st_size=14, ...}, 0) = 0
7  openat(AT_FDCWD, "/tmp/pkg/.env", O_RDONLY) = 3</tmp/pkg/.env>
[pid 8] openat(AT_FDCWD, "/tmp/home/.ssh/id_rsa", O_RDONLY) = 4
"#;
        assert_eq!(
            bait_accesses(trace, &bait),
            vec!["/tmp/home/.npmrc", "/tmp/home/.ssh/id_rsa"]
        );
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
