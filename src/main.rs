mod ai_analyzer;
mod attack;
mod auth;
mod baseline;
mod cli;
mod correlate;
mod cve;
mod db;
mod deobfuscate;
mod diff;
mod emulate;
mod entropy;
mod export;
mod git_history;
mod installed;
mod iocs;
mod metrics;
mod reputation;
mod sandbox;
mod scanner;
mod triage;
mod ttp;
mod vsix;
mod workflow;
mod yara_engine;
mod zipslip;

use axum::{
    extract::{Extension, Multipart, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Json},
    routing::{delete, get, post},
    Router,
};
use clap::Parser;
use cli::{Cli, Commands, UserAction};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;
use tracing::{error, info, warn};

#[derive(Clone)]
struct AppState {
    scans: Arc<Mutex<Vec<ScanResult>>>,
    token: Option<String>,
    /// Caps how many scans run at once; the rest wait in the queue.
    scan_slots: Arc<tokio::sync::Semaphore>,
    /// Abort handles for queued/running scans, so `DELETE` cancels work.
    running: Arc<Mutex<HashMap<String, tokio::task::AbortHandle>>>,
    /// Simple submission budget (scans per minute) to prevent API abuse.
    submit_budget: Arc<Mutex<RateBudget>>,
}

struct RateBudget {
    window: Instant,
    count: u32,
    limit: u32,
}

impl RateBudget {
    fn new(limit: u32) -> Self {
        Self {
            window: Instant::now(),
            count: 0,
            limit,
        }
    }

    /// Returns false once the per-minute budget is exhausted.
    fn try_take(&mut self) -> bool {
        if self.window.elapsed() >= Duration::from_secs(60) {
            self.window = Instant::now();
            self.count = 0;
        }
        if self.count >= self.limit {
            return false;
        }
        self.count += 1;
        true
    }
}

fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn scan_timeout() -> Duration {
    Duration::from_secs(u64::from(env_u32("KALASCAN_SCAN_TIMEOUT_SECS", 900)))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub repo_url: String,
    #[serde(default)]
    pub llm_provider: String,
    #[serde(default)]
    pub llm_model: String,
    #[serde(default)]
    pub llm_api_key: Option<String>,
    #[serde(default)]
    pub llm_endpoint: Option<String>,
    #[serde(default)]
    pub ai_analysis_enabled: bool,
    #[serde(default)]
    pub check_cve: Option<bool>,
    #[serde(default)]
    pub yara_dir: Option<String>,
    /// Extra RegEx rules TOML (CLI-only, like yara_dir)
    #[serde(default)]
    pub rules_file: Option<String>,
    #[serde(default)]
    pub git_history: bool,
    #[serde(default)]
    pub deep_triage: bool,
    #[serde(default)]
    pub deobfuscate: bool,
    #[serde(default)]
    pub emulate: bool,
    #[serde(default)]
    pub sandbox: bool,
    #[serde(default)]
    pub sandbox_image: Option<String>,
    /// Only report findings absent from `baseline` (CI new-findings mode)
    #[serde(default)]
    pub new_only: bool,
    /// Baseline JSON path; when set the current findings are also re-recorded
    #[serde(default)]
    pub baseline: Option<String>,
    /// Path-glob ignore file (default: .kalascanignore when present)
    #[serde(default)]
    pub ignore: Option<String>,
    /// Scan only files changed vs `base_ref` (PR mode)
    #[serde(default)]
    pub changed_only: bool,
    #[serde(default)]
    pub base_ref: Option<String>,
    /// A local directory holding someone else's code (`kalascan installed`).
    /// Never read from the API: remote targets are untrusted by construction.
    #[serde(skip)]
    pub third_party: bool,
}

/// `https://user:token@host/x` -> `https://host/x`, also inside error text
/// such as git's stderr. Scan targets are shown in logs, the audit log, the
/// history table and every report.
pub(crate) fn redact_credentials(text: &str) -> String {
    static USERINFO: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/@\s]+@").unwrap()
    });
    USERINFO.replace_all(text, "$1").into_owned()
}

/// Host and port a remote target makes the server connect to.
fn target_host(target: &str) -> Option<(String, u16)> {
    let t = target.trim();
    // scp-like `git@host:org/repo`
    if let Some(rest) = t.strip_prefix("git@") {
        let host = rest.split([':', '/']).next().filter(|h| !h.is_empty())?;
        return Some((host.to_string(), 22));
    }
    let url = url::Url::parse(t).ok()?;
    let host = url.host_str()?.trim_matches(['[', ']']).to_string();
    Some((host, url.port_or_known_default().unwrap_or(22)))
}

/// API targets must not point the server at its own network: cloud
/// metadata, admin ports, internal Git. The CLI is the operator's own tool
/// and skips this. shortcut: checked once at submit; a host that re-resolves
/// to an internal address before the clone (DNS rebinding) still passes.
async fn check_target_host(target: &str) -> Result<(), String> {
    if vsix::allow_private_targets() {
        return Ok(());
    }
    let Some((host, port)) = target_host(target) else {
        return Ok(()); // marketplace id or npm:/pypi: package: fixed public hosts
    };
    let addrs: Vec<std::net::IpAddr> = match host.parse() {
        Ok(ip) => vec![ip],
        // Unresolvable: the clone or download fails on its own.
        Err(_) => tokio::net::lookup_host((host.as_str(), port))
            .await
            .map(|found| found.map(|a| a.ip()).collect())
            .unwrap_or_default(),
    };
    if addrs.into_iter().any(vsix::is_internal_ip) {
        return Err(format!(
            "Target host '{}' is an internal address; set KALASCAN_ALLOW_PRIVATE_TARGETS=1 \
             to scan internal servers",
            host
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleMatch {
    pub file_path: String,
    pub line_number: usize,
    pub matched_pattern: String,
    pub severity: String,
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAnalysis {
    pub is_malicious: bool,
    pub risk_score: u8,
    pub malware_type: String,
    pub threat_summary: String,
    pub suspicious_lines: Vec<String>,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: String,
    pub repo_url: String,
    pub timestamp: String,
    pub total_files: usize,
    pub scanned_files: usize,
    pub total_matches: usize,
    pub risk_score: u8,
    pub ai_analysis: Option<AiAnalysis>,
    pub rule_matches: Vec<RuleMatch>,
    #[serde(default)]
    pub triage: Option<triage::TriageReport>,
    #[serde(default)]
    pub deobfuscation: Option<deobfuscate::DeobfuscationReport>,
    #[serde(default)]
    pub emulation: Option<emulate::EmulationReport>,
    #[serde(default)]
    pub ttp: Option<ttp::TtpReport>,
    #[serde(default)]
    pub sandbox: Option<sandbox::SandboxReport>,
    pub status: String,
    /// Wall-clock duration of the scan, when it ran to completion.
    #[serde(default)]
    pub duration_ms: Option<u64>,
    /// External URLs / IPs the scanned code refers to.
    #[serde(default)]
    pub iocs: Vec<iocs::Ioc>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("kalascan=info")
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Scan {
            target,
            format,
            fail_on_risk,
            output,
            new_only,
            baseline,
            update_baseline,
            ignore,
            untrusted,
            changed_only,
            base_ref,
            ai,
            llm_provider,
            llm_model,
            llm_key,
            llm_endpoint,
            cve,
            yara_dir,
            rules,
            git_history,
            deep_triage,
            deobfuscate,
            emulate,
            sandbox,
            sandbox_image,
        }) => {
            // Written only on request: --new-only reads the baseline, never updates it.
            let baseline_path = baseline.clone().filter(|_| update_baseline);
            let req = ScanRequest {
                repo_url: target,
                llm_provider,
                llm_model,
                llm_api_key: llm_key,
                llm_endpoint,
                ai_analysis_enabled: ai,
                check_cve: Some(cve),
                yara_dir: yara_dir.map(|p| p.to_string_lossy().to_string()),
                rules_file: rules.map(|p| p.to_string_lossy().to_string()),
                git_history,
                deep_triage,
                deobfuscate,
                emulate,
                sandbox,
                sandbox_image: Some(sandbox_image),
                new_only,
                baseline: baseline.map(|p| p.to_string_lossy().to_string()),
                ignore: ignore.map(|p| p.to_string_lossy().to_string()),
                changed_only,
                base_ref: Some(base_ref),
                third_party: untrusted,
            };
            run_cli_scan(req, format, fail_on_risk, output, baseline_path).await?;
        }
        Some(Commands::Serve { addr }) => {
            start_web_server(&addr).await?;
        }
        Some(Commands::User { action }) => {
            run_user_command(action)?;
        }
        Some(Commands::Rules { name }) => {
            run_rules_command(name)?;
        }
        Some(Commands::Installed {
            format,
            min_risk,
            fail_on_risk,
            jobs,
        }) => {
            run_installed_command(&format, min_risk, fail_on_risk, jobs).await?;
        }
        Some(Commands::Diff {
            old,
            new,
            format,
            fail_on_new,
            cve,
        }) => {
            run_diff_command(&old, &new, &format, fail_on_new.as_deref(), cve).await?;
        }
        Some(Commands::Sbom { path, output }) => {
            run_sbom_command(&path, output.as_deref())?;
        }
        None => {
            // clap already reads KALASCAN_ADDR. Loopback like `serve`: 0.0.0.0
            // made a bare `kalascan` refuse to start without auth.
            let addr = cli.addr.unwrap_or_else(|| "127.0.0.1:3000".to_string());
            start_web_server(&addr).await?;
        }
    }

    Ok(())
}

async fn start_web_server(addr: &str) -> anyhow::Result<()> {
    info!(
        "KalaScan v{} starting Web UI on http://{}",
        env!("CARGO_PKG_VERSION"),
        addr
    );

    // Initialize DB
    if let Err(e) = db::init_db() {
        error!("Failed to init DB (running without persistence): {}", e);
    }

    let token = std::env::var("KALASCAN_TOKEN")
        .ok()
        .filter(|t| !t.trim().is_empty());
    let user_count: i64 = db::ready_conn()
        .ok()
        .and_then(|conn| {
            conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
                .ok()
        })
        .unwrap_or(0);
    if token.is_some() {
        info!("Legacy bearer token enabled (KALASCAN_TOKEN, admin role)");
    }
    if user_count > 0 {
        info!(
            "Multi-user auth enabled: {} user(s) in the database",
            user_count
        );
    }
    if token.is_none() && user_count == 0 {
        if is_loopback(addr) {
            info!("No auth configured (loopback only)");
        } else if std::env::var("KALASCAN_ALLOW_UNAUTHENTICATED").as_deref() == Ok("1") {
            error!(
                "Bound to non-loopback address {} without users or KALASCAN_TOKEN — API is unauthenticated (KALASCAN_ALLOW_UNAUTHENTICATED=1)",
                addr
            );
        } else {
            // Anyone who can reach the port could queue scans and read every
            // result; refuse instead of logging a line nobody reads.
            anyhow::bail!(
                "Refusing to serve on non-loopback address {} without auth. Set KALASCAN_TOKEN \
                 (or add users with `kalascan user add`), or set KALASCAN_ALLOW_UNAUTHENTICATED=1 \
                 if this network is trusted",
                addr
            );
        }
    }

    let state = AppState {
        scans: Arc::new(Mutex::new(Vec::new())),
        token,
        scan_slots: Arc::new(tokio::sync::Semaphore::new(
            env_u32("KALASCAN_MAX_CONCURRENT_SCANS", 4) as usize,
        )),
        running: Arc::new(Mutex::new(HashMap::new())),
        submit_budget: Arc::new(Mutex::new(RateBudget::new(env_u32(
            "KALASCAN_SCAN_RATE_LIMIT",
            30,
        )))),
    };

    // Resume scans that were queued/running when the process last stopped.
    requeue_pending(&state).await;

    let app = Router::new()
        .route("/", get(root))
        .route("/scan", post(api_scan))
        .route("/api/scan", post(api_scan))
        .route("/api/scan/upload", post(api_scan_upload))
        .route("/api/results/{id}", get(get_result))
        .route("/api/scan/{id}/status", get(scan_status))
        .route("/api/history", get(history))
        .route("/api/report/{id}/{format}", get(report))
        .route("/api/audit", get(audit_log))
        .route("/api/sbom", get(sbom_endpoint))
        .route("/api/scan/{id}", delete(delete_scan))
        .route("/results/{id}", get(results_page))
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics_endpoint))
        .route("/openapi.yaml", get(openapi_spec))
        .route("/static/app.css", get(app_css))
        // axum's 2 MiB default rejects real .vsix uploads with a dropped
        // connection (the browser only sees "Failed to fetch"). Cap at the
        // vsix archive guard (1 GiB) instead; KALASCAN_MAX_UPLOAD_MB=0 disables
        // the body limit entirely.
        .layer(upload_body_limit())
        .layer(axum::middleware::from_fn(security_headers))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("Web UI available at http://{}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}

fn is_loopback(addr: &str) -> bool {
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1")
}

/// Enforce bearer auth + RBAC. Inserts the resolved [`auth::Principal`] into
/// request extensions so handlers can attribute actions in the audit log.
async fn auth_middleware(
    State(state): State<AppState>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let path = req.uri().path().to_string();
    if is_auth_exempt(&path) {
        return next.run(req).await;
    }

    let principal = match authenticate_request(&state, req.headers()) {
        Ok(Some(p)) => p,
        Ok(None) => {
            auth::audit("anonymous", "auth.denied", None, Some(&path));
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "success": false, "error": "Unauthorized" })),
            )
                .into_response();
        }
        Err(e) => {
            warn!("Auth check failed: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "success": false, "error": "Authentication error" })),
            )
                .into_response();
        }
    };

    // Read routes: viewer. Anything that mutates state: operator.
    let required = if req.method().as_str() == "GET" {
        auth::Role::Viewer
    } else {
        auth::Role::Operator
    };
    if !principal.role.at_least(required) {
        auth::audit(&principal.name, "auth.forbidden", None, Some(&path));
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "success": false, "error": "Insufficient role" })),
        )
            .into_response();
    }

    req.extensions_mut().insert(principal.clone());
    next.run(req).await
}

/// Liveness/readiness probes and the spec stay unauthenticated so health
/// checks, Prometheus scrapers and API discovery work without credentials.
/// The UI shell is public too: a browser navigation carries no bearer token,
/// so `/` used to answer JSON 401 before the page could ask for one. It holds
/// no data under auth (see `root`); everything else goes through `/api`.
fn is_auth_exempt(path: &str) -> bool {
    path == "/"
        || path.starts_with("/results/")
        || path == "/healthz"
        || path == "/metrics"
        || path == "/openapi.yaml"
        || path.starts_with("/static/")
}

/// Resolve the caller. `None` = credentials missing or wrong.
fn authenticate_request(
    state: &AppState,
    headers: &HeaderMap,
) -> anyhow::Result<Option<auth::Principal>> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    if token.is_empty() {
        // Anonymous access only while no auth of any kind is configured.
        if state.token.is_none() && !auth::any_users() {
            return Ok(Some(auth::Principal::anonymous()));
        }
        return Ok(None);
    }
    if let Some(expected) = state.token.as_deref() {
        if auth::constant_time_eq(token.as_bytes(), expected.as_bytes()) {
            return Ok(Some(auth::Principal::legacy_admin()));
        }
    }
    Ok(auth::authenticate(token))
}

/// Add hardening headers. Styles and scripts are self-hosted and inline, so
/// `unsafe-inline` stays for those sources; the CSP's real job is blocking any
/// third-party CDN or injected remote resource.
async fn security_headers(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static(
            "default-src 'self'; \
             style-src 'self' 'unsafe-inline'; \
             script-src 'self' 'unsafe-inline'; \
             img-src 'self' data:; \
             font-src 'self'; \
             connect-src 'self'; \
             object-src 'none'; \
             base-uri 'self'; \
             frame-ancestors 'none'; \
             form-action 'self'",
        ),
    );
    headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        axum::http::header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        axum::http::header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static("no-referrer"),
    );
    resp
}

/// The dashboard. Two placeholders, filled by plain substitution: a template
/// engine (69 crates) for six values was not worth its compile time.
async fn root(State(state): State<AppState>) -> Html<String> {
    // The page is served without auth; under auth the history comes from
    // /api/history once the browser has a token.
    let auth_enabled = state.token.is_some() || auth::any_users();
    let scan_list = if auth_enabled {
        Vec::new()
    } else {
        db::list_scans(100).unwrap_or_default()
    };
    // Embed as raw JSON for the client-side history list. Escape `<`/`&`/`>` so a
    // crafted repo URL cannot break out of the `<script>` block.
    let scans_json = serde_json::to_string(&scan_list)
        .unwrap_or_else(|_| "[]".to_string())
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026");
    // Scan data goes in last, so text inside it is never substituted again.
    Html(
        include_str!("../templates/index.html")
            .replace("__VERSION__", env!("CARGO_PKG_VERSION"))
            .replace("__SCANS_JSON__", &scans_json),
    )
}

fn pending_scan(id: &str, target: &str) -> ScanResult {
    ScanResult {
        id: id.to_string(),
        repo_url: target.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        total_files: 0,
        scanned_files: 0,
        total_matches: 0,
        risk_score: 0,
        ai_analysis: None,
        rule_matches: Vec::new(),
        triage: None,
        deobfuscation: None,
        emulation: None,
        ttp: None,
        sandbox: None,
        status: "queued".to_string(),
        duration_ms: None,
        iocs: Vec::new(),
    }
}

async fn store_result(state: &AppState, result: ScanResult) {
    // A deleted scan must stay deleted, even if its task finished afterwards.
    // The pending row is written at submit time, so updating no row means the
    // caller deleted it while the scan was running. One UPDATE, not a check
    // and then an upsert: a DELETE landing between the two resurrected it.
    match db::save_scan(&result) {
        Ok(false) => {
            info!("Scan {} was deleted; discarding result", result.id);
            return;
        }
        Ok(true) => {}
        Err(e) => error!("Failed to save scan to DB: {}", e),
    }
    let history_limit = env_u32("KALASCAN_HISTORY_LIMIT", 500);
    if let Err(e) = db::prune_scans(history_limit) {
        warn!("Failed to prune scan history: {}", e);
    }

    let mut scans = state.scans.lock().await;
    if let Some(slot) = scans.iter_mut().find(|s| s.id == result.id) {
        *slot = result;
    } else {
        scans.push(result);
    }
    trim_memory(&mut scans);
}

/// Bound the in-memory scan list; finished scans are re-readable from SQLite.
fn trim_memory(scans: &mut Vec<ScanResult>) {
    let cap = env_u32("KALASCAN_MEMORY_SCANS", 100) as usize;
    if scans.len() <= cap {
        return;
    }
    scans.retain(|s| matches!(s.status.as_str(), "queued" | "running"));
    if scans.len() > cap {
        let excess = scans.len() - cap;
        scans.drain(0..excess);
    }
}

/// Enqueue a scan: register a pending entry, then run the work in the
/// background behind a concurrency permit and a timeout.
async fn spawn_scan(state: AppState, req: ScanRequest, id: String) {
    let work_id = id.clone();
    let work = async move { execute_scan_with_id(req, work_id).await };
    spawn_task(state, id, work).await;
}

async fn spawn_task<F>(state: AppState, id: String, work: F)
where
    F: std::future::Future<Output = anyhow::Result<ScanResult>> + Send + 'static,
{
    let task_state = state.clone();
    let task_id = id.clone();
    let handle = tokio::spawn(async move {
        // Queueing happens here so the HTTP response stays instant.
        let permit = match task_state.scan_slots.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return,
        };
        // Dropped on every exit, abort included.
        let _active = metrics::scan_started();
        {
            let mut scans = task_state.scans.lock().await;
            if let Some(slot) = scans.iter_mut().find(|s| s.id == task_id) {
                slot.status = "running".to_string();
            }
        }

        let started = Instant::now();
        let outcome = tokio::time::timeout(scan_timeout(), work).await;
        drop(permit);
        let duration_ms = started.elapsed().as_millis() as u64;

        let result = match outcome {
            Ok(Ok(result)) => {
                metrics::scan_finished(true, false, duration_ms, result.total_matches as u64);
                result
            }
            Ok(Err(e)) => {
                error!("Scan {} failed: {}", task_id, e);
                metrics::scan_finished(false, false, duration_ms, 0);
                failed_result(&task_state, &task_id, e.to_string()).await
            }
            Err(_) => {
                error!("Scan {} timed out", task_id);
                metrics::scan_finished(false, true, duration_ms, 0);
                failed_result(&task_state, &task_id, "scan timed out".to_string()).await
            }
        };
        let mut result = result;
        result.duration_ms = Some(duration_ms);
        store_result(&task_state, result).await;
        task_state.running.lock().await.remove(&task_id);
    });

    let mut running = state.running.lock().await;
    running.retain(|_, h| !h.is_finished());
    running.insert(id, handle.abort_handle());
}

async fn failed_result(state: &AppState, id: &str, message: String) -> ScanResult {
    let mut failed = pending_scan(id, "");
    {
        let scans = state.scans.lock().await;
        if let Some(prev) = scans.iter().find(|s| s.id == id) {
            failed.repo_url = prev.repo_url.clone();
        }
    }
    failed.status = format!("failed: {}", message);
    failed
}

/// Register a pending scan or reject it when the submission budget is spent.
#[allow(clippy::result_large_err)]
async fn begin_scan(
    state: &AppState,
    req: &ScanRequest,
    actor: &str,
) -> Result<String, axum::response::Response> {
    let allowed = state.submit_budget.lock().await.try_take();
    if !allowed {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "success": false,
                "error": "Scan rate limit exceeded; try again shortly"
            })),
        )
            .into_response());
    }
    let id = uuid::Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now().to_rfc3339();
    let shown = redact_credentials(&req.repo_url);
    state.scans.lock().await.push(pending_scan(&id, &shown));
    // Persist the queued row (with the request) so a restart can resume it.
    if let Err(e) = db::save_pending(&id, req, &timestamp) {
        warn!("Failed to persist pending scan {}: {}", id, e);
    }
    metrics::scan_submitted();
    auth::audit(actor, "scan.submit", Some(&id), Some(&shown));
    Ok(id)
}

/// Shared submit path for both JSON and form endpoints.
/// API callers must not reach the server's own filesystem or config: local
/// paths are scanned in place (their contents come back as finding context),
/// and yara_dir / ignore / baseline / sandbox_image name server-side files or
/// images. Those stay CLI-only; local packages go through the upload route.
fn validate_api_request(req: &ScanRequest) -> Result<(), String> {
    let t = req.repo_url.trim();
    let remote = ["https://", "http://", "ssh://", "git@"]
        .iter()
        .any(|p| t.starts_with(p));
    let marketplace_id = vsix::parse_marketplace_id(t).is_some();
    if !(remote || marketplace_id || vsix::parse_package_target(t).is_some()) {
        return Err(
            "Target must be a remote URL, publisher.extension id, npm:/pypi: package; \
             upload local packages via /api/scan/upload"
                .to_string(),
        );
    }
    let server_paths = [
        ("yara_dir", req.yara_dir.is_some()),
        ("rules_file", req.rules_file.is_some()),
        ("ignore", req.ignore.is_some()),
        ("baseline", req.baseline.is_some()),
        ("sandbox_image", req.sandbox_image.is_some()),
    ];
    if let Some((field, _)) = server_paths.iter().find(|(_, set)| *set) {
        return Err(format!("'{}' is CLI-only", field));
    }
    Ok(())
}

async fn scan_accepted(
    state: &AppState,
    req: ScanRequest,
    actor: &str,
) -> axum::response::Response {
    let checked = match validate_api_request(&req) {
        Ok(()) => check_target_host(&req.repo_url).await,
        Err(e) => Err(e),
    };
    if let Err(error) = checked {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "success": false, "error": error })),
        )
            .into_response();
    }
    let id = match begin_scan(state, &req, actor).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    info!(
        "Queued scan {} for {}",
        id,
        redact_credentials(&req.repo_url)
    );
    spawn_scan(state.clone(), req, id.clone()).await;
    Json(serde_json::json!({
        "success": true,
        "result_id": id,
        "status": "queued"
    }))
    .into_response()
}

async fn api_scan(
    State(state): State<AppState>,
    Extension(principal): Extension<auth::Principal>,
    Json(req): Json<ScanRequest>,
) -> impl IntoResponse {
    scan_accepted(&state, req, &principal.name).await
}

async fn scan_status(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    if let Some(result) = state
        .scans
        .lock()
        .await
        .iter()
        .find(|r| r.id == id)
        .cloned()
    {
        let done = !matches!(result.status.as_str(), "running" | "queued");
        return Json(serde_json::json!({
            "success": true,
            "status": result.status,
            "done": done,
            "result": if done { Some(result) } else { None }
        }))
        .into_response();
    }
    match db::get_scan(&id) {
        Ok(Some(result)) => Json(serde_json::json!({
            "success": true,
            "status": result.status,
            "done": true,
            "result": result
        }))
        .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "success": false, "error": "Scan not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "success": false, "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn get_result(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    // Try in-memory first, then DB
    let scans = state.scans.lock().await;
    if let Some(result) = scans.iter().find(|r| r.id == id) {
        return Json(serde_json::json!({
            "success": true,
            "result": result
        }))
        .into_response();
    }
    drop(scans);

    // Fallback to DB
    match db::get_scan(&id) {
        Ok(Some(result)) => Json(serde_json::json!({
            "success": true,
            "result": result
        }))
        .into_response(),
        Ok(None) | Err(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "success": false,
                "error": "Result not found"
            })),
        )
            .into_response(),
    }
}

async fn history() -> impl IntoResponse {
    match db::list_scans(100) {
        Ok(scan_list) => Json(serde_json::json!({
            "success": true,
            "scans": scan_list
        }))
        .into_response(),
        Err(e) => {
            error!("Failed to list scans: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": "Failed to list scans"
                })),
            )
                .into_response()
        }
    }
}

async fn healthz() -> impl IntoResponse {
    let db_ok = db::list_scans(1).is_ok();
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "db": if db_ok { "ok" } else { "unavailable" },
    }))
}

async fn metrics_endpoint(State(state): State<AppState>) -> impl IntoResponse {
    let pending = state
        .scans
        .lock()
        .await
        .iter()
        .filter(|s| matches!(s.status.as_str(), "queued" | "running"))
        .count();
    let active = metrics::active_scans().max(0) as usize;
    (
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        metrics::render(pending.saturating_sub(active)),
    )
        .into_response()
}

async fn sbom_endpoint(
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    let cwd = std::env::current_dir().unwrap_or_default();
    let root = params
        .get("path")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| cwd.clone());

    let (canon_root, canon_cwd) = match (root.canonicalize(), cwd.canonicalize()) {
        (Ok(r), Ok(c)) => (r, c),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "success": false, "error": "path does not exist" })),
            )
                .into_response();
        }
    };
    // Refuse reads outside the process working directory.
    if !canon_root.starts_with(&canon_cwd) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "success": false, "error": "path is outside the allowed root" })),
        )
            .into_response();
    }

    let packages = cve::extract_manifest_packages(&canon_root);
    let sbom = export::export_cyclonedx(&packages, &canon_root);
    (
        [(
            "content-type",
            "application/vnd.cyclonedx+json; charset=utf-8",
        )],
        sbom,
    )
        .into_response()
}

fn upload_body_limit() -> axum::extract::DefaultBodyLimit {
    match env_u32("KALASCAN_MAX_UPLOAD_MB", 1024) {
        0 => axum::extract::DefaultBodyLimit::disable(),
        mb => axum::extract::DefaultBodyLimit::max(mb as usize * 1024 * 1024),
    }
}

async fn app_css() -> impl IntoResponse {
    (
        [
            ("content-type", "text/css; charset=utf-8"),
            ("cache-control", "public, max-age=3600"),
        ],
        include_str!("../static/app.css"),
    )
        .into_response()
}

async fn openapi_spec() -> impl IntoResponse {
    (
        [("content-type", "application/yaml; charset=utf-8")],
        include_str!("../openapi.yaml").replace("__VERSION__", env!("CARGO_PKG_VERSION")),
    )
        .into_response()
}

async fn audit_log(Extension(principal): Extension<auth::Principal>) -> impl IntoResponse {
    // GET only requires viewer, so the audit trail is additionally gated to
    // admins here: it reveals who did what and when.
    if !principal.role.at_least(auth::Role::Admin) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "success": false, "error": "Admin role required" })),
        )
            .into_response();
    }
    match db::audit_list(200) {
        Ok(entries) => {
            Json(serde_json::json!({ "success": true, "entries": entries })).into_response()
        }
        Err(e) => {
            error!("Failed to read audit log: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "success": false, "error": "Failed to read audit log" })),
            )
                .into_response()
        }
    }
}

async fn report(Path((id, format)): Path<(String, String)>) -> impl IntoResponse {
    match db::get_scan(&id) {
        Ok(Some(result)) => match format.as_str() {
            "md" => {
                let content = export::export_markdown(&result);
                (
                    StatusCode::OK,
                    [("content-type", "text/markdown; charset=utf-8")],
                    content,
                )
                    .into_response()
            }
            "html" => {
                let content = export::export_html(&result);
                (
                    StatusCode::OK,
                    [("content-type", "text/html; charset=utf-8")],
                    content,
                )
                    .into_response()
            }
            "sarif" => {
                let content = export::export_sarif(&result);
                (
                    StatusCode::OK,
                    [("content-type", "application/sarif+json; charset=utf-8")],
                    content,
                )
                    .into_response()
            }
            "csv" => {
                let content = export::export_csv(&result);
                (
                    StatusCode::OK,
                    [
                        ("content-type", "text/csv; charset=utf-8"),
                        ("content-disposition", "attachment; filename=\"report.csv\""),
                    ],
                    content,
                )
                    .into_response()
            }
            "junit" | "junit.xml" => {
                let content = export::export_junit(&result);
                (
                    StatusCode::OK,
                    [("content-type", "application/xml; charset=utf-8")],
                    content,
                )
                    .into_response()
            }
            "github" => {
                let content = export::export_github(&result);
                (
                    StatusCode::OK,
                    [("content-type", "text/plain; charset=utf-8")],
                    content,
                )
                    .into_response()
            }
            _ => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "success": false,
                    "error": "Invalid format. Use 'md', 'html', 'sarif', 'csv', 'junit' or 'github'"
                })),
            )
                .into_response(),
        },
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "success": false,
                "error": "Scan not found"
            })),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to get scan for report: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": "Failed to generate report"
                })),
            )
                .into_response()
        }
    }
}

async fn delete_scan(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Extension(principal): Extension<auth::Principal>,
) -> impl IntoResponse {
    // Cancel queued/running work first; aborting drops the future, which also
    // releases its temp dir and concurrency permit.
    let cancelled = state
        .running
        .lock()
        .await
        .remove(&id)
        .map(|handle| {
            handle.abort();
            true
        })
        .unwrap_or(false);
    if cancelled {
        info!("Cancelled running scan {}", id);
        metrics::scan_cancelled();
    }

    let was_in_memory = {
        let mut scans = state.scans.lock().await;
        let before = scans.len();
        scans.retain(|r| r.id != id);
        scans.len() != before
    };

    // Remove from DB. A cancelled scan may never have been persisted, which is
    // still a successful delete from the caller's perspective.
    match db::delete_scan(&id) {
        Ok(_) => {
            auth::audit(&principal.name, "scan.delete", Some(&id), None);
            Json(serde_json::json!({ "success": true })).into_response()
        }
        Err(e) if was_in_memory || cancelled => {
            info!("Deleted in-memory scan {}: {}", id, e);
            auth::audit(&principal.name, "scan.delete", Some(&id), None);
            Json(serde_json::json!({ "success": true })).into_response()
        }
        Err(e) => {
            error!("Failed to delete scan {}: {}", id, e);
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "success": false,
                    "error": e.to_string()
                })),
            )
                .into_response()
        }
    }
}

/// Old result links: redirect into the dashboard, which loads the result over
/// the authenticated API. Served without auth, so it reads no scan data.
/// Scan ids are UUIDs; anything else is refused rather than escaped, so the
/// id is safe in the page's URL, attribute and script contexts as it is.
async fn results_page(Path(id): Path<String>) -> axum::response::Response {
    if id.is_empty() || id.len() > 64 || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    Html(include_str!("../templates/result.html").replace("__RESULT_ID__", &id)).into_response()
}

async fn api_scan_upload(
    State(state): State<AppState>,
    Extension(principal): Extension<auth::Principal>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut file_name: String = "uploaded.vsix".to_string();
    let mut llm_provider = "ollama".to_string();
    let mut llm_model = "llama3".to_string();
    let mut llm_api_key: Option<String> = None;
    let mut llm_endpoint: Option<String> = None;
    let mut ai_analysis_enabled = false;
    let mut check_cve = true;
    let mut deep_triage = false;
    let mut deobfuscate = false;
    let mut emulate = false;
    let mut sandbox = false;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or_default().to_string();
        if name == "file" {
            if let Some(fname) = field.file_name() {
                file_name = fname.to_string();
            }
            if let Ok(bytes) = field.bytes().await {
                file_bytes = Some(bytes.to_vec());
            }
        } else if name == "llm_provider" {
            if let Ok(val) = field.text().await {
                llm_provider = val;
            }
        } else if name == "llm_model" {
            if let Ok(val) = field.text().await {
                llm_model = val;
            }
        } else if name == "llm_api_key" {
            if let Ok(val) = field.text().await {
                if !val.trim().is_empty() {
                    llm_api_key = Some(val);
                }
            }
        } else if name == "llm_endpoint" {
            if let Ok(val) = field.text().await {
                if !val.trim().is_empty() {
                    llm_endpoint = Some(val);
                }
            }
        } else if name == "ai_analysis_enabled" {
            if let Ok(val) = field.text().await {
                ai_analysis_enabled = val == "true" || val == "1" || val == "on";
            }
        } else if name == "check_cve" {
            if let Ok(val) = field.text().await {
                check_cve = val == "true" || val == "1" || val == "on";
            }
        } else if name == "deep_triage" {
            if let Ok(val) = field.text().await {
                deep_triage = val == "true" || val == "1" || val == "on";
            }
        } else if name == "deobfuscate" {
            if let Ok(val) = field.text().await {
                deobfuscate = val == "true" || val == "1" || val == "on";
            }
        } else if name == "emulate" {
            if let Ok(val) = field.text().await {
                emulate = val == "true" || val == "1" || val == "on";
            }
        } else if name == "sandbox" {
            if let Ok(val) = field.text().await {
                sandbox = val == "true" || val == "1" || val == "on";
            }
        }
        // `sandbox_image` is CLI-only: an API caller must not pick which
        // image the host's Docker daemon runs (see validate_api_request).
    }

    let bytes = match file_bytes {
        Some(b) => b,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "success": false,
                    "error": "No file uploaded"
                })),
            )
                .into_response();
        }
    };

    // Unpacking is blocking I/O + archive parsing; keep it off the async workers.
    let display_name = file_name.clone();
    let unpacked = tokio::task::spawn_blocking(move || {
        let tmp_dir = tempfile::tempdir()?;
        let scan_dir = vsix::extract_zip(&bytes, tmp_dir.path())?;
        Ok::<_, anyhow::Error>((tmp_dir, scan_dir))
    })
    .await;

    let (tmp_dir, scan_dir) = match unpacked {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "success": false,
                    "error": format!("Failed to unpack extension archive: {}", e)
                })),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": format!("Unpack task failed: {}", e)
                })),
            )
                .into_response();
        }
    };
    let req = ScanRequest {
        repo_url: format!("vsix://{}", display_name),
        llm_provider,
        llm_model,
        llm_api_key,
        llm_endpoint,
        ai_analysis_enabled,
        check_cve: Some(check_cve),
        yara_dir: None,
        rules_file: None,
        git_history: false,
        deep_triage,
        deobfuscate,
        emulate,
        sandbox,
        sandbox_image: None,
        new_only: false,
        baseline: None,
        ignore: None,
        changed_only: false,
        base_ref: None,
        third_party: true,
    };

    let scan_id = match begin_scan(&state, &req, &principal.name).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // The temp dir must outlive the scan task; move it into the task.
    let work_id = scan_id.clone();
    let work = async move { execute_scan_in(req, scan_dir, work_id, Some(tmp_dir)).await };
    spawn_task(state.clone(), scan_id.clone(), work).await;

    Json(serde_json::json!({
        "success": true,
        "result_id": scan_id,
        "status": "queued"
    }))
    .into_response()
}

async fn execute_scan(req: ScanRequest) -> anyhow::Result<ScanResult> {
    let id = uuid::Uuid::new_v4().to_string();
    execute_scan_with_id(req, id).await
}

async fn execute_scan_with_id(req: ScanRequest, id: String) -> anyhow::Result<ScanResult> {
    let shown = redact_credentials(&req.repo_url);
    info!("Starting scan for: {}", shown);

    // A local directory is scanned in place (no clone, no temp dir). This keeps
    // PR scans fast and avoids a second clone when the caller already has a
    // checkout. Packages (.vsix/.zip/.jar/.crx) still go through unpacking.
    let local_path = std::path::Path::new(&req.repo_url);
    if local_path.is_dir() && !vsix::is_vsix_target(&req.repo_url) {
        let path = local_path.to_path_buf();
        info!("Scanning local directory {:?} in place", path);
        return execute_scan_in(req, path, id, None).await;
    }

    let tmp_dir = tempfile::tempdir()?;
    let target_dir = tmp_dir.path().join("source");
    std::fs::create_dir_all(&target_dir)?;

    let is_extension = vsix::is_vsix_target(&req.repo_url);
    let scan_dir = if is_extension {
        info!("Target detected as IDE Extension / Package: {}", shown);
        vsix::unpack_extension(&req.repo_url, &target_dir).await?
    } else {
        info!("Cloning {} to {:?}", shown, target_dir);
        let mut clone_cmd = tokio::process::Command::new("git");
        clone_cmd.arg("clone");
        if !req.git_history {
            clone_cmd.arg("--depth").arg("1");
        }
        // The raw URL (credentials included) goes to git only; logs and
        // errors use `shown`. `--`: a repo_url like `--upload-pack=<cmd>`
        // must never parse as an option. kill_on_drop: a timed-out or
        // cancelled scan must not leave git cloning into a deleted temp dir.
        let clone_output = clone_cmd
            .arg("--")
            .arg(&req.repo_url)
            .arg(&target_dir)
            .kill_on_drop(true)
            .output()
            .await
            .map_err(|e| anyhow::anyhow!("Git not found: {}. Install git: brew install git", e))?;

        if !clone_output.status.success() {
            let stderr = redact_credentials(&String::from_utf8_lossy(&clone_output.stderr));
            return Err(anyhow::anyhow!(
                "Git clone failed for {}: {}",
                shown,
                stderr
            ));
        }
        target_dir
    };

    execute_scan_in(req, scan_dir, id, Some(tmp_dir)).await
}

async fn execute_scan_in(
    req: ScanRequest,
    scan_dir: std::path::PathBuf,
    scan_id: String,
    tmp_guard: Option<tempfile::TempDir>,
) -> anyhow::Result<ScanResult> {
    let timestamp = chrono::Utc::now().to_rfc3339();
    let repo_url = redact_credentials(&req.repo_url);
    // The operator's own checkout, scanned in place. Anything cloned,
    // downloaded or uploaded (it has a temp dir) is someone else's code.
    let own_tree = tmp_guard.is_none() && !req.third_party;

    info!(
        "Source ready at {:?}. Running static + YARA + entropy scan...",
        scan_dir
    );

    // Phase 1: optional changed-only filter (PR mode)
    let changed_files = if req.changed_only && !vsix::is_vsix_target(&repo_url) {
        let base = req.base_ref.as_deref().unwrap_or("origin/main");
        info!("Collecting files changed vs {}...", base);
        git_changed_files(&scan_dir, base).await
    } else {
        None
    };

    // Phase 2: Static rule + YARA + Entropy check
    let custom_yara = req.yara_dir.clone().map(std::path::PathBuf::from);
    // Fail the scan on a broken rules file rather than silently matching nothing.
    let extra_rules = match &req.rules_file {
        Some(path) => scanner::load_rules_file(std::path::Path::new(path))?,
        None => Vec::new(),
    };
    let scan_path = scan_dir.clone();
    let changed_clone = changed_files.clone();
    let (total_files, scanned_files, mut rule_matches) = tokio::task::spawn_blocking(move || {
        scanner::scan_directory_filtered(
            &scan_path,
            custom_yara.as_deref(),
            &extra_rules,
            changed_clone.as_ref(),
            own_tree,
        )
    })
    .await
    .map_err(|e| anyhow::anyhow!("Scanner task failed: {}", e))?;

    // Phase 2b: offline typo-squat check, then dependency CVEs via OSV if enabled
    let pkgs = cve::extract_manifest_packages(&scan_dir);
    rule_matches.extend(cve::typosquat_matches(&pkgs));
    rule_matches.extend(cve::own_package_matches(&scan_dir));
    rule_matches.extend(reputation::identity_matches(&scan_dir));
    if let Some((publisher, name, _)) = vsix::parse_marketplace_id(&repo_url) {
        rule_matches.extend(reputation::marketplace_matches(publisher, name).await);
    }

    // IOCs, and exact-URL threat intel when an abuse.ch key is configured.
    let ioc_dir = scan_dir.clone();
    let iocs = tokio::task::spawn_blocking(move || iocs::extract(&ioc_dir, own_tree))
        .await
        .unwrap_or_default();
    if let Ok(key) = std::env::var("URLHAUS_AUTH_KEY") {
        if !key.trim().is_empty() && !iocs.is_empty() {
            info!("Checking {} IOCs against URLhaus...", iocs.len().min(100));
            rule_matches.extend(iocs::urlhaus_matches(&iocs, key.trim()).await);
        }
    }
    if req.check_cve.unwrap_or(true) && !pkgs.is_empty() {
        info!("Auditing {} manifest packages with OSV API...", pkgs.len());
        let cve_matches = cve::check_vulnerabilities(&pkgs).await;
        rule_matches.extend(cve_matches);
    }

    // Cross-file chains, once every current-tree finding is in (history hits
    // are old snapshots and must not complete a chain).
    let chains =
        correlate::correlate_package_with(&rule_matches, !cve::is_vscode_extension(&scan_dir));
    rule_matches.extend(chains);

    // Phase 2c: Full git commit history scan
    if req.git_history && !vsix::is_vsix_target(&repo_url) {
        info!("Scanning full git commit history at {:?}...", scan_dir);
        let history_matches = git_history::scan_git_history(&scan_dir).await;
        info!("Git history scan found {} matches", history_matches.len());
        rule_matches.extend(history_matches);
    }

    // Phase 2d: baseline / ignore filtering (CI mode)
    let ignore_path = req
        .ignore
        .as_ref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(".kalascanignore"));
    let ignore_set = baseline::IgnoreSet::load(&ignore_path);
    if !ignore_set.is_empty() {
        info!("Applying ignore rules from {:?}", ignore_path);
    }
    let baseline_set = match req.baseline.as_ref() {
        Some(p) if req.new_only => {
            let set = baseline::load_baseline(std::path::Path::new(p))?;
            info!("Loaded {} baselined findings from {}", set.len(), p);
            Some(set)
        }
        _ => None,
    };
    let total_before_filter = rule_matches.len();
    rule_matches = baseline::apply_filters(rule_matches, &ignore_set, baseline_set.as_ref());
    if total_before_filter != rule_matches.len() {
        info!(
            "Filtered {} findings (ignored/baselined); {} remain",
            total_before_filter - rule_matches.len(),
            rule_matches.len()
        );
    }

    info!(
        "Scan complete: {} files scanned, {} matches found",
        scanned_files,
        rule_matches.len()
    );

    // Phase 2d: Deep static binary triage
    info!("Running static binary triage...");
    let triage_report = triage::analyze_directory(&scan_dir, &rule_matches, req.deep_triage).await;

    let deobfuscation_report = if req.deobfuscate {
        info!("Running recursive deobfuscation...");
        Some(deobfuscate::analyze_directory(&scan_dir))
    } else {
        None
    };

    let emulation_report = if req.emulate {
        info!("Running bounded static emulation...");
        Some(emulate::analyze_triage(&scan_dir, &triage_report))
    } else {
        None
    };

    let sandbox_report = if req.sandbox {
        info!("Running Docker-isolated sandbox execution...");
        let config = sandbox::SandboxConfig {
            image: req
                .sandbox_image
                .clone()
                .unwrap_or_else(|| "kalascan-sandbox:latest".to_string()),
            ..Default::default()
        };
        Some(sandbox::analyze_triage(&scan_dir, &triage_report, &config).await)
    } else {
        None
    };

    let ttp_report = ttp::build(
        &rule_matches,
        Some(&triage_report),
        deobfuscation_report.as_ref(),
        emulation_report.as_ref(),
        sandbox_report.as_ref(),
    );

    // Phase 3: AI analysis
    let ai_result = if req.ai_analysis_enabled && !rule_matches.is_empty() {
        info!("Running AI deep analysis...");

        let context_snippets: Vec<String> = rule_matches
            .iter()
            .map(|m| {
                format!(
                    "File: {}\nLine {}: {}\nContext: {}",
                    m.file_path, m.line_number, m.matched_pattern, m.context
                )
            })
            .collect();

        let combined_prompt = context_snippets.join("\n\n---\n\n");

        let analysis = ai_analyzer::analyze_with_llm(
            &req.llm_provider,
            &req.llm_model,
            &req.llm_api_key,
            &req.llm_endpoint,
            &combined_prompt,
        )
        .await;

        match analysis {
            Ok(a) => Some(a),
            Err(e) => {
                error!("AI analysis error: {}", e);
                None
            }
        }
    } else {
        None
    };

    let risk_score = calculate_risk_score(
        &rule_matches,
        &ai_result,
        Some(&triage_report),
        deobfuscation_report.as_ref(),
        emulation_report.as_ref(),
        sandbox_report.as_ref(),
    );

    let result = ScanResult {
        id: scan_id.clone(),
        repo_url,
        timestamp,
        total_files,
        scanned_files,
        total_matches: rule_matches.len(),
        risk_score,
        ai_analysis: ai_result,
        rule_matches,
        triage: Some(triage_report),
        deobfuscation: deobfuscation_report,
        emulation: emulation_report,
        ttp: Some(ttp_report),
        sandbox: sandbox_report,
        status: "completed".to_string(),
        duration_ms: None,
        iocs,
    };

    info!("Scan complete. ID: {}", scan_id);

    Ok(result)
}

/// Resolve the set of files changed between `base_ref` and HEAD inside a clone.
/// Returns `None` on any failure so callers fall back to a full scan.
async fn git_changed_files(
    repo: &std::path::Path,
    base_ref: &str,
) -> Option<std::collections::HashSet<std::path::PathBuf>> {
    // base_ref comes from the API request and is passed to `git fetch` / `git
    // diff` as a positional arg; `--upload-pack=<cmd>` would run a command.
    if base_ref.starts_with('-') {
        warn!("Rejected base_ref {:?}: looks like a git option", base_ref);
        return None;
    }

    // Try to make the base ref available in shallow clones. Ignore failures:
    // the ref may already exist locally.
    let remote_ref = base_ref.strip_prefix("origin/").unwrap_or(base_ref);
    let fetched = tokio::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["fetch", "--depth", "1", "origin", remote_ref])
        .kill_on_drop(true)
        .output()
        .await;

    let run_diff = |range: &str| {
        let repo = repo.to_path_buf();
        let range = range.to_string();
        async move {
            tokio::process::Command::new("git")
                .arg("-C")
                .arg(repo)
                .args(["diff", "--name-only", &range])
                .kill_on_drop(true)
                .output()
                .await
                .ok()
        }
    };

    let range = format!("{}...HEAD", base_ref);
    let output = run_diff(&range).await?;
    // Shallow-clone fallback: diff against the freshly fetched FETCH_HEAD.
    let output = if output.status.success() {
        output
    } else if fetched.as_ref().is_ok_and(|f| f.status.success()) {
        run_diff("FETCH_HEAD...HEAD").await?
    } else {
        output
    };
    if !output.status.success() {
        info!(
            "git diff against {} failed; falling back to full scan",
            base_ref
        );
        return None;
    }

    let changed: std::collections::HashSet<std::path::PathBuf> =
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(std::path::PathBuf::from)
            .collect();

    if changed.is_empty() {
        info!("No changed files vs {}; nothing to scan", base_ref);
        return None;
    }
    info!("Restricting scan to {} changed files", changed.len());
    Some(changed)
}

async fn requeue_pending(state: &AppState) {
    match db::pending_scans(10_000) {
        Ok(pending) => {
            for (id, req) in pending {
                info!("Requeuing interrupted scan {} ({})", id, req.repo_url);
                state
                    .scans
                    .lock()
                    .await
                    .push(pending_scan(&id, &req.repo_url));
                spawn_scan(state.clone(), req, id).await;
            }
        }
        Err(e) => error!("Failed to list pending scans for requeue: {}", e),
    }
}

fn run_user_command(action: UserAction) -> anyhow::Result<()> {
    db::init_db()?;
    match action {
        UserAction::Add { name, role } => {
            let role = auth::Role::parse(&role).ok_or_else(|| {
                anyhow::anyhow!("Invalid role '{}'; use viewer, operator or admin", role)
            })?;
            match auth::create_user(&name, role) {
                Ok(token) => {
                    auth::audit("cli", "user.add", Some(&name), None);
                    println!(
                        "User '{}' created ({}).\n\nToken (store it now; it is not shown again):\n\n  {}",
                        name,
                        role.as_str(),
                        token
                    );
                }
                Err(e) => anyhow::bail!("Failed to create user '{}': {}", name, e),
            }
        }
        UserAction::List => {
            let users = auth::list_users()?;
            if users.is_empty() {
                println!("No users yet. Create one with: kalascan user add <name> --role operator");
                return Ok(());
            }
            for u in users {
                println!(
                    "{:8} {} (created {}, last used {})",
                    u.role,
                    u.name,
                    u.created_at,
                    u.last_used_at.as_deref().unwrap_or("never")
                );
            }
        }
        UserAction::Remove { name } => {
            if auth::remove_user(&name)? {
                auth::audit("cli", "user.remove", Some(&name), None);
                println!("User '{}' removed", name);
            } else {
                eprintln!("User '{}' not found", name);
                std::process::exit(2);
            }
        }
    }
    Ok(())
}

fn run_sbom_command(
    path: &std::path::Path,
    output: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    if !path.is_dir() {
        anyhow::bail!("{} is not a directory", path.display());
    }
    let packages = cve::extract_manifest_packages(path);
    let sbom = export::export_cyclonedx(&packages, path);
    match output {
        Some(out) => {
            std::fs::write(out, &sbom)?;
            println!(
                "SBOM written to {} ({} components)",
                out.display(),
                packages.len()
            );
        }
        None => println!("{}", sbom),
    }
    Ok(())
}

async fn run_installed_command(
    format: &str,
    min_risk: u8,
    fail_on_risk: Option<u8>,
    jobs: usize,
) -> anyhow::Result<()> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or_else(|| anyhow::anyhow!("cannot locate the home directory"))?;
    let found = installed::discover(std::path::Path::new(&home));
    eprintln!("Scanning {} installed extensions...", found.len());

    let permits = Arc::new(tokio::sync::Semaphore::new(jobs.max(1)));
    let mut tasks = tokio::task::JoinSet::new();
    for ext in found {
        let permits = permits.clone();
        tasks.spawn(async move {
            let _permit = permits.acquire_owned().await;
            // Offline and in place: no OSV calls, nothing copied or executed.
            let mut req: ScanRequest = serde_json::from_value(serde_json::json!({
                "repo_url": ext.path.to_string_lossy(),
                "check_cve": false,
            }))
            .expect("static request");
            req.third_party = true;
            (ext, execute_scan(req).await)
        });
    }
    let mut rows = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        let (ext, result) = joined?;
        match result {
            Ok(r) => rows.push((ext, r)),
            Err(e) => eprintln!("  failed {}: {}", ext.path.display(), e),
        }
    }
    rows.sort_by(|a, b| {
        b.1.risk_score
            .cmp(&a.1.risk_score)
            .then(a.0.name.cmp(&b.0.name))
    });

    let strong = |r: &ScanResult| -> Vec<String> {
        let mut names: Vec<String> = r
            .rule_matches
            .iter()
            .filter(|m| {
                m.severity == "critical" || m.matched_pattern.starts_with(correlate::CHAIN_PREFIX)
            })
            .map(|m| m.matched_pattern.clone())
            .collect();
        names.sort();
        names.dedup();
        names
    };
    let shown: Vec<_> = rows
        .iter()
        .filter(|(_, r)| r.risk_score >= min_risk)
        .collect();
    if format == "json" {
        let out: Vec<_> = shown
            .iter()
            .map(|(ext, r)| {
                serde_json::json!({
                    "app": ext.app,
                    "extension": ext.name,
                    "path": ext.path,
                    "risk_score": r.risk_score,
                    "critical": strong(r),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!(
            "{:>4}  {:<16} {:<48} CRITICAL FINDINGS",
            "RISK", "APP", "EXTENSION"
        );
        for (ext, r) in &shown {
            println!(
                "{:>4}  {:<16} {:<48} {}",
                r.risk_score,
                ext.app,
                ext.name,
                strong(r).join(", ")
            );
        }
    }
    if let Some(threshold) = fail_on_risk {
        if rows.iter().any(|(_, r)| r.risk_score >= threshold) {
            std::process::exit(1);
        }
    }
    Ok(())
}

async fn run_diff_command(
    old: &str,
    new: &str,
    format: &str,
    fail_on_new: Option<&str>,
    cve: bool,
) -> anyhow::Result<()> {
    let request = |target: &str| -> anyhow::Result<ScanRequest> {
        Ok(serde_json::from_value(serde_json::json!({
            "repo_url": target,
            "check_cve": cve,
        }))?)
    };
    // Sequential: both may download from the same registry.
    let old_result = execute_scan(request(old)?).await?;
    let new_result = execute_scan(request(new)?).await?;
    let d = diff::diff(&old_result, &new_result);
    match format {
        "json" => println!("{}", serde_json::to_string_pretty(&d)?),
        _ => print!("{}", diff::format_text(&d)),
    }
    if let Some(threshold) = fail_on_new {
        if !["critical", "high", "medium", "low"].contains(&threshold) {
            anyhow::bail!("--fail-on-new must be critical, high, medium or low");
        }
        let limit = diff::severity_rank(threshold);
        if d.new_capabilities
            .iter()
            .any(|c| diff::severity_rank(&c.severity) <= limit)
        {
            eprintln!("New capability at or above '{}' severity", threshold);
            std::process::exit(1);
        }
    }
    Ok(())
}

fn run_rules_command(name: Option<String>) -> anyhow::Result<()> {
    let rules = scanner::build_rules();
    match name {
        Some(query) => {
            let q = query.to_lowercase();
            let matches: Vec<_> = rules
                .iter()
                .filter(|r| r.name.to_lowercase().contains(&q) || r.id.to_lowercase() == q)
                .collect();
            match matches.as_slice() {
                [rule] => {
                    println!(
                        "Rule: {} {}  [{}, {}]",
                        rule.id, rule.name, rule.severity, rule.category
                    );
                    println!("Ruleset: {}", scanner::RULESET_VERSION);
                    println!();
                    println!("{}", rule.description);
                    println!();
                    println!("Pattern: {}", rule.pattern.as_str());
                }
                [] => {
                    eprintln!(
                        "Unknown rule '{}'. Use `kalascan rules` to list rules.",
                        query
                    );
                    std::process::exit(2);
                }
                many => {
                    eprintln!("'{}' is ambiguous; matches:", query);
                    for r in many {
                        println!("  {}", r.name);
                    }
                    std::process::exit(2);
                }
            }
        }
        None => {
            println!("Ruleset version: {}", scanner::RULESET_VERSION);
            println!(
                "{:<11} {:8}  {:<34} {:<14} DESCRIPTION",
                "ID", "SEVERITY", "RULE", "CATEGORY"
            );
            for r in rules.iter() {
                let desc = if r.description.len() > 50 {
                    format!("{}…", r.description.chars().take(50).collect::<String>())
                } else {
                    r.description.to_string()
                };
                println!(
                    "{:<11} {:8}  {:<34} {:<14} {}",
                    r.id, r.severity, r.name, r.category, desc
                );
            }
        }
    }
    Ok(())
}

async fn run_cli_scan(
    req: ScanRequest,
    format: String,
    fail_on_risk: Option<u8>,
    output: Option<std::path::PathBuf>,
    baseline_out: Option<std::path::PathBuf>,
) -> anyhow::Result<()> {
    let result = execute_scan(req).await?;

    // `--update-baseline` (exclusive with --new-only, so these are all findings).
    if let Some(path) = baseline_out {
        baseline::save_baseline(&path, &result.rule_matches)?;
        eprintln!(
            "Baseline updated at {} ({} findings)",
            path.display(),
            result.rule_matches.len()
        );
    }

    let output_content = match format.to_lowercase().as_str() {
        "json" => serde_json::to_string_pretty(&result)?,
        "md" | "markdown" => export::export_markdown(&result),
        "html" => export::export_html(&result),
        "sarif" => export::export_sarif(&result),
        "csv" => export::export_csv(&result),
        "junit" | "junit.xml" => export::export_junit(&result),
        "github" => export::export_github(&result),
        _ => format_cli_text(&result),
    };

    if let Some(out_path) = output {
        std::fs::write(&out_path, &output_content)?;
        println!("Report successfully saved to: {:?}", out_path);
    } else {
        println!("{}", output_content);
    }

    if let Some(threshold) = fail_on_risk {
        if result.risk_score >= threshold {
            eprintln!(
                "\n❌ Quality Gate Failed: Risk score {} >= threshold {}",
                result.risk_score, threshold
            );
            std::process::exit(1);
        }
    }

    Ok(())
}

fn format_cli_text(result: &ScanResult) -> String {
    let mut out = String::new();
    out.push_str("============================================================\n");
    out.push_str("🛡️  KalaScan Security & Malware Audit Report\n");
    out.push_str("============================================================\n");
    out.push_str(&format!("Target:        {}\n", result.repo_url));
    out.push_str(&format!("Scan ID:       {}\n", result.id));
    out.push_str(&format!("Timestamp:     {}\n", result.timestamp));
    out.push_str(&format!(
        "Files Scanned: {} / {}\n",
        result.scanned_files, result.total_files
    ));
    out.push_str(&format!("Total Matches: {}\n", result.total_matches));

    let level = match export::risk_score_to_level(result.risk_score) {
        "danger" => "🔴 HIGH RISK (Possible Malware)",
        "warning" => "🟡 WARNING (Suspicious)",
        _ => "🟢 SAFE",
    };
    out.push_str(&format!(
        "Risk Score:    {} / 100 [{}]\n",
        result.risk_score, level
    ));
    out.push_str("------------------------------------------------------------\n");

    if result.rule_matches.is_empty() {
        out.push_str("No malicious patterns or high-risk vulnerabilities detected.\n");
    } else {
        out.push_str("FINDINGS:\n");
        for (i, m) in result.rule_matches.iter().enumerate() {
            out.push_str(&format!(
                "\n[{}] [{}] {}\n     File:    {}:{}\n     Context: {}\n",
                i + 1,
                m.severity.to_uppercase(),
                m.matched_pattern,
                m.file_path,
                m.line_number,
                m.context.trim()
            ));
        }
    }

    if let Some(ai) = &result.ai_analysis {
        out.push_str("\n------------------------------------------------------------\n");
        out.push_str("AI DEEP ANALYSIS:\n");
        out.push_str(&format!("Malware Type:   {}\n", ai.malware_type));
        out.push_str(&format!("Threat Summary: {}\n", ai.threat_summary));
        out.push_str(&format!("Recommendation: {}\n", ai.recommendation));
    }

    if let Some(triage) = &result.triage {
        out.push_str("\n------------------------------------------------------------\n");
        out.push_str("DEEP STATIC TRIAGE:\n");
        out.push_str(&format!("Files Analyzed: {}\n", triage.files_scanned));
        out.push_str(&format!("Binaries:       {}\n", triage.binaries.len()));
        out.push_str(&format!("Capabilities:   {}\n", triage.capabilities.len()));
        out.push_str(&format!(
            "ATT&CK Techniques: {}\n",
            triage.attack_techniques.len()
        ));
        if triage.deep {
            let available: Vec<String> = triage
                .tools
                .iter()
                .filter(|tool| tool.available)
                .map(|tool| tool.name.clone())
                .collect();
            out.push_str(&format!(
                "Deep Tools:     {}\n",
                if available.is_empty() {
                    "none available".to_string()
                } else {
                    available.join(", ")
                }
            ));
        }
        for binary in &triage.binaries {
            out.push_str(&format!(
                "\nBinary: {} [{} {}] entropy {:.2}\n",
                binary.path,
                binary.file_type,
                binary.architecture.as_deref().unwrap_or("unknown"),
                binary.entropy
            ));
            out.push_str(&format!("  SHA-256: {}\n", binary.sha256));
            if let Some(packer) = &binary.packer {
                out.push_str(&format!(
                    "  Packer:  {} ({}) - {}\n",
                    packer.name, packer.confidence, packer.evidence
                ));
            }
            if !binary.indicators.is_empty() {
                out.push_str(&format!("  Indicators: {}\n", binary.indicators.join("; ")));
            }
        }
        if !triage.attack_techniques.is_empty() {
            out.push_str("\nATT&CK Techniques:\n");
            for technique in &triage.attack_techniques {
                out.push_str(&format!(
                    "  {} {} [{}]\n",
                    technique.id, technique.name, technique.tactic
                ));
            }
        }
    }

    if let Some(deobfuscation) = &result.deobfuscation {
        out.push_str("\n------------------------------------------------------------\n");
        out.push_str("DEOBFUSCATION:\n");
        out.push_str(&format!(
            "Files Analyzed: {}\n",
            deobfuscation.files_scanned
        ));
        out.push_str(&format!(
            "Artifacts:      {}\n",
            deobfuscation.artifacts.len()
        ));
        for artifact in &deobfuscation.artifacts {
            out.push_str(&format!(
                "\n[{}] {}:{} ({})\n",
                artifact.confidence.to_uppercase(),
                artifact.file_path,
                artifact.line_number,
                artifact.encoding
            ));
            out.push_str(&format!(
                "  Decoded: {}\n",
                artifact.decoded.replace('\n', " ")
            ));
            if !artifact.indicators.is_empty() {
                out.push_str(&format!(
                    "  Indicators: {}\n",
                    artifact.indicators.join("; ")
                ));
            }
        }
    }

    if let Some(emulation) = &result.emulation {
        out.push_str("\n------------------------------------------------------------\n");
        out.push_str("SAFE STATIC EMULATION:\n");
        out.push_str(&format!("Files Analyzed: {}\n", emulation.files_scanned));
        out.push_str(&format!("Traces:         {}\n", emulation.traces.len()));
        for trace in &emulation.traces {
            out.push_str(&format!(
                "\n{} [{}] entry {} instructions {}\n",
                trace.file_path, trace.architecture, trace.entrypoint, trace.instructions
            ));
            out.push_str(&format!("  Stopped: {}\n", trace.stopped_reason));
            if !trace.api_calls.is_empty() {
                out.push_str(&format!("  API Calls: {}\n", trace.api_calls.join(", ")));
            }
            if !trace.recovered_strings.is_empty() {
                out.push_str(&format!(
                    "  Recovered Strings: {}\n",
                    trace.recovered_strings.join(" | ")
                ));
            }
            if !trace.indicators.is_empty() {
                out.push_str(&format!("  Indicators: {}\n", trace.indicators.join("; ")));
            }
        }
    }

    if let Some(sandbox) = &result.sandbox {
        out.push_str("\n------------------------------------------------------------\n");
        out.push_str("DOCKER SANDBOX:\n");
        out.push_str(&format!(
            "Available:      {}\n",
            if sandbox.available { "yes" } else { "no" }
        ));
        out.push_str(&format!("Image:          {}\n", sandbox.image));
        out.push_str(&format!("Files Analyzed: {}\n", sandbox.files_analyzed));
        out.push_str(&format!("Executions:     {}\n", sandbox.executions.len()));
        for execution in &sandbox.executions {
            out.push_str(&format!(
                "\n{} [{}] exit {:?} in {}ms ({} syscalls)\n",
                execution.file_path,
                execution.architecture,
                execution.exit_code,
                execution.duration_ms,
                execution.syscalls
            ));
            if execution.timed_out {
                out.push_str("  Timed out: yes\n");
            }
            if !execution.processes.is_empty() {
                out.push_str(&format!(
                    "  Processes: {}\n",
                    execution.processes.join(", ")
                ));
            }
            if !execution.network_attempts.is_empty() {
                out.push_str(&format!(
                    "  Network Attempts: {}\n",
                    execution.network_attempts.join(" | ")
                ));
            }
            if !execution.file_accesses.is_empty() {
                out.push_str(&format!(
                    "  Sensitive Files: {}\n",
                    execution.file_accesses.join(" | ")
                ));
            }
            if !execution.indicators.is_empty() {
                out.push_str(&format!(
                    "  Indicators: {}\n",
                    execution.indicators.join("; ")
                ));
            }
        }
        for note in &sandbox.notes {
            out.push_str(&format!("  Note: {}\n", note));
        }
    }

    if let Some(ttp) = &result.ttp {
        out.push_str("\n------------------------------------------------------------\n");
        out.push_str("TTP / ATT&CK COVERAGE:\n");
        out.push_str(&format!(
            "Techniques:     {}\nTactics:        {}\nCoverage:       {}%\n",
            ttp.techniques.len(),
            ttp.tactics.len(),
            ttp.coverage_score
        ));
        for technique in &ttp.techniques {
            out.push_str(&format!(
                "\n[{}] {} {} [{}] ({} observations)\n",
                technique.severity.to_uppercase(),
                technique.id,
                technique.name,
                technique.tactic,
                technique.observations
            ));
            out.push_str(&format!("  Sources: {}\n", technique.sources.join(", ")));
        }
        if !ttp.tactics.is_empty() {
            out.push_str("\nKill Chain:\n");
            for tactic in &ttp.tactics {
                out.push_str(&format!(
                    "  {}: {}\n",
                    tactic.tactic,
                    tactic.techniques.join(", ")
                ));
            }
        }
    }

    if !result.iocs.is_empty() {
        out.push_str("------------------------------------------------------------\n");
        out.push_str(&format!(
            "INDICATORS ({} external URLs / IPs):\n",
            result.iocs.len()
        ));
        for ioc in result.iocs.iter().take(30) {
            out.push_str(&format!(
                "  [{}] {}  ({})\n",
                ioc.kind,
                ioc.value,
                ioc.files.join(", ")
            ));
        }
        if result.iocs.len() > 30 {
            out.push_str("  … see --format json for the full list\n");
        }
    }

    out.push_str("============================================================\n");
    out
}

fn calculate_risk_score(
    matches: &[RuleMatch],
    ai: &Option<AiAnalysis>,
    triage: Option<&triage::TriageReport>,
    deobfuscation: Option<&deobfuscate::DeobfuscationReport>,
    emulation: Option<&emulate::EmulationReport>,
    sandbox: Option<&sandbox::SandboxReport>,
) -> u8 {
    use std::collections::HashSet;

    // Count each (file, rule) pair once: the same regex firing 40 times in a
    // minified bundle is one finding, not 40. The old code added every hit at
    // full weight, so a legitimate extension with a few hundred benign matches
    // saturated the static cap by itself and every later pass pushed it to 100.
    let mut seen: HashSet<(&str, &str)> = HashSet::new();
    let (mut critical, mut high, mut medium, mut cve) = (0u16, 0u16, 0u16, 0u16);

    for m in matches {
        // History hits (`<hash>:<path>`) count as the file they belong to.
        let file = git_history::tree_path(&m.file_path);
        if !seen.insert((file, m.matched_pattern.as_str())) {
            continue;
        }
        if m.matched_pattern.starts_with("Known Vulnerability:") {
            cve += 1;
            continue;
        }
        // A chain is two corroborating hard signals by construction. Listing
        // spoofs (invisible characters, look-alike publisher, a popular
        // extension's repository under a stranger's name) have no benign
        // reading at all, so they weigh the same.
        if m.matched_pattern.starts_with(correlate::CHAIN_PREFIX)
            || m.matched_pattern == reputation::INVISIBLE_NAME
            || m.matched_pattern == reputation::PUBLISHER_LOOKALIKE
            || m.matched_pattern == reputation::REPACKAGED_COPY
            || m.matched_pattern == iocs::URLHAUS_HIT
        {
            critical += 2;
            continue;
        }
        match m.severity.as_str() {
            "critical" => critical += 1,
            "high" => high += 1,
            "medium" => medium += 1,
            _ => {}
        }
    }

    // Hard signals dominate (exfil endpoints, encoded commands). Soft ones
    // (`process.env`, loopback IPs, `exec()` in a Python extension) are
    // ubiquitous in legitimate code, so they saturate quickly.
    let static_score = (critical * 35).min(70) + (high * 5).min(15) + medium.min(5);

    // Vulnerable dependencies are a hygiene issue, not malware evidence.
    let cve_score = cve.min(5);

    // The deep passes overlap heavily. One shared budget keeps them from
    // stacking five separate ceilings on the same evidence.
    let dynamic = triage.map_or(0, |r| triage::risk_contribution(r) as u16)
        + deobfuscation.map_or(0, |r| deobfuscate::risk_contribution(r) as u16)
        + emulation.map_or(0, |r| emulate::risk_contribution(r) as u16)
        + sandbox.map_or(0, |r| sandbox::risk_contribution(r) as u16);
    let dynamic_score = dynamic.min(20);

    // AI corroborates the static result; a benign verdict never raises it.
    // TTP is derived from the matches above, so it is reported but not scored
    // twice.
    let ai_score = ai.as_ref().map_or(0, |a| {
        if a.is_malicious {
            (a.risk_score as u16 / 2).min(25)
        } else {
            0
        }
    });

    (static_score + cve_score + dynamic_score + ai_score).min(100) as u8
}

#[cfg(test)]
mod api_validation_tests {
    use super::*;

    fn req(repo_url: &str, extra: serde_json::Value) -> ScanRequest {
        let mut v = serde_json::json!({ "repo_url": repo_url });
        v.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn api_accepts_remote_targets_only() {
        for ok in [
            "https://github.com/user/repo",
            "git@github.com:user/repo.git",
            "ms-python.python",
            "npm:express@4.17.1",
            "pypi:requests",
            "https://open-vsx.org/extension/ns/name",
        ] {
            assert!(
                validate_api_request(&req(ok, serde_json::json!({}))).is_ok(),
                "{}",
                ok
            );
        }
        for bad in [
            "/",
            "/root/.ssh",
            "./",
            "..",
            "src",
            "file:///etc",
            "evil.vsix",
            "/tmp/x.zip",
            "--upload-pack=x",
        ] {
            assert!(
                validate_api_request(&req(bad, serde_json::json!({}))).is_err(),
                "{}",
                bad
            );
        }
    }

    #[test]
    fn api_rejects_server_side_paths() {
        for field in [
            "yara_dir",
            "rules_file",
            "ignore",
            "baseline",
            "sandbox_image",
        ] {
            let r = req(
                "https://github.com/a/b",
                serde_json::json!({ field: "/etc" }),
            );
            assert_eq!(
                validate_api_request(&r).unwrap_err(),
                format!("'{}' is CLI-only", field)
            );
        }
    }
}

#[cfg(test)]
mod git_injection_tests {
    use super::*;

    fn git(dir: &std::path::Path, args: &[&str]) {
        let ok = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .unwrap()
            .status
            .success();
        assert!(ok, "git {:?} failed", args);
    }

    /// A clone with a real `origin`, so an injected `--upload-pack` would run.
    fn repo_with_origin() -> (tempfile::TempDir, std::path::PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let origin = tmp.path().join("origin");
        std::fs::create_dir(&origin).unwrap();
        git(&origin, &["init", "-q"]);
        std::fs::write(origin.join("a.txt"), "x").unwrap();
        git(&origin, &["add", "."]);
        git(
            &origin,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "commit",
                "-qm",
                "init",
            ],
        );
        git(tmp.path(), &["clone", "-q", "origin", "clone"]);
        let clone = tmp.path().join("clone");
        (tmp, clone)
    }

    #[tokio::test]
    async fn base_ref_cannot_inject_git_options() {
        let (tmp, clone) = repo_with_origin();
        let marker = tmp.path().join("pwned");
        let evil = format!("--upload-pack=touch {}", marker.display());
        assert!(git_changed_files(&clone, &evil).await.is_none());
        assert!(!marker.exists(), "injected --upload-pack ran");
    }

    #[tokio::test]
    async fn repo_url_cannot_inject_git_options() {
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("pwned");
        let req: ScanRequest = serde_json::from_value(serde_json::json!({
            "repo_url": format!("--upload-pack=touch {}", marker.display()),
            "ai_analysis_enabled": false,
            "llm_provider": "ollama",
            "llm_model": "llama3"
        }))
        .unwrap();
        assert!(execute_scan(req).await.is_err());
        assert!(!marker.exists(), "injected --upload-pack ran");
    }
}

#[cfg(test)]
mod risk_score_tests {
    use super::*;

    fn hit(file: &str, rule: &str, severity: &str) -> RuleMatch {
        RuleMatch {
            file_path: file.to_string(),
            line_number: 1,
            matched_pattern: rule.to_string(),
            severity: severity.to_string(),
            context: String::new(),
        }
    }

    fn benign_ai() -> Option<AiAnalysis> {
        Some(AiAnalysis {
            is_malicious: false,
            risk_score: 15,
            malware_type: "None".to_string(),
            threat_summary: String::new(),
            suspicious_lines: Vec::new(),
            recommendation: String::new(),
        })
    }

    #[test]
    fn repeated_benign_hits_do_not_reach_high_risk() {
        // Real case: legitimate Python extension, 310 files, 570 matches and
        // 14 CVEs, AI says benign — the score was pinned at 100.
        let mut matches = Vec::new();
        for file in 0..300 {
            for rule in ["Environment Variable Dump", "Hardcoded IP Address"] {
                for line in 0..3 {
                    let mut m = hit(&format!("out/{}", file), rule, "medium");
                    m.line_number = line;
                    matches.push(m);
                }
            }
            matches.push(hit(&format!("out/{}", file), "exec() Usage", "high"));
        }
        for id in 0..14 {
            matches.push(hit(
                "package.json",
                &format!("Known Vulnerability: GHSA-{} in lodash@4.17.15", id),
                "high",
            ));
        }

        let score = calculate_risk_score(&matches, &benign_ai(), None, None, None, None);
        assert!(score < 70, "benign extension scored {}", score);
    }

    #[test]
    fn single_hit_per_rule_per_file() {
        let many: Vec<_> = (0..50)
            .map(|_| hit("a.js", "Environment Variable Dump", "medium"))
            .collect();
        let one = vec![hit("a.js", "Environment Variable Dump", "medium")];
        assert_eq!(
            calculate_risk_score(&many, &None, None, None, None, None),
            calculate_risk_score(&one, &None, None, None, None, None)
        );
    }

    #[test]
    fn real_malware_chain_stays_high_risk() {
        let matches = vec![
            hit("out/extension.js", "Discord Webhook", "critical"),
            hit("out/extension.js", "SSH Key Access", "high"),
            hit("out/extension.js", "exec() Usage", "high"),
            hit("out/extension.js", "Environment Variable Dump", "medium"),
        ];
        let score = calculate_risk_score(&matches, &benign_ai(), None, None, None, None);
        assert!(score >= 40, "malware chain scored {}", score);
    }

    #[test]
    fn malicious_package_scores_as_critical_not_hygiene() {
        let vuln = vec![hit(
            "requirements.txt",
            "Known Vulnerability: GHSA-x in requests@2.25.1",
            "high",
        )];
        let mal = vec![hit(
            "requirements.txt",
            "Malicious Package: MAL-2024-1 in evilpkg@1.0",
            "critical",
        )];
        assert_eq!(
            calculate_risk_score(&vuln, &None, None, None, None, None),
            1
        );
        assert_eq!(
            calculate_risk_score(&mal, &None, None, None, None, None),
            35
        );
    }

    #[test]
    fn listing_spoof_alone_is_high_risk() {
        let m = vec![hit("package.json", reputation::INVISIBLE_NAME, "critical")];
        assert_eq!(calculate_risk_score(&m, &None, None, None, None, None), 70);
    }

    #[test]
    fn benign_ai_never_raises_score() {
        let base = vec![hit("a.js", "exec() Usage", "high")];
        let without = calculate_risk_score(&base, &None, None, None, None, None);
        let with = calculate_risk_score(&base, &benign_ai(), None, None, None, None);
        assert_eq!(without, with);
    }
}
