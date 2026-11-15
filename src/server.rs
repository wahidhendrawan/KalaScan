//! The web server (`kalascan serve`): Axum routes, auth and security-header
//! middleware, the scan queue and the upload endpoint.

use crate::*;
use axum::{
    extract::{Extension, Multipart, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Json},
    routing::{delete, get, post},
    Router,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

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
    /// Bound to loopback: while no auth is configured, only requests
    /// addressed to a loopback name are served (see `auth_middleware`).
    loopback_only: bool,
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
        return Ok(()); // marketplace id or npm:/pypi:/crates: package: fixed public hosts
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

pub(crate) async fn start_web_server(addr: &str) -> anyhow::Result<()> {
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
        // KALASCAN_ALLOW_UNAUTHENTICATED=1 also covers a local reverse proxy
        // that does its own auth and forwards the public Host.
        loopback_only: is_loopback(addr)
            && std::env::var("KALASCAN_ALLOW_UNAUTHENTICATED").as_deref() != Ok("1"),
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
    // A page on another site must not drive this API through the visitor's
    // browser: on loopback without auth, any open tab could queue scans and
    // read every result. The dashboard is same-origin; curl and CI send no
    // Origin. No CORS headers are sent either, so nothing is opted back in.
    if is_cross_origin(req.headers()) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "success": false, "error": "Cross-origin request refused" })),
        )
            .into_response();
    }

    let path = req.uri().path().to_string();
    if is_auth_exempt(&path) {
        return next.run(req).await;
    }

    // DNS rebinding: a page whose domain re-resolves to 127.0.0.1 is
    // same-origin to the browser, so the check above passes, but its Host
    // header still names that domain. Only the unauthenticated loopback
    // server is exposed: with a token the page has nothing to send.
    let host = req
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if state.loopback_only && !is_loopback(host) && state.token.is_none() && !auth::any_users() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "success": false,
                "error": "Host not allowed: without auth this server answers to localhost only"
            })),
        )
            .into_response();
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

/// True when a browser sent the request from a page on another origin: an
/// `Origin` whose host is not the one the request was addressed to. Behind
/// a reverse proxy the public name arrives in `X-Forwarded-Host`.
fn is_cross_origin(headers: &HeaderMap) -> bool {
    let value = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let Some(origin) = value("origin") else {
        return false;
    };
    let authority = origin.split_once("://").map_or(origin, |(_, a)| a);
    !["host", "x-forwarded-host"]
        .iter()
        .any(|h| value(h) == Some(authority))
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
            "Target must be a remote URL, publisher.extension id, npm:/pypi:/crates: package; \
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
        history_max_commits: None,
        history_since: None,
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
        secrets: false,
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
    fn requests_from_another_origin_are_refused() {
        let headers = |pairs: &[(&'static str, &'static str)]| {
            let mut h = HeaderMap::new();
            for (k, v) in pairs {
                h.insert(*k, axum::http::HeaderValue::from_static(v));
            }
            h
        };
        // curl, CI: no Origin at all.
        assert!(!is_cross_origin(&headers(&[("host", "127.0.0.1:3000")])));
        // The dashboard's own fetch.
        assert!(!is_cross_origin(&headers(&[
            ("host", "127.0.0.1:3000"),
            ("origin", "http://127.0.0.1:3000")
        ])));
        // Behind a proxy that rewrites Host.
        assert!(!is_cross_origin(&headers(&[
            ("host", "kalascan:3000"),
            ("x-forwarded-host", "scan.example.com"),
            ("origin", "https://scan.example.com")
        ])));
        for origin in ["https://evil.example", "http://localhost:3000", "null"] {
            assert!(
                is_cross_origin(&headers(&[("host", "127.0.0.1:3000"), ("origin", origin)])),
                "{}",
                origin
            );
        }
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
