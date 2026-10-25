mod ai_analyzer;
mod attack;
mod baseline;
mod cli;
mod cve;
mod db;
mod deobfuscate;
mod emulate;
mod entropy;
mod export;
mod git_history;
mod sandbox;
mod scanner;
mod triage;
mod ttp;
mod vsix;
mod yara_engine;

use axum::{
    extract::{Multipart, Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::{delete, get, post},
    Router,
};
use clap::Parser;
use cli::{Cli, Commands};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tera::Tera;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;
use tracing::{error, info};

#[derive(Clone)]
struct AppState {
    tera: Arc<Tera>,
    scans: Arc<Mutex<Vec<ScanResult>>>,
    token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub repo_url: String,
    pub llm_provider: String,
    pub llm_model: String,
    pub llm_api_key: Option<String>,
    pub llm_endpoint: Option<String>,
    pub ai_analysis_enabled: bool,
    #[serde(default)]
    pub check_cve: Option<bool>,
    #[serde(default)]
    pub yara_dir: Option<String>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
            ignore,
            changed_only,
            base_ref,
            ai,
            llm_provider,
            llm_model,
            llm_key,
            llm_endpoint,
            cve,
            yara_dir,
            git_history,
            deep_triage,
            deobfuscate,
            emulate,
            sandbox,
            sandbox_image,
        }) => {
            let baseline_path = baseline.clone();
            let req = ScanRequest {
                repo_url: target,
                llm_provider,
                llm_model,
                llm_api_key: llm_key,
                llm_endpoint,
                ai_analysis_enabled: ai,
                check_cve: Some(cve),
                yara_dir: yara_dir.map(|p| p.to_string_lossy().to_string()),
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
            };
            run_cli_scan(req, format, fail_on_risk, output, baseline_path).await?;
        }
        Some(Commands::Serve { addr }) => {
            start_web_server(&addr).await?;
        }
        None => {
            let addr = cli.addr.unwrap_or_else(|| {
                std::env::var("KALASCAN_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string())
            });
            start_web_server(&addr).await?;
        }
    }

    Ok(())
}

async fn start_web_server(addr: &str) -> anyhow::Result<()> {
    info!("KalaScan v1.6.0 starting Web UI on http://{}", addr);

    // Initialize DB
    if let Err(e) = db::init_db() {
        error!("Failed to init DB (running without persistence): {}", e);
    }

    let tera = Tera::new("templates/**/*.html").map_err(|e| {
        error!("Failed to load templates: {}", e);
        e
    })?;

    let token = std::env::var("KALASCAN_TOKEN")
        .ok()
        .filter(|t| !t.trim().is_empty());
    if token.is_some() {
        info!("API bearer-token authentication enabled (KALASCAN_TOKEN)");
    } else if !is_loopback(addr) {
        error!(
            "Bound to non-loopback address {} without KALASCAN_TOKEN — API is unauthenticated",
            addr
        );
    }

    let state = AppState {
        tera: Arc::new(tera),
        scans: Arc::new(Mutex::new(Vec::new())),
        token,
    };

    let app = Router::new()
        .route("/", get(root))
        .route("/scan", post(start_scan))
        .route("/api/scan", post(api_scan))
        .route("/api/scan/upload", post(api_scan_upload))
        .route("/api/results/{id}", get(get_result))
        .route("/api/scan/{id}/status", get(scan_status))
        .route("/api/history", get(history))
        .route("/api/report/{id}/{format}", get(report))
        .route("/api/scan/{id}", delete(delete_scan))
        .route("/results/{id}", get(results_page))
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

/// Enforce bearer auth when `KALASCAN_TOKEN` is set.
async fn auth_middleware(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if let Err((status, msg)) = check_auth(&state, req.headers()) {
        return (
            status,
            Json(serde_json::json!({ "success": false, "error": msg })),
        )
            .into_response();
    }
    next.run(req).await
}

fn check_auth(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<(), (StatusCode, String)> {
    let Some(expected) = state.token.as_deref() else {
        return Ok(());
    };
    let provided = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    // Constant-time-ish comparison
    let expected = expected.as_bytes();
    let provided = provided.as_bytes();
    let mut diff = expected.len() ^ provided.len();
    for i in 0..expected.len() {
        diff |= (expected[i] ^ *provided.get(i).unwrap_or(&0)) as usize;
    }
    if diff == 0 {
        Ok(())
    } else {
        Err((StatusCode::UNAUTHORIZED, "Unauthorized".to_string()))
    }
}

async fn root(State(state): State<AppState>) -> Result<Html<String>, (StatusCode, String)> {
    let mut ctx = tera::Context::new();
    // Load scans from DB for initial render
    let scan_list = db::list_scans(100).unwrap_or_default();
    ctx.insert("scans", &scan_list);
    // Embed as raw JSON for the client-side history list. Escape `<`/`&`/`>` so a
    // crafted repo URL cannot break out of the `<script>` block.
    let scans_json = serde_json::to_string(&scan_list)
        .unwrap_or_else(|_| "[]".to_string())
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026");
    ctx.insert("scans_json", &scans_json);
    match state.tera.render("index.html", &ctx) {
        Ok(html) => Ok(Html(html)),
        Err(e) => {
            error!("Template error: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Template error: {}", e),
            ))
        }
    }
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
        status: "running".to_string(),
    }
}

async fn store_result(state: &AppState, result: ScanResult) {
    if let Err(e) = db::save_scan(&result) {
        error!("Failed to save scan to DB: {}", e);
    }
    let mut scans = state.scans.lock().await;
    if let Some(slot) = scans.iter_mut().find(|s| s.id == result.id) {
        *slot = result;
    } else {
        scans.push(result);
    }
}

fn spawn_scan(state: AppState, req: ScanRequest, id: String) {
    tokio::spawn(async move {
        match execute_scan_with_id(req, id.clone()).await {
            Ok(result) => store_result(&state, result).await,
            Err(e) => {
                error!("Scan {} failed: {}", id, e);
                let mut failed = pending_scan(&id, "");
                {
                    let scans = state.scans.lock().await;
                    if let Some(prev) = scans.iter().find(|s| s.id == id) {
                        failed.repo_url = prev.repo_url.clone();
                    }
                }
                failed.status = format!("failed: {}", e);
                store_result(&state, failed).await;
            }
        }
    });
}

async fn start_scan(
    State(state): State<AppState>,
    Json(req): Json<ScanRequest>,
) -> impl IntoResponse {
    let id = uuid::Uuid::new_v4().to_string();
    {
        let mut scans = state.scans.lock().await;
        scans.push(pending_scan(&id, &req.repo_url));
    }
    spawn_scan(state, req, id.clone());

    Json(serde_json::json!({
        "success": true,
        "result_id": id,
        "status": "running"
    }))
    .into_response()
}

async fn api_scan(
    State(state): State<AppState>,
    Json(req): Json<ScanRequest>,
) -> impl IntoResponse {
    let id = uuid::Uuid::new_v4().to_string();
    {
        let mut scans = state.scans.lock().await;
        scans.push(pending_scan(&id, &req.repo_url));
    }
    spawn_scan(state, req, id.clone());

    Json(serde_json::json!({
        "success": true,
        "result_id": id,
        "status": "running"
    }))
    .into_response()
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
        let done = result.status != "running";
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
            _ => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "success": false,
                    "error": "Invalid format. Use 'md', 'html' or 'sarif'"
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

async fn delete_scan(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    // Remove from in-memory
    {
        let mut scans = state.scans.lock().await;
        scans.retain(|r| r.id != id);
    }

    // Remove from DB
    match db::delete_scan(&id) {
        Ok(_) => Json(serde_json::json!({ "success": true })).into_response(),
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

async fn results_page(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    let result = {
        let scans = state.scans.lock().await;
        scans.iter().find(|r| r.id == id).cloned()
    };
    let result = match result {
        Some(result) => Some(result),
        None => db::get_scan(&id).ok().flatten(),
    };

    let mut ctx = tera::Context::new();
    match result {
        Some(r) => {
            ctx.insert("has_result", &true);
            let result_json = serde_json::to_string_pretty(&r).unwrap_or_default();
            ctx.insert("result_json", &result_json);
            ctx.insert("result", &r);
        }
        None => {
            ctx.insert("has_result", &false);
        }
    }

    let id_str = id.clone();
    ctx.insert("result_id", &id_str);

    match state.tera.render("result.html", &ctx) {
        Ok(html) => Html(html).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Template error: {}", e),
        )
            .into_response(),
    }
}

async fn api_scan_upload(
    State(state): State<AppState>,
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
    let mut sandbox_image: Option<String> = None;

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
        } else if name == "sandbox_image" {
            if let Ok(val) = field.text().await {
                if !val.trim().is_empty() {
                    sandbox_image = Some(val);
                }
            }
        }
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
        let scan_dir = vsix::extract_zip(std::io::Cursor::new(bytes), tmp_dir.path())?;
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
        git_history: false,
        deep_triage,
        deobfuscate,
        emulate,
        sandbox,
        sandbox_image,
        new_only: false,
        baseline: None,
        ignore: None,
        changed_only: false,
        base_ref: None,
    };

    let scan_id = uuid::Uuid::new_v4().to_string();
    {
        let mut scans = state.scans.lock().await;
        scans.push(pending_scan(&scan_id, &req.repo_url));
    }
    let task_state = state.clone();
    let task_id = scan_id.clone();
    // The temp dir must outlive the scan task; move it into the task.
    tokio::spawn(async move {
        let result = execute_scan_in(req, scan_dir, task_id.clone(), Some(tmp_dir)).await;
        match result {
            Ok(r) => store_result(&task_state, r).await,
            Err(e) => {
                error!("Upload scan {} failed: {}", task_id, e);
                let _ = tokio::time::timeout(std::time::Duration::from_secs(1), async {
                    let mut scans = task_state.scans.lock().await;
                    if let Some(slot) = scans.iter_mut().find(|s| s.id == task_id) {
                        slot.status = format!("failed: {}", e);
                    }
                })
                .await;
            }
        }
    });

    Json(serde_json::json!({
        "success": true,
        "result_id": scan_id,
        "status": "running"
    }))
    .into_response()
}

async fn execute_scan(req: ScanRequest) -> anyhow::Result<ScanResult> {
    let id = uuid::Uuid::new_v4().to_string();
    execute_scan_with_id(req, id).await
}

async fn execute_scan_with_id(req: ScanRequest, id: String) -> anyhow::Result<ScanResult> {
    info!("Starting scan for: {}", req.repo_url);

    let tmp_dir = tempfile::tempdir()?;
    let target_dir = tmp_dir.path().join("source");
    std::fs::create_dir_all(&target_dir)?;

    let is_extension = vsix::is_vsix_target(&req.repo_url);
    let scan_dir = if is_extension {
        info!(
            "Target detected as IDE Extension / Package: {}",
            req.repo_url
        );
        vsix::unpack_extension(&req.repo_url, &target_dir).await?
    } else {
        info!("Cloning {} to {:?}", req.repo_url, target_dir);
        let mut clone_cmd = tokio::process::Command::new("git");
        clone_cmd.arg("clone");
        if !req.git_history {
            clone_cmd.arg("--depth").arg("1");
        }
        // Never expose credentials in logs; strip any userinfo from the URL.
        let clone_output = clone_cmd
            .arg(&req.repo_url)
            .arg(&target_dir)
            .output()
            .await
            .map_err(|e| anyhow::anyhow!("Git not found: {}. Install git: brew install git", e))?;

        if !clone_output.status.success() {
            let stderr = String::from_utf8_lossy(&clone_output.stderr);
            return Err(anyhow::anyhow!(
                "Git clone failed for {}: {}",
                req.repo_url,
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
    _tmp_guard: Option<tempfile::TempDir>,
) -> anyhow::Result<ScanResult> {
    let timestamp = chrono::Utc::now().to_rfc3339();
    let repo_url = req.repo_url.clone();

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
    let scan_path = scan_dir.clone();
    let changed_clone = changed_files.clone();
    let (total_files, scanned_files, mut rule_matches) = tokio::task::spawn_blocking(move || {
        scanner::scan_directory_filtered(&scan_path, custom_yara.as_deref(), changed_clone.as_ref())
    })
    .await
    .map_err(|e| anyhow::anyhow!("Scanner task failed: {}", e))?;

    // Phase 2b: Dependency CVE check via OSV API if enabled
    if req.check_cve.unwrap_or(true) {
        let pkgs = cve::extract_manifest_packages(&scan_dir);
        if !pkgs.is_empty() {
            info!("Auditing {} manifest packages with OSV API...", pkgs.len());
            let cve_matches = cve::check_vulnerabilities(&pkgs).await;
            rule_matches.extend(cve_matches);
        }
    }

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
        Some(&ttp_report),
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
    // Try to make the base ref available in shallow clones. Ignore failures:
    // the ref may already exist locally.
    let remote_ref = base_ref.strip_prefix("origin/").unwrap_or(base_ref);
    let fetched = tokio::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["fetch", "--depth", "1", "origin", remote_ref])
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
    } else if fetched.as_ref().map_or(false, |f| f.status.success()) {
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

async fn run_cli_scan(
    req: ScanRequest,
    format: String,
    fail_on_risk: Option<u8>,
    output: Option<std::path::PathBuf>,
    baseline_out: Option<std::path::PathBuf>,
) -> anyhow::Result<()> {
    let new_only = req.new_only;
    let result = execute_scan(req).await?;

    // `--new-only` merges into the baseline so prior fingerprints survive;
    // a plain `--baseline` run records the current findings (overwrite).
    if let Some(path) = baseline_out {
        if new_only {
            baseline::merge_baseline(&path, &result.rule_matches)?;
        } else {
            baseline::save_baseline(&path, &result.rule_matches)?;
        }
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

    let level = if result.risk_score >= 70 {
        "🔴 HIGH RISK (Possible Malware)"
    } else if result.risk_score >= 30 {
        "🟡 WARNING (Suspicious)"
    } else {
        "🟢 SAFE"
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
    ttp: Option<&ttp::TtpReport>,
) -> u8 {
    let mut score = 0u16;

    for m in matches {
        score += match m.severity.as_str() {
            "critical" => 15,
            "high" => 10,
            "medium" => 5,
            _ => 2,
        };
    }

    if score > 60 {
        score = 60;
    }

    if let Some(ai) = ai {
        let ai_score = ai.risk_score as u16 / 2;
        score += ai_score;
    }

    if let Some(triage) = triage {
        score += triage::risk_contribution(triage) as u16;
    }

    if let Some(deobfuscation) = deobfuscation {
        score += deobfuscate::risk_contribution(deobfuscation) as u16;
    }

    if let Some(emulation) = emulation {
        score += emulate::risk_contribution(emulation) as u16;
    }

    if let Some(sandbox) = sandbox {
        score += sandbox::risk_contribution(sandbox) as u16;
    }

    if let Some(ttp) = ttp {
        score += ttp::risk_contribution(ttp) as u16;
    }

    if score > 100 {
        100
    } else {
        score as u8
    }
}
