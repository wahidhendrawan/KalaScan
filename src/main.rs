mod ai_analyzer;
mod scanner;

use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub repo_url: String,
    pub llm_provider: String,          // "ollama" | "openai"
    pub llm_model: String,             // e.g. "llama3" | "gpt-4"
    pub llm_api_key: Option<String>,   // for OpenAI
    pub llm_endpoint: Option<String>,  // custom endpoint
    pub ai_analysis_enabled: bool,
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
    pub status: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("kalascan=info")
        .init();

    info!("KalaScan v1.0.0 starting...");

    let tera = Tera::new("templates/**/*.html")
        .map_err(|e| {
            error!("Failed to load templates: {}", e);
            e
        })?;

    let state = AppState {
        tera: Arc::new(tera),
        scans: Arc::new(Mutex::new(Vec::new())),
    };

    let app = Router::new()
        .route("/", get(root))
        .route("/scan", post(start_scan))
        .route("/api/scan", post(api_scan))
        .route("/api/results/{id}", get(get_result))
        .route("/results/{id}", get(results_page))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = std::env::var("KALASCAN_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("Web UI: http://{}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}

async fn root(State(state): State<AppState>) -> Result<Html<String>, (StatusCode, String)> {
    let ctx = tera::Context::new();
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

async fn start_scan(State(state): State<AppState>, Json(req): Json<ScanRequest>) -> impl IntoResponse {
    match run_scan(req, &state).await {
        Ok(result) => {
            let mut scans = state.scans.lock().await;
            let id = result.id.clone();
            scans.push(result);

            Json(serde_json::json!({
                "success": true,
                "result_id": id
            }))
            .into_response()
        }
        Err(e) => {
            error!("Scan failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": e.to_string()
                })),
            )
                .into_response()
        }
    }
}

async fn api_scan(State(state): State<AppState>, Json(req): Json<ScanRequest>) -> impl IntoResponse {
    let result = run_scan(req, &state).await;
    match result {
        Ok(r) => Json(serde_json::json!({
            "success": true,
            "result": r
        }))
        .into_response(),
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "success": false,
                "error": e.to_string()
            })))
            .into_response()
        }
    }
}

async fn get_result(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let scans = state.scans.lock().await;
    if let Some(result) = scans.iter().find(|r| r.id == id) {
        Json(serde_json::json!({
            "success": true,
            "result": result
        }))
        .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "success": false,
                "error": "Result not found"
            })),
        )
            .into_response()
    }
}

async fn results_page(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let scans = state.scans.lock().await;
    let result = scans.iter().find(|r| r.id == id).cloned();

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
    drop(scans);

    match state.tera.render("result.html", &ctx) {
        Ok(html) => Html(html).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Template error: {}", e),
        )
            .into_response(),
    }
}

async fn run_scan(req: ScanRequest, _state: &AppState) -> anyhow::Result<ScanResult> {
    info!("Starting scan for: {}", req.repo_url);

    let scan_id = uuid::Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now().to_rfc3339();

    // Phase 1: Clone repo ke temp directory
    let tmp_dir = tempfile::tempdir()?;
    let repo_path = tmp_dir.path().join("repo");

    info!("Cloning {} to {:?}", req.repo_url, repo_path);

    // Clone via git
    let clone_output = tokio::process::Command::new("git")
        .arg("clone")
        .arg("--depth")
        .arg("1")
        .arg(&req.repo_url)
        .arg(&repo_path)
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

    info!("Clone successful. Running static scan...");

    // Phase 2: Static rule check
    let (total_files, scanned_files, rule_matches) = scanner::scan_directory(&repo_path);

    info!(
        "Static scan complete: {} files scanned, {} matches found",
        scanned_files,
        rule_matches.len()
    );

    // Phase 3: AI analysis
    let ai_result = if req.ai_analysis_enabled && !rule_matches.is_empty() {
        info!("Running AI deep analysis...");

        // Collect suspicious code snippets for AI
        let context_snippets: Vec<String> = rule_matches
            .iter()
            .map(|m| format!("File: {}\nLine {}: {}\nContext: {}", m.file_path, m.line_number, m.matched_pattern, m.context))
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

    // Calculate risk score
    let risk_score = calculate_risk_score(&rule_matches, &ai_result);

    let result = ScanResult {
        id: scan_id.clone(),
        repo_url: req.repo_url,
        timestamp,
        total_files,
        scanned_files,
        total_matches: rule_matches.len(),
        risk_score,
        ai_analysis: ai_result,
        rule_matches,
        status: "completed".to_string(),
    };

    // tmp_dir goes out of scope here → RAII auto-cleanup
    info!("Scan complete. ID: {}", scan_id);

    Ok(result)
}

fn calculate_risk_score(matches: &[RuleMatch], ai: &Option<AiAnalysis>) -> u8 {
    let mut score = 0u16;

    // Cada match contributes
    for m in matches {
        score += match m.severity.as_str() {
            "critical" => 15,
            "high" => 10,
            "medium" => 5,
            _ => 2,
        };
    }

    // Cap at 100 from rules alone
    if score > 60 {
        score = 60;
    }

    // AI risk boost (if available)
    if let Some(ai) = ai {
        let ai_score = ai.risk_score as u16 / 2; // AI contributes up to 50
        score += ai_score;
    }

    if score > 100 {
        100
    } else {
        score as u8
    }
}
