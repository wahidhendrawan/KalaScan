mod ai_analyzer;
mod attack;
mod cli;
mod cve;
mod db;
mod entropy;
mod export;
mod git_history;
mod scanner;
mod triage;
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
            ai,
            llm_provider,
            llm_model,
            llm_key,
            llm_endpoint,
            cve,
            yara_dir,
            git_history,
            deep_triage,
        }) => {
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
            };
            run_cli_scan(req, format, fail_on_risk, output).await?;
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
    info!("KalaScan v1.3.0 starting Web UI on http://{}", addr);

    // Initialize DB
    if let Err(e) = db::init_db() {
        error!("Failed to init DB (running without persistence): {}", e);
    }

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
        .route("/api/scan/upload", post(api_scan_upload))
        .route("/api/results/{id}", get(get_result))
        .route("/api/history", get(history))
        .route("/api/report/{id}/{format}", get(report))
        .route("/api/scan/{id}", delete(delete_scan))
        .route("/results/{id}", get(results_page))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("Web UI available at http://{}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}

async fn root(State(state): State<AppState>) -> Result<Html<String>, (StatusCode, String)> {
    let mut ctx = tera::Context::new();
    // Load scans from DB for initial render
    let scan_list = db::list_scans(100).unwrap_or_default();
    ctx.insert("scans", &scan_list);
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

async fn start_scan(
    State(state): State<AppState>,
    Json(req): Json<ScanRequest>,
) -> impl IntoResponse {
    match run_scan(req, &state).await {
        Ok(result) => {
            // Persist to DB
            if let Err(e) = db::save_scan(&result) {
                error!("Failed to save scan to DB: {}", e);
            }
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

async fn api_scan(
    State(state): State<AppState>,
    Json(req): Json<ScanRequest>,
) -> impl IntoResponse {
    let result = run_scan(req, &state).await;
    match result {
        Ok(r) => {
            if let Err(e) = db::save_scan(&r) {
                error!("Failed to save scan to DB: {}", e);
            }
            Json(serde_json::json!({
                "success": true,
                "result": r
            }))
            .into_response()
        }
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
    Path(id): Path<String>,
) -> impl IntoResponse {
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
            _ => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "success": false,
                    "error": "Invalid format. Use 'md' or 'html'"
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
) -> impl IntoResponse {
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

async fn results_page(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
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

    let scan_id = uuid::Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now().to_rfc3339();

    let tmp_dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "success": false, "error": e.to_string() })),
            )
                .into_response();
        }
    };

    let scan_dir = match vsix::extract_zip(std::io::Cursor::new(bytes), tmp_dir.path()) {
        Ok(dir) => dir,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "success": false,
                    "error": format!("Failed to unpack extension archive: {}", e)
                })),
            )
                .into_response();
        }
    };

    let (total_files, scanned_files, mut rule_matches) = scanner::scan_directory(&scan_dir);

    // Check dependency manifests for CVEs via OSV API when enabled
    if check_cve {
        let pkgs = cve::extract_manifest_packages(&scan_dir);
        if !pkgs.is_empty() {
            let cve_matches = cve::check_vulnerabilities(&pkgs).await;
            rule_matches.extend(cve_matches);
        }
    }

    let triage_report = triage::analyze_directory(&scan_dir, &rule_matches, deep_triage).await;

    let ai_result = if ai_analysis_enabled && !rule_matches.is_empty() {
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
        ai_analyzer::analyze_with_llm(
            &llm_provider,
            &llm_model,
            &llm_api_key,
            &llm_endpoint,
            &combined_prompt,
        )
        .await
        .ok()
    } else {
        None
    };

    let risk_score = calculate_risk_score(&rule_matches, &ai_result, Some(&triage_report));

    let result = ScanResult {
        id: scan_id.clone(),
        repo_url: format!("vsix://{}", file_name),
        timestamp,
        total_files,
        scanned_files,
        total_matches: rule_matches.len(),
        risk_score,
        ai_analysis: ai_result,
        rule_matches,
        triage: Some(triage_report),
        status: "completed".to_string(),
    };

    if let Err(e) = db::save_scan(&result) {
        error!("Failed to save scan to DB: {}", e);
    }
    {
        let mut scans = state.scans.lock().await;
        scans.push(result.clone());
    }

    Json(serde_json::json!({
        "success": true,
        "result_id": scan_id,
        "result": result
    }))
    .into_response()
}

async fn run_scan(req: ScanRequest, _state: &AppState) -> anyhow::Result<ScanResult> {
    execute_scan(req).await
}

async fn execute_scan(req: ScanRequest) -> anyhow::Result<ScanResult> {
    info!("Starting scan for: {}", req.repo_url);

    let scan_id = uuid::Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now().to_rfc3339();

    let tmp_dir = tempfile::tempdir()?;
    let target_dir = tmp_dir.path().join("source");
    std::fs::create_dir_all(&target_dir)?;

    let is_extension = vsix::is_vsix_target(&req.repo_url);
    let scan_dir = if is_extension {
        info!("Target detected as IDE Extension / Package: {}", req.repo_url);
        vsix::unpack_extension(&req.repo_url, &target_dir).await?
    } else {
        info!("Cloning {} to {:?}", req.repo_url, target_dir);
        let mut clone_cmd = tokio::process::Command::new("git");
        clone_cmd.arg("clone");
        if !req.git_history {
            clone_cmd.arg("--depth").arg("1");
        }
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

    info!("Source ready at {:?}. Running static + YARA + entropy scan...", scan_dir);

    // Phase 2: Static rule + YARA + Entropy check
    let custom_yara = req.yara_dir.as_ref().map(std::path::Path::new);
    let (total_files, scanned_files, mut rule_matches) =
        scanner::scan_directory_with_yara(&scan_dir, custom_yara);

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
    if req.git_history && !is_extension {
        info!("Scanning full git commit history at {:?}...", scan_dir);
        let history_matches = git_history::scan_git_history(&scan_dir).await;
        info!("Git history scan found {} matches", history_matches.len());
        rule_matches.extend(history_matches);
    }

    info!(
        "Scan complete: {} files scanned, {} matches found",
        scanned_files,
        rule_matches.len()
    );

    // Phase 2d: Deep static binary triage
    info!("Running static binary triage...");
    let triage_report = triage::analyze_directory(&scan_dir, &rule_matches, req.deep_triage).await;

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

    let risk_score = calculate_risk_score(&rule_matches, &ai_result, Some(&triage_report));

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
        triage: Some(triage_report),
        status: "completed".to_string(),
    };

    info!("Scan complete. ID: {}", scan_id);

    Ok(result)
}

async fn run_cli_scan(
    req: ScanRequest,
    format: String,
    fail_on_risk: Option<u8>,
    output: Option<std::path::PathBuf>,
) -> anyhow::Result<()> {
    let result = execute_scan(req).await?;

    let output_content = match format.to_lowercase().as_str() {
        "json" => serde_json::to_string_pretty(&result)?,
        "md" | "markdown" => export::export_markdown(&result),
        "html" => export::export_html(&result),
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
    out.push_str(&format!("Files Scanned: {} / {}\n", result.scanned_files, result.total_files));
    out.push_str(&format!("Total Matches: {}\n", result.total_matches));

    let level = if result.risk_score >= 70 {
        "🔴 HIGH RISK (Possible Malware)"
    } else if result.risk_score >= 30 {
        "🟡 WARNING (Suspicious)"
    } else {
        "🟢 SAFE"
    };
    out.push_str(&format!("Risk Score:    {} / 100 [{}]\n", result.risk_score, level));
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
        out.push_str(&format!("ATT&CK Techniques: {}\n", triage.attack_techniques.len()));
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

    out.push_str("============================================================\n");
    out
}

fn calculate_risk_score(
    matches: &[RuleMatch],
    ai: &Option<AiAnalysis>,
    triage: Option<&triage::TriageReport>,
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

    if score > 100 {
        100
    } else {
        score as u8
    }
}
