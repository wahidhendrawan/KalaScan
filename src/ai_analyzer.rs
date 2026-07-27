use crate::AiAnalysis;
use serde_json::Value;
use std::sync::OnceLock;
use tracing::info;

const SYSTEM_PROMPT: &str = r#"Kamu adalah spesialis Malware Analysis dan Application Security Audit.
Tugas kamu adalah menganalisis potongan kode dari repositori untuk mendeteksi indikasi malicious code (Information Stealer, Ransomware, Backdoor, Obfuscation).

Analisis kode berdasarkan kriteria:
1. PENGAMBILAN DATA SENSITIF (Exfiltration): Akses ke browser, crypto wallet, token session, pengiriman data via Webhook/C2.
2. OBFUSCATION & EXECUTION: Encoding bertingkat, eksekusi perintah sistem tersembunyi, unduhan payload eksternal.
3. RANSOMWARE/DESTRUCTIVE: Enkripsi massal, penghapusan backup/shadow copies.

Output HARUS berupa JSON valid dengan format:
{
  "is_malicious": boolean,
  "risk_score": integer (0 - 100),
  "malware_type": "None" | "Information Stealer" | "Ransomware" | "Backdoor" | "Suspicious",
  "threat_summary": "Penjelasan ringkas temuan",
  "suspicious_lines": ["Daftar baris kode/fungsi berbahaya"],
  "recommendation": "Safe" | "High Risk" | "Do Not Execute"
}"#;

/// Detect if running inside a Docker container.
fn in_docker() -> bool {
    static DOCKER: OnceLock<bool> = OnceLock::new();
    *DOCKER.get_or_init(|| std::path::Path::new("/.dockerenv").exists())
}

/// Replace localhost with host.docker.internal when in a Docker container.
fn resolve_host(url: &str) -> String {
    if in_docker() && url.contains("://localhost:") {
        url.replace("://localhost:", "://host.docker.internal:")
    } else {
        url.to_string()
    }
}

/// Analyze suspicious code snippets using an LLM (Ollama or OpenAI-compatible API).
pub async fn analyze_with_llm(
    provider: &str,
    model: &str,
    api_key: &Option<String>,
    endpoint: &Option<String>,
    code_snippets: &str,
) -> anyhow::Result<AiAnalysis> {
    match provider.to_lowercase().as_str() {
        "ollama" => ollama_analyze(model, endpoint, code_snippets).await,
        "openai" => openai_analyze(model, api_key, endpoint, code_snippets, true).await,
        "deepseek" => openai_analyze(
            model,
            api_key,
            &Some("https://api.deepseek.com/v1/chat/completions".to_string()),
            code_snippets,
            true,
        )
        .await,
        "9router" | "custom" => {
            // Generic OpenAI-compatible provider (API key optional)
            openai_analyze(model, api_key, endpoint, code_snippets, false).await
        }
        _ => Err(anyhow::anyhow!(
            "Unknown LLM provider: {}. Use 'ollama', 'openai', 'deepseek', '9router', or 'custom'.",
            provider
        )),
    }

}

/// Analyze with local Ollama instance
async fn ollama_analyze(
    model: &str,
    endpoint: &Option<String>,
    code_snippets: &str,
) -> anyhow::Result<AiAnalysis> {
    let base_url = resolve_host(
        endpoint
            .as_deref()
            .unwrap_or("http://localhost:11434/api/generate"),
    );

    let user_prompt = format!(
        "Analisis potongan kode berikut dari hasil pemindaian statis (RegEx). Indikator yang terdeteksi telah ditandai.\n\nKODE:\n{}",
        code_snippets
    );

    let body = serde_json::json!({
        "model": model,
        "system": SYSTEM_PROMPT,
        "prompt": user_prompt,
        "stream": false,
        "options": {
            "temperature": 0.1,
            "num_predict": 1024
        }
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()?;

    info!("Calling Ollama API at {} with model {}", base_url, model);

    let resp = client
        .post(base_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Ollama connection failed: {}. Is Ollama running?", e))?;

    let status = resp.status();
    let raw: Value = resp.json().await?;

    if !status.is_success() {
        return Err(anyhow::anyhow!(
            "Ollama API error {}: {}",
            status.as_u16(),
            raw.to_string()
        ));
    }

    let response_text = raw["response"]
        .as_str()
        .unwrap_or(&raw.to_string())
        .to_string();

    parse_ai_response(&response_text)
}

/// Analyze with OpenAI-compatible API.
/// If `require_key` is false, the API key is optional (for local proxies like 9Router).
async fn openai_analyze(
    model: &str,
    api_key: &Option<String>,
    endpoint: &Option<String>,
    code_snippets: &str,
    require_key: bool,
) -> anyhow::Result<AiAnalysis> {
    let base_url = resolve_host(&match (endpoint.as_deref(), require_key) {
        // 9Router local proxy default
        (None, false) => "http://localhost:20128/v1/chat/completions",
        // OpenAI default
        (None, true) => "https://api.openai.com/v1/chat/completions",
        (Some(ep), _) => ep,
    }.to_string());

    if require_key && api_key.is_none() {
        return Err(anyhow::anyhow!("OpenAI API key is required for this provider"));
    }
    let key = api_key.as_deref().unwrap_or("");

    let user_prompt = format!(
        "Analisis potongan kode berikut dari hasil pemindaian statis (RegEx):\n\nKODE:\n{}",
        code_snippets
    );

    let body = serde_json::json!({
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.1,
        "max_tokens": 1024,
        "response_format": {"type": "json_object"}
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()?;

    info!("Calling OpenAI API at {} with model {}", base_url, model);

    let mut req = client.post(base_url);
    if !key.is_empty() {
        req = req.header("Authorization", format!("Bearer {}", key));
    }
    // Remove response_format if the provider doesn't support it (e.g. 9Router via many backends)
    let body_no_json_mode = serde_json::json!({
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.1,
        "max_tokens": 1024
    });
    let final_body = if require_key { &body } else { &body_no_json_mode };

    let resp = req.json(final_body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("OpenAI API connection failed: {}", e))?;

    let status = resp.status();
    let response_text = match resp.text().await {
        Ok(t) => t,
        Err(e) => return Err(anyhow::anyhow!("Failed to read response body: {}", e)),
    };

    if !status.is_success() {
        // Try to parse JSON error
        if let Ok(val) = serde_json::from_str::<Value>(&response_text) {
            let error_msg = val["error"]["message"].as_str().unwrap_or(&response_text);
            return Err(anyhow::anyhow!("OpenAI API error {}: {}", status.as_u16(), error_msg));
        }
        return Err(anyhow::anyhow!("OpenAI API error {}: {}", status.as_u16(), response_text));
    }

    // Try to parse JSON from response
    let content = if let Ok(val) = serde_json::from_str::<Value>(&response_text) {
        val["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or(&response_text)
            .to_string()
    } else {
        // Fallback: use raw text
        response_text.trim().to_string()
    };

    parse_ai_response(&content)
}

/// Parse the LLM JSON response into our AiAnalysis struct
fn parse_ai_response(text: &str) -> anyhow::Result<AiAnalysis> {
    info!("Raw AI response (first 300 chars): {}", &text[..text.len().min(300)]);

    // Strip SSE trailing markers like "data: [DONE]" appended by some proxies
    let clean = text
        .trim()
        .strip_suffix("data: [DONE]")
        .map(|s| s.trim())
        .unwrap_or(text.trim())
        .to_string();
    // If text ends with literal '}data: [DONE]', strip after the last '}'
    let clean = if let Some(end) = clean.rfind("data: [DONE]") {
        clean[..end].trim().to_string()
    } else {
        clean
    };

    // Try to extract JSON from the SSE-cleaned response (LLM may include markdown code blocks)
    let json_str: String = if let Some(start) = clean.find("```json") {
        let after = &clean[start + 7..];
        if let Some(end) = after.find("```") {
            after[..end].to_string()
        } else {
            after.to_string()
        }
    } else if let Some(start) = clean.find('{') {
        clean[start..].to_string()
    } else {
        clean.to_string()
    };

    let analysis: AiAnalysis = if let Ok(val) = serde_json::from_str::<Value>(&json_str) {
        // Check if this is a chat completion wrapper with content field
        let content_str = val["choices"][0]["message"]["content"].as_str();
        if let Some(inner) = content_str {
            // Try to parse the inner content as our JSON
            match serde_json::from_str::<Value>(inner) {
                Ok(inner_val) => {
                    AiAnalysis {
                        is_malicious: inner_val["is_malicious"].as_bool().unwrap_or(false),
                        risk_score: inner_val["risk_score"].as_u64().unwrap_or(0) as u8,
                        malware_type: inner_val["malware_type"].as_str().unwrap_or("None").to_string(),
                        threat_summary: inner_val["threat_summary"].as_str().unwrap_or("No threat summary provided").to_string(),
                        suspicious_lines: inner_val["suspicious_lines"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default(),
                        recommendation: inner_val["recommendation"].as_str().unwrap_or("Safe").to_string(),
                    }
                }
                Err(_) => {
                    // Inner content isn't JSON — return raw fields
                    AiAnalysis {
                        is_malicious: false,
                        risk_score: 0,
                        malware_type: "None".to_string(),
                        threat_summary: inner.to_string(),
                        suspicious_lines: vec![],
                        recommendation: "Safe".to_string(),
                    }
                }
            }
        } else {
            // Direct JSON (no chat completion wrapper)
            AiAnalysis {
                is_malicious: val["is_malicious"].as_bool().unwrap_or(false),
                risk_score: val["risk_score"].as_u64().unwrap_or(0) as u8,
                malware_type: val["malware_type"].as_str().unwrap_or("None").to_string(),
                threat_summary: val["threat_summary"].as_str().unwrap_or("No threat summary provided").to_string(),
                suspicious_lines: val["suspicious_lines"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default(),
                recommendation: val["recommendation"].as_str().unwrap_or("Safe").to_string(),
            }
        }
    } else {
        return Err(anyhow::anyhow!("Failed to parse AI response: {}", json_str));
    };

    Ok(analysis)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_malicious_json() {
        let json = r#"{
            "is_malicious": true,
            "risk_score": 85,
            "malware_type": "Information Stealer",
            "threat_summary": "Kode ini mengambil data browser dan mengirim via Discord webhook.",
            "suspicious_lines": ["eval(base64.b64decode(...))", "discord.com/api/webhooks/..."],
            "recommendation": "Do Not Execute"
        }"#;

        let result = parse_ai_response(json).unwrap();
        assert!(result.is_malicious);
        assert_eq!(result.risk_score, 85);
        assert_eq!(result.malware_type, "Information Stealer");
        assert_eq!(result.recommendation, "Do Not Execute");
    }

    #[test]
    fn test_parse_safe_json() {
        let json = r#"{
            "is_malicious": false,
            "risk_score": 5,
            "malware_type": "None",
            "threat_summary": "Tidak ada indikasi malicious code.",
            "suspicious_lines": [],
            "recommendation": "Safe"
        }"#;

        let result = parse_ai_response(json).unwrap();
        assert!(!result.is_malicious);
        assert_eq!(result.risk_score, 5);
        assert_eq!(result.malware_type, "None");
        assert_eq!(result.recommendation, "Safe");
    }

    #[test]
    fn test_parse_markdown_wrapped_json() {
        let text = "```json\n{\"is_malicious\": false, \"risk_score\": 0, \"malware_type\": \"None\", \"threat_summary\": \"Clean\", \"suspicious_lines\": [], \"recommendation\": \"Safe\"}\n```";
        let result = parse_ai_response(text).unwrap();
        assert!(!result.is_malicious);
        assert_eq!(result.risk_score, 0);
    }
}
