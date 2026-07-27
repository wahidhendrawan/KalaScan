use crate::AiAnalysis;
use serde_json::Value;
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
        "openai" => openai_analyze(model, api_key, endpoint, code_snippets).await,
        _ => Err(anyhow::anyhow!("Unknown LLM provider: {}. Use 'ollama' or 'openai'.", provider)),
    }
}

/// Analyze with local Ollama instance
async fn ollama_analyze(
    model: &str,
    endpoint: &Option<String>,
    code_snippets: &str,
) -> anyhow::Result<AiAnalysis> {
    let base_url = endpoint
        .as_deref()
        .unwrap_or("http://localhost:11434/api/generate");

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

/// Analyze with OpenAI-compatible API
async fn openai_analyze(
    model: &str,
    api_key: &Option<String>,
    endpoint: &Option<String>,
    code_snippets: &str,
) -> anyhow::Result<AiAnalysis> {
    let key = api_key
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("OpenAI API key is required"))?;

    let base_url = endpoint
        .as_deref()
        .unwrap_or("https://api.openai.com/v1/chat/completions");

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

    let resp = client
        .post(base_url)
        .header("Authorization", format!("Bearer {}", key))
        .json(&body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("OpenAI API connection failed: {}", e))?;

    let status = resp.status();
    let raw: Value = resp.json().await?;

    if !status.is_success() {
        let err_str = raw.to_string();
        let error_msg = raw["error"]["message"]
            .as_str()
            .unwrap_or(&err_str);
        return Err(anyhow::anyhow!(
            "OpenAI API error {}: {}",
            status.as_u16(),
            error_msg
        ));
    }

    let content = raw["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or(&raw.to_string())
        .to_string();

    parse_ai_response(&content)
}

/// Parse the LLM JSON response into our AiAnalysis struct
fn parse_ai_response(text: &str) -> anyhow::Result<AiAnalysis> {
    info!("Raw AI response (first 300 chars): {}", &text[..text.len().min(300)]);

    // Try to extract JSON from the response (LLM may include markdown code blocks)
    let json_str = if let Some(start) = text.find("```json") {
        let content = &text[start + 7..];
        if let Some(end) = content.find("```") {
            &content[..end]
        } else {
            content
        }
    } else if let Some(start) = text.find('{') {
        &text[start..]
    } else {
        text
    };

    let analysis: Value = serde_json::from_str(json_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse AI JSON response: {}\nRaw: {}", e, json_str))?;

    Ok(AiAnalysis {
        is_malicious: analysis["is_malicious"].as_bool().unwrap_or(false),
        risk_score: analysis["risk_score"].as_u64().unwrap_or(0) as u8,
        malware_type: analysis["malware_type"]
            .as_str()
            .unwrap_or("None")
            .to_string(),
        threat_summary: analysis["threat_summary"]
            .as_str()
            .unwrap_or("No threat summary provided")
            .to_string(),
        suspicious_lines: analysis["suspicious_lines"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        recommendation: analysis["recommendation"]
            .as_str()
            .unwrap_or("Safe")
            .to_string(),
    })
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
