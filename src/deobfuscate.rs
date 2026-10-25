use crate::attack::{self, AttackTechnique};
use crate::scanner;
use base64::Engine;
use flate2::read::{GzDecoder, ZlibDecoder};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Read;
use std::path::Path;
use std::sync::LazyLock;
use walkdir::WalkDir;

const ENGINE: &str = "kalascan-deobfuscation/1.6.0";
const MAX_FILES: usize = 10_000;
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_ARTIFACTS: usize = 200;
const MAX_DECODES_PER_FILE: usize = 128;
const MAX_DECODE_DEPTH: u8 = 3;
const MAX_DECODED_BYTES: usize = 512 * 1024;
const MAX_ORIGINAL_CHARS: usize = 300;
const MAX_DECODED_CHARS: usize = 1200;
const MIN_BASE64_CHARS: usize = 16;

const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "__pycache__",
    ".tox",
    ".eggs",
    "target",
    "venv",
    ".venv",
];

const TEXT_EXTENSIONS: &[&str] = &[
    "py", "js", "ts", "mjs", "cjs", "jsx", "tsx", "sh", "bash", "zsh", "ps1", "bat", "cmd", "vbs",
    "vbe", "php", "java", "kt", "kts", "rb", "pl", "lua", "html", "htm", "json", "yaml", "yml",
    "toml", "xml", "md", "txt", "env", "cfg", "ini", "sql", "csv",
];

static BASE64_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/_-]{16,}={0,2}").unwrap());
static HEX_ESCAPE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\\x[0-9A-Fa-f]{2}){4,}").unwrap());
static HEX_ARRAY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:0x[0-9A-Fa-f]{2}\s*,\s*){4,}0x[0-9A-Fa-f]{2}").unwrap());
static HEX_STRING_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[0-9A-Fa-f]{32,}\b").unwrap());
static URL_ESCAPE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:%[0-9A-Fa-f]{2}){4,}").unwrap());
static PS_ENC_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)-(?:enc|encodedcommand)\s+([A-Za-z0-9+/=]{20,})").unwrap());
static JS_CHAR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)String\.fromCharCode\(\s*([0-9,\s]{5,})\)").unwrap());
static PY_CHAR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:chr\(\s*(?:0x[0-9A-Fa-f]+|\d{1,7})\s*\)\s*\+?\s*){4,}").unwrap()
});
static PS_CHAR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:\[char\]\s*(?:0x[0-9A-Fa-f]+|\d{1,7})\s*\+?\s*){4,}").unwrap()
});
static UNICODE_ESCAPE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\\u[0-9A-Fa-f]{4}){4,}").unwrap());
static ROT13_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z]{12,}").unwrap());
static NUMBER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"0x[0-9A-Fa-f]+|\d{1,7}").unwrap());

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeobfuscationReport {
    pub engine: String,
    pub files_scanned: usize,
    pub artifacts: Vec<DeobfuscatedArtifact>,
    pub attack_techniques: Vec<AttackTechnique>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeobfuscatedArtifact {
    pub file_path: String,
    pub line_number: usize,
    pub encoding: String,
    pub original: String,
    pub decoded: String,
    pub decoded_bytes: usize,
    pub depth: u8,
    pub confidence: String,
    pub indicators: Vec<String>,
    pub attack: Vec<AttackTechnique>,
}

struct Candidate {
    start: usize,
    encoding: String,
    bytes: Vec<u8>,
    confidence: &'static str,
}

struct ScanState<'a> {
    report: &'a mut DeobfuscationReport,
    seen: HashSet<String>,
    decodes: usize,
}

pub fn analyze_directory(dir: &Path) -> DeobfuscationReport {
    let mut report = DeobfuscationReport {
        engine: ENGINE.to_string(),
        ..Default::default()
    };
    let mut seen = HashSet::new();

    for entry in WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            let name = entry.file_name().to_string_lossy();
            !entry.path().is_dir() || !SKIP_DIRS.contains(&name.as_ref())
        })
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        if !entry.file_type().is_file() {
            continue;
        }
        if report.files_scanned >= MAX_FILES {
            report.notes.push(format!(
                "Stopped after {} files to bound deobfuscation cost.",
                MAX_FILES
            ));
            break;
        }
        if !is_text_candidate(entry.path()) {
            continue;
        }
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.len() > MAX_FILE_BYTES {
            report.notes.push(format!(
                "Skipped oversized file {} ({} bytes).",
                entry.path().display(),
                metadata.len()
            ));
            continue;
        }
        let data = match std::fs::read(entry.path()) {
            Ok(data) => data,
            Err(_) => continue,
        };
        if data.contains(&0) {
            continue;
        }
        let content = String::from_utf8_lossy(&data);
        let rel_path = entry
            .path()
            .strip_prefix(dir)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .to_string();
        report.files_scanned += 1;

        let mut state = ScanState {
            report: &mut report,
            seen,
            decodes: 0,
        };
        scan_text(&rel_path, &content, &mut state);
        seen = state.seen;

        if report.artifacts.len() >= MAX_ARTIFACTS {
            report.notes.push(format!(
                "Artifact list capped at {} entries.",
                MAX_ARTIFACTS
            ));
            break;
        }
    }

    report.artifacts.sort_by(|a, b| {
        confidence_rank(&a.confidence)
            .cmp(&confidence_rank(&b.confidence))
            .then(a.file_path.cmp(&b.file_path))
            .then(a.line_number.cmp(&b.line_number))
            .then(a.encoding.cmp(&b.encoding))
    });
    report.artifacts.truncate(MAX_ARTIFACTS);

    for artifact in &report.artifacts {
        attack::merge(&mut report.attack_techniques, artifact.attack.clone());
    }
    report.attack_techniques.sort_by(|a, b| a.id.cmp(&b.id));

    report
}

pub fn risk_contribution(report: &DeobfuscationReport) -> u8 {
    let mut score = 0u16;
    for artifact in &report.artifacts {
        score += match artifact.confidence.as_str() {
            "high" => 6,
            "medium" => 3,
            _ => 1,
        };
        if artifact
            .indicators
            .iter()
            .any(|indicator| is_strong_indicator(indicator))
        {
            score += 2;
        }
    }
    score.min(25) as u8
}

fn scan_text(file_path: &str, content: &str, state: &mut ScanState<'_>) {
    let candidates = extract_candidates(content);
    for candidate in candidates {
        if state.decodes >= MAX_DECODES_PER_FILE {
            break;
        }
        let line_number = line_number_at(content, candidate.start);
        process_decoded(
            state,
            file_path,
            line_number,
            &candidate.encoding,
            &truncate(&candidate.encoding, MAX_ORIGINAL_CHARS),
            candidate.bytes,
            candidate.encoding.clone(),
            1,
            candidate.confidence,
        );
    }
}

fn process_decoded(
    state: &mut ScanState<'_>,
    file_path: &str,
    line_number: usize,
    root_original: &str,
    _root_encoding: &str,
    bytes: Vec<u8>,
    chain: String,
    depth: u8,
    base_confidence: &'static str,
) {
    if bytes.is_empty() || state.decodes >= MAX_DECODES_PER_FILE {
        return;
    }
    if bytes.len() > MAX_DECODED_BYTES {
        return;
    }
    state.decodes += 1;

    if let Some((codec, decompressed)) = try_decompress(&bytes) {
        if !decompressed.is_empty() {
            let next_chain = format!("{} -> {}", chain, codec);
            process_decoded(
                state,
                file_path,
                line_number,
                root_original,
                _root_encoding,
                decompressed,
                next_chain,
                depth,
                "high",
            );
        }
        return;
    }

    if let Some((text, codec)) = decode_text(&bytes) {
        let next_chain = match codec {
            Some(codec) => format!("{} -> {}", chain, codec),
            None => chain.clone(),
        };
        let indicators = detect_indicators(&text);
        let confidence = if base_confidence == "high" {
            "high"
        } else if indicators
            .iter()
            .any(|indicator| is_strong_indicator(indicator))
        {
            "high"
        } else if !indicators.is_empty() {
            "medium"
        } else {
            "low"
        };
        let should_report = base_confidence == "high"
            || !indicators.is_empty()
            || next_chain.contains("utf-16le")
            || next_chain.contains("gzip")
            || next_chain.contains("zlib");
        if should_report {
            add_artifact(
                state,
                file_path,
                line_number,
                root_original,
                &next_chain,
                &text,
                depth,
                confidence,
                indicators,
            );
        }

        if depth < MAX_DECODE_DEPTH && state.decodes < MAX_DECODES_PER_FILE {
            for candidate in extract_candidates(&text) {
                if state.decodes >= MAX_DECODES_PER_FILE {
                    break;
                }
                process_decoded(
                    state,
                    file_path,
                    line_number,
                    root_original,
                    _root_encoding,
                    candidate.bytes,
                    format!("{} -> {}", next_chain, candidate.encoding),
                    depth + 1,
                    candidate.confidence,
                );
            }
        }
    }

    if !chain.contains("xor(") {
        if let Some((key, decoded)) = try_single_byte_xor(&bytes) {
            let next_chain = format!("{} -> xor(0x{:02x})", chain, key);
            process_decoded(
                state,
                file_path,
                line_number,
                root_original,
                _root_encoding,
                decoded,
                next_chain,
                depth,
                "medium",
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_artifact(
    state: &mut ScanState<'_>,
    file_path: &str,
    line_number: usize,
    original: &str,
    encoding: &str,
    decoded: &str,
    depth: u8,
    confidence: &str,
    indicators: Vec<String>,
) {
    let mut hasher = Sha256::new();
    hasher.update(decoded.as_bytes());
    let digest = hex::encode(hasher.finalize());
    let key = format!("{}:{}:{}:{}", file_path, line_number, encoding, digest);
    if !state.seen.insert(key) {
        return;
    }
    if state.report.artifacts.len() >= MAX_ARTIFACTS {
        return;
    }

    let attack_text = format!("{} {} {}", encoding, decoded, indicators.join(" "));
    let attack = attack::map_text(&attack_text);
    state.report.artifacts.push(DeobfuscatedArtifact {
        file_path: file_path.to_string(),
        line_number,
        encoding: encoding.to_string(),
        original: truncate(original, MAX_ORIGINAL_CHARS),
        decoded: truncate(decoded, MAX_DECODED_CHARS),
        decoded_bytes: decoded.len(),
        depth,
        confidence: confidence.to_string(),
        indicators,
        attack,
    });
}

fn extract_candidates(text: &str) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    let lower = text.to_ascii_lowercase();

    for mat in PS_ENC_RE.captures_iter(text) {
        if let Some(payload) = mat.get(1) {
            if let Some(bytes) = decode_base64(payload.as_str()) {
                candidates.push(Candidate {
                    start: mat.get(0).map(|m| m.start()).unwrap_or(0),
                    encoding: "powershell -EncodedCommand -> base64".to_string(),
                    bytes,
                    confidence: "high",
                });
            }
        }
    }

    for mat in JS_CHAR_RE.captures_iter(text) {
        if let Some(payload) = mat.get(1) {
            if let Some(bytes) = decode_numbers(payload.as_str()) {
                candidates.push(Candidate {
                    start: mat.get(0).map(|m| m.start()).unwrap_or(0),
                    encoding: "string.fromcharcode".to_string(),
                    bytes,
                    confidence: "high",
                });
            }
        }
    }

    for mat in PY_CHAR_RE.find_iter(text) {
        if let Some(bytes) = decode_numbers(mat.as_str()) {
            candidates.push(Candidate {
                start: mat.start(),
                encoding: "chr()".to_string(),
                bytes,
                confidence: "high",
            });
        }
    }

    for mat in PS_CHAR_RE.find_iter(text) {
        if let Some(bytes) = decode_numbers(mat.as_str()) {
            candidates.push(Candidate {
                start: mat.start(),
                encoding: "[char]".to_string(),
                bytes,
                confidence: "high",
            });
        }
    }

    for mat in HEX_ESCAPE_RE.find_iter(text) {
        if let Some(bytes) = decode_hex_escapes(mat.as_str()) {
            candidates.push(Candidate {
                start: mat.start(),
                encoding: "hex escape".to_string(),
                bytes,
                confidence: "high",
            });
        }
    }

    for mat in HEX_ARRAY_RE.find_iter(text) {
        if let Some(bytes) = decode_numbers(mat.as_str()) {
            candidates.push(Candidate {
                start: mat.start(),
                encoding: "hex array".to_string(),
                bytes,
                confidence: "medium",
            });
        }
    }

    for mat in HEX_STRING_RE.find_iter(text) {
        let raw = mat.as_str();
        if raw.len() % 2 != 0 {
            continue;
        }
        if let Ok(bytes) = hex::decode(raw) {
            let context = context_window(&lower, mat.start(), mat.end(), 80);
            let known = contains_any(
                &context,
                &["hex", "fromhex", "unhexlify", "decode", "bytes.fromhex"],
            );
            candidates.push(Candidate {
                start: mat.start(),
                encoding: "hex string".to_string(),
                bytes,
                confidence: if known { "high" } else { "medium" },
            });
        }
    }

    for mat in URL_ESCAPE_RE.find_iter(text) {
        if let Some(bytes) = decode_url_escapes(mat.as_str()) {
            candidates.push(Candidate {
                start: mat.start(),
                encoding: "url percent".to_string(),
                bytes,
                confidence: "high",
            });
        }
    }

    for mat in UNICODE_ESCAPE_RE.find_iter(text) {
        if let Some(bytes) = decode_unicode_escapes(mat.as_str()) {
            candidates.push(Candidate {
                start: mat.start(),
                encoding: "unicode escape".to_string(),
                bytes,
                confidence: "high",
            });
        }
    }

    for mat in BASE64_RE.find_iter(text) {
        let raw = mat.as_str();
        if raw.len() < MIN_BASE64_CHARS || is_hex_string(raw) {
            continue;
        }
        if raw.contains("://") || raw.starts_with('/') || raw.contains('\\') {
            continue;
        }
        let context = context_window(&lower, mat.start(), mat.end(), 80);
        let known = contains_any(
            &context,
            &[
                "base64",
                "frombase64string",
                "atob(",
                "b64decode",
                "b64encode",
                "encodedcommand",
                "powershell",
                "-enc ",
                "decode",
            ],
        );
        if !known && raw.len() < 24 {
            continue;
        }
        if let Some(bytes) = decode_base64(raw) {
            candidates.push(Candidate {
                start: mat.start(),
                encoding: "base64".to_string(),
                bytes,
                confidence: if known { "high" } else { "low" },
            });
        }
    }

    for mat in ROT13_RE.find_iter(text) {
        let raw = mat.as_str();
        if raw.len() < 12 {
            continue;
        }
        let decoded = rot13(raw);
        if detect_indicators(&decoded).is_empty() {
            continue;
        }
        candidates.push(Candidate {
            start: mat.start(),
            encoding: "rot13".to_string(),
            bytes: decoded.into_bytes(),
            confidence: "medium",
        });
    }

    candidates.sort_by_key(|candidate| candidate.start);
    candidates
}

fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let cleaned = input.trim_matches(|c: char| {
        matches!(
            c,
            '"' | '\'' | '`' | ')' | ']' | '}' | ';' | ',' | ' ' | '\n' | '\r' | '\t'
        )
    });
    if cleaned.len() < 8 {
        return None;
    }
    let mut padded = cleaned.to_string();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    let variants = [cleaned, padded.as_str()];
    for candidate in variants {
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(candidate) {
            return Some(bytes);
        }
        if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE.decode(candidate) {
            return Some(bytes);
        }
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD_NO_PAD.decode(candidate) {
            return Some(bytes);
        }
        if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(candidate) {
            return Some(bytes);
        }
    }
    None
}

fn decode_hex_escapes(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for part in input.split("\\x").skip(1) {
        if part.len() < 2 {
            return None;
        }
        out.push(u8::from_str_radix(&part[..2], 16).ok()?);
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn decode_url_escapes(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for part in input.split('%').skip(1) {
        if part.len() < 2 {
            return None;
        }
        out.push(u8::from_str_radix(&part[..2], 16).ok()?);
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn decode_numbers(input: &str) -> Option<Vec<u8>> {
    let mut chars = String::new();
    for mat in NUMBER_RE.find_iter(input) {
        let raw = mat.as_str();
        let value = if let Some(hex) = raw.strip_prefix("0x") {
            u32::from_str_radix(hex, 16).ok()?
        } else {
            raw.parse::<u32>().ok()?
        };
        chars.push(char::from_u32(value)?);
    }
    if chars.len() < 4 {
        None
    } else {
        Some(chars.into_bytes())
    }
}

fn decode_unicode_escapes(input: &str) -> Option<Vec<u8>> {
    let mut out = String::new();
    for part in input.split("\\u").skip(1) {
        if part.len() < 4 {
            return None;
        }
        let value = u16::from_str_radix(&part[..4], 16).ok()?;
        out.push(char::from_u32(value as u32)?);
    }
    if out.len() < 4 {
        None
    } else {
        Some(out.into_bytes())
    }
}

fn decode_text(bytes: &[u8]) -> Option<(String, Option<&'static str>)> {
    if is_utf16le(bytes) {
        let mut text = String::new();
        for chunk in bytes.chunks_exact(2) {
            let value = u16::from_le_bytes([chunk[0], chunk[1]]);
            if let Some(ch) = char::from_u32(value as u32) {
                text.push(ch);
            }
        }
        if printable_text_ratio(&text) >= 0.8 {
            return Some((text, Some("utf-16le")));
        }
    }

    let text = String::from_utf8_lossy(bytes).to_string();
    if text.len() >= 4 && printable_text_ratio(&text) >= 0.85 {
        Some((text, None))
    } else {
        None
    }
}

fn is_utf16le(bytes: &[u8]) -> bool {
    if bytes.len() < 8 || bytes.len() % 2 != 0 {
        return false;
    }
    let zeros = bytes
        .chunks_exact(2)
        .filter(|chunk| chunk[1] == 0 && chunk[0] != 0)
        .count();
    zeros * 100 / (bytes.len() / 2) >= 30
}

fn try_decompress(bytes: &[u8]) -> Option<(&'static str, Vec<u8>)> {
    if bytes.len() < 8 {
        return None;
    }
    if bytes.starts_with(&[0x1f, 0x8b]) {
        if let Some(out) = read_decoder(GzDecoder::new(bytes)) {
            return Some(("gzip", out));
        }
    }
    if bytes.len() >= 2 && bytes[0] & 0x0f == 8 {
        let header = u16::from_be_bytes([bytes[0], bytes[1]]);
        if header % 31 == 0 {
            if let Some(out) = read_decoder(ZlibDecoder::new(bytes)) {
                return Some(("zlib", out));
            }
        }
    }
    None
}

fn read_decoder<R: Read>(reader: R) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut limited = reader.take(MAX_DECODED_BYTES as u64 + 1);
    limited.read_to_end(&mut out).ok()?;
    if out.is_empty() || out.len() > MAX_DECODED_BYTES {
        None
    } else {
        Some(out)
    }
}

fn try_single_byte_xor(bytes: &[u8]) -> Option<(u8, Vec<u8>)> {
    if bytes.len() < 8 || bytes.len() > 4096 {
        return None;
    }
    let mut best: Option<(u8, Vec<u8>, usize)> = None;
    for key in 1u8..=255 {
        let decoded: Vec<u8> = bytes.iter().map(|byte| byte ^ key).collect();
        if let Some((text, _)) = decode_text(&decoded) {
            let indicators = detect_indicators(&text);
            if indicators.is_empty() {
                continue;
            }
            let score = printable_text_ratio(&text) as usize + indicators.len() * 20;
            if best
                .as_ref()
                .is_none_or(|(_, _, best_score)| score > *best_score)
            {
                best = Some((key, decoded, score));
            }
        }
    }
    best.map(|(key, bytes, _)| (key, bytes))
}

fn printable_text_ratio(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }
    let printable = text
        .chars()
        .filter(|ch| !ch.is_control() || matches!(ch, '\n' | '\r' | '\t'))
        .count();
    printable as f64 / text.chars().count() as f64
}

pub(crate) fn detect_indicators(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let checks: &[(&[&str], &str)] = &[
        (&["http://", "https://"], "Contains URL"),
        (
            &[
                "powershell",
                "-encodedcommand",
                "frombase64string",
                "invoke-expression",
                "iex(",
            ],
            "PowerShell execution",
        ),
        (
            &[
                "downloadstring",
                "webclient",
                "invoke-webrequest",
                "start-bitstransfer",
            ],
            "Remote payload download",
        ),
        (
            &[
                "cmd.exe",
                "wscript",
                "cscript",
                "mshta",
                "rundll32",
                "regsvr32",
                "certutil",
                "bitsadmin",
            ],
            "System binary proxy execution",
        ),
        (
            &[
                "eval(",
                "new function(",
                "child_process",
                "exec(",
                "spawn(",
                "os.system",
                "subprocess",
            ],
            "Dynamic code execution",
        ),
        (
            &[
                "virtualalloc",
                "writeprocessmemory",
                "createremotethread",
                "loadlibrary",
                "getprocaddress",
            ],
            "Process injection or native API use",
        ),
        (
            &["discord", "telegram", "slack", "webhook"],
            "Messaging or webhook exfiltration",
        ),
        (
            &[
                "bitcoin",
                "wallet",
                "metamask",
                "phantom",
                "keystore",
                "private key",
            ],
            "Crypto wallet targeting",
        ),
        (
            &[
                "password",
                "credential",
                "cookie",
                "session token",
                "api key",
                "ssh key",
                ".env",
            ],
            "Credential or session access",
        ),
        (
            &["shellcode", "meterpreter", "beacon", "reverse shell", "c2 "],
            "Malware or command-and-control indicator",
        ),
        (
            &[
                "base64",
                "fromhex",
                "unhexlify",
                "xor",
                "decrypt",
                "decryptstring",
            ],
            "Additional decoding layer",
        ),
    ];

    let mut indicators = Vec::new();
    for (needles, label) in checks {
        if needles.iter().any(|needle| lower.contains(needle)) {
            indicators.push((*label).to_string());
        }
    }
    indicators
}

fn is_strong_indicator(indicator: &str) -> bool {
    matches!(
        indicator,
        "PowerShell execution"
            | "Remote payload download"
            | "System binary proxy execution"
            | "Dynamic code execution"
            | "Process injection or native API use"
            | "Messaging or webhook exfiltration"
            | "Crypto wallet targeting"
            | "Credential or session access"
            | "Malware or command-and-control indicator"
    )
}

fn is_text_candidate(path: &Path) -> bool {
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if scanner::is_critical_file(filename) {
        return true;
    }
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    TEXT_EXTENSIONS.contains(&extension.as_str())
}

fn is_hex_string(value: &str) -> bool {
    value.len() >= 32 && value.len() % 2 == 0 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn context_window(text: &str, start: usize, end: usize, radius: usize) -> String {
    let begin = start.saturating_sub(radius);
    let finish = (end + radius).min(text.len());
    text.get(begin..finish).unwrap_or_default().to_string()
}

fn line_number_at(text: &str, offset: usize) -> usize {
    text.as_bytes()
        .iter()
        .take(offset.min(text.len()))
        .filter(|byte| **byte == b'\n')
        .count()
        + 1
}

fn truncate(value: &str, max_chars: usize) -> String {
    let mut out: String = value
        .chars()
        .take(max_chars)
        .map(|ch| {
            if ch.is_control() && !matches!(ch, '\n' | '\r' | '\t') {
                ' '
            } else {
                ch
            }
        })
        .collect();
    if value.chars().count() > max_chars {
        out.push_str("...");
    }
    out
}

fn rot13(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            'a'..='m' => char::from_u32(ch as u32 + 13).unwrap_or(ch),
            'n'..='z' => char::from_u32(ch as u32 - 13).unwrap_or(ch),
            'A'..='M' => char::from_u32(ch as u32 + 13).unwrap_or(ch),
            'N'..='Z' => char::from_u32(ch as u32 - 13).unwrap_or(ch),
            _ => ch,
        })
        .collect()
}

fn confidence_rank(confidence: &str) -> u8 {
    match confidence {
        "high" => 0,
        "medium" => 1,
        _ => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(content: &str) -> DeobfuscationReport {
        let mut report = DeobfuscationReport {
            engine: ENGINE.to_string(),
            ..Default::default()
        };
        let mut state = ScanState {
            report: &mut report,
            seen: HashSet::new(),
            decodes: 0,
        };
        scan_text("test.py", content, &mut state);
        report.artifacts.sort_by(|a, b| a.encoding.cmp(&b.encoding));
        report
    }

    #[test]
    fn decodes_base64_payload() {
        let report = scan(
            r#"payload = base64.b64decode("cG93ZXJzaGVsbCAtYyBodHRwczovL2V2aWwuZXhhbXBsZS9wYXlsb2Fk")"#,
        );
        assert!(report
            .artifacts
            .iter()
            .any(|artifact| artifact.decoded.contains("powershell")));
    }

    #[test]
    fn decodes_powershell_encoded_command() {
        let encoded = "cABvAHcAZQByAHMAaABlAGwAbAAgAC0AYwAgAGgAdAB0AHAAcwA6AC8ALwBlAHYAaQBsAC4AZQB4AGEAbQBwAGwAZQA=";
        let report = scan(&format!("powershell -EncodedCommand {}", encoded));
        assert!(report.artifacts.iter().any(|artifact| {
            artifact.encoding.contains("utf-16le")
                && artifact.decoded.to_ascii_lowercase().contains("powershell")
        }));
    }

    #[test]
    fn decodes_hex_escapes_and_char_codes() {
        let report = scan(
            r#"a = "\x70\x6f\x77\x65\x72\x73\x68\x65\x6c\x6c"
b = String.fromCharCode(104,116,116,112,115,58,47,47,101,118,105,108)"#,
        );
        assert!(report
            .artifacts
            .iter()
            .any(|artifact| artifact.decoded.contains("powershell")));
        assert!(report
            .artifacts
            .iter()
            .any(|artifact| artifact.decoded.contains("https://evil")));
    }

    #[test]
    fn decodes_url_and_unicode_escapes() {
        let report = scan(
            r#"a = "%70%6f%77%65%72%73%68%65%6c%6c"; b = "\u0070\u006f\u0077\u0065\u0072\u0073\u0068\u0065\u006c\u006c";"#,
        );
        assert!(report
            .artifacts
            .iter()
            .any(|artifact| artifact.decoded.contains("powershell")));
    }

    #[test]
    fn decodes_single_byte_xor() {
        let plain = b"powershell -c https://evil.example/payload";
        let encoded: Vec<u8> = plain.iter().map(|byte| byte ^ 0x5a).collect();
        let hex: String = encoded.iter().map(|byte| format!("{:02x}", byte)).collect();
        let report = scan(&format!(r#"payload = bytes.fromhex("{}")"#, hex));
        assert!(report
            .artifacts
            .iter()
            .any(|artifact| artifact.decoded.contains("powershell")));
    }

    #[test]
    fn decodes_recursive_base64() {
        let inner =
            base64::engine::general_purpose::STANDARD.encode("https://evil.example/payload");
        let outer = base64::engine::general_purpose::STANDARD.encode(inner);
        let report = scan(&format!(r#"x = atob("{}")"#, outer));
        assert!(report.artifacts.iter().any(|artifact| {
            artifact.depth >= 2 && artifact.decoded.contains("https://evil.example")
        }));
    }

    #[test]
    fn decodes_gzip_payload() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(b"powershell -c https://evil.example")
            .unwrap();
        let compressed = encoder.finish().unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(compressed);
        let report = scan(&format!(r#"payload = base64.b64decode("{}")"#, encoded));
        assert!(report
            .artifacts
            .iter()
            .any(|artifact| artifact.encoding.contains("gzip")
                && artifact.decoded.contains("powershell")));
    }

    #[test]
    fn ignores_plain_text() {
        let report = scan("const message = 'hello world';");
        assert!(report.artifacts.is_empty());
    }

    #[test]
    fn maps_attack_techniques() {
        let report = scan(
            r#"payload = base64.b64decode("cG93ZXJzaGVsbCAtYyBodHRwczovL2V2aWwuZXhhbXBsZS9wYXlsb2Fk")"#,
        );
        assert!(!report.artifacts[0].attack.is_empty());
    }

    #[test]
    fn risk_contribution_is_capped() {
        let mut report = DeobfuscationReport::default();
        for _ in 0..100 {
            report.artifacts.push(DeobfuscatedArtifact {
                file_path: "x".into(),
                line_number: 1,
                encoding: "base64".into(),
                original: "x".into(),
                decoded: "powershell".into(),
                decoded_bytes: 10,
                depth: 1,
                confidence: "high".into(),
                indicators: vec!["PowerShell execution".into()],
                attack: Vec::new(),
            });
        }
        assert_eq!(risk_contribution(&report), 25);
    }
}
