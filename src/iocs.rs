//! Indicators of compromise: every external URL / host / public IP the
//! scanned code refers to, for analysts and blocklists, plus an opt-in
//! exact-URL lookup in abuse.ch URLhaus (`URLHAUS_AUTH_KEY`).

use crate::RuleMatch;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::LazyLock;
use std::time::Duration;
use walkdir::WalkDir;

pub const URLHAUS_HIT: &str = "Known Malicious URL (URLhaus)";

/// Unique URLs kept per scan; enough for triage, bounded for huge repos.
const MAX_IOCS: usize = 200;
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Ioc {
    /// `url` or `ip`
    pub kind: String,
    pub value: String,
    pub host: String,
    pub files: Vec<String>,
}

static URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\b(?:https?|wss?|ftp)://[^\s"'`<>()\[\]{}\\]+"#).unwrap());

/// Documentation, schema and registry hosts that every codebase links to.
const BENIGN_HOSTS: &[&str] = &[
    "github.com",
    "npmjs.com",
    "npmjs.org",
    "nodejs.org",
    "w3.org",
    "mozilla.org",
    "microsoft.com",
    "visualstudio.com",
    "python.org",
    "pypi.org",
    "apache.org",
    "json-schema.org",
    "schemastore.org",
    "example.com",
    "example.org",
    "example.net",
    "localhost",
    "opensource.org",
    "creativecommons.org",
    "gnu.org",
    "ietf.org",
    "wikipedia.org",
    "stackoverflow.com",
    "readthedocs.io",
    "shields.io",
    "semver.org",
    "spdx.org",
    "unicode.org",
    "tc39.es",
    "whatwg.org",
    "ecma-international.org",
    "googleapis.com",
    "gstatic.com",
    "jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
];

fn host_of(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?.split(':').next()?;
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty() && host.contains('.')).then_some(host)
}

fn is_benign(host: &str) -> bool {
    BENIGN_HOSTS
        .iter()
        .any(|b| host == *b || host.ends_with(&format!(".{}", b)))
        || host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| ip.is_private() || ip.is_loopback() || ip.is_link_local())
}

/// Collect external URLs from the script and manifest files under `root`.
/// `own_tree`: same directory skipping as the scanner (`scanner::skip_dir`).
pub fn extract(root: &Path, own_tree: bool) -> Vec<Ioc> {
    let mut found: BTreeMap<String, Ioc> = BTreeMap::new();
    let entries = WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| !crate::scanner::skip_dir(e, own_tree))
        .flatten()
        .filter(|e| e.file_type().is_file())
        .filter(|e| crate::scanner::is_critical_file(&e.file_name().to_string_lossy()));
    for entry in entries {
        if entry.metadata().map_or(true, |m| m.len() > MAX_FILE_BYTES) {
            continue;
        }
        let Ok(bytes) = std::fs::read(entry.path()) else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        let rel = entry
            .path()
            .strip_prefix(root)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .to_string();
        for m in URL.find_iter(&text) {
            let url = m.as_str().trim_end_matches(['.', ',', ';', ':']);
            let Some(host) = host_of(url) else {
                continue;
            };
            if is_benign(&host) {
                continue;
            }
            if !found.contains_key(url) && found.len() >= MAX_IOCS {
                continue;
            }
            let kind = if host.parse::<std::net::Ipv4Addr>().is_ok() {
                "ip"
            } else {
                "url"
            };
            let ioc = found.entry(url.to_string()).or_insert_with(|| Ioc {
                kind: kind.to_string(),
                value: url.to_string(),
                host,
                files: Vec::new(),
            });
            if ioc.files.len() < 3 && !ioc.files.contains(&rel) {
                ioc.files.push(rel.clone());
            }
        }
    }
    found.into_values().collect()
}

#[derive(Deserialize)]
struct UrlhausReply {
    query_status: String,
    #[serde(default)]
    threat: Option<String>,
    #[serde(default)]
    url_status: Option<String>,
}

/// Exact-URL lookups (not host: shared hosts like raw.githubusercontent.com
/// always have *some* malicious URL). Errors and misses yield nothing.
pub async fn urlhaus_matches(iocs: &[Ioc], auth_key: &str) -> Vec<RuleMatch> {
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for ioc in iocs.iter().take(100) {
        let reply = client
            .post("https://urlhaus-api.abuse.ch/v1/url/")
            .header("Auth-Key", auth_key)
            .form(&[("url", ioc.value.as_str())])
            .send()
            .await;
        let Ok(reply) = reply else { continue };
        let Ok(reply) = reply.json::<UrlhausReply>().await else {
            continue;
        };
        if reply.query_status == "ok" {
            out.push(RuleMatch {
                file_path: ioc.files.first().cloned().unwrap_or_default(),
                line_number: 1,
                matched_pattern: URLHAUS_HIT.to_string(),
                severity: "critical".to_string(),
                context: format!(
                    "{} — URLhaus: {} ({})",
                    ioc.value,
                    reply.threat.unwrap_or_else(|| "malware".into()),
                    reply.url_status.unwrap_or_else(|| "unknown".into())
                ),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_external_urls_only() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("index.js"),
            "// docs: https://nodejs.org/api/fs.html\n\
             fetch('https://webhook.site/abc-123');\n\
             const c2 = \"http://91.92.242.133/support\";\n\
             const lan = 'http://192.168.1.4:8080/x';\n\
             see https://user:pw@evil.example.ru:8443/p?q=1.\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("README.md"),
            "https://not-scanned.example.ru",
        )
        .unwrap();
        let iocs = extract(dir.path(), false);
        let values: Vec<(&str, &str)> = iocs
            .iter()
            .map(|i| (i.kind.as_str(), i.host.as_str()))
            .collect();
        assert_eq!(
            values,
            vec![
                ("ip", "91.92.242.133"),
                ("url", "evil.example.ru"),
                ("url", "webhook.site"),
            ]
        );
        assert_eq!(iocs[2].value, "https://webhook.site/abc-123");
        assert_eq!(iocs[2].files, vec!["index.js"]);
    }
}
