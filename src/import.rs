//! `kalascan import`: read another scanner's report and normalize it into one
//! finding shape, so Nessus, Nmap, Burp, ZAP, Nuclei, Qualys and CSV results
//! end up in the same text / JSON / SARIF. Field and severity mapping follow
//! VulnBoard's parsers (backend/src/routes/scanner.ts), except that
//! informational items stay `info` instead of becoming `low`.

use crate::export;
use anyhow::{anyhow, bail, Context};
use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;

/// Reports are read whole; real exports stay well under this.
pub const MAX_REPORT_BYTES: u64 = 256 * 1024 * 1024;
/// Findings past this are dropped with a warning.
pub const MAX_FINDINGS: usize = 100_000;
/// Plugin output and HTTP evidence can run to megabytes per finding.
const MAX_EVIDENCE_CHARS: usize = 4_000;

const SUPPORTED: &str =
    "Nessus (.nessus v2 XML), Nmap XML, Burp Suite XML, OWASP ZAP (XML or JSON), \
     Nuclei (JSON or JSONL), Qualys scan XML, CSV with a title/name column";

pub const SEVERITIES: [&str; 5] = ["critical", "high", "medium", "low", "info"];

#[derive(Debug, Default, Serialize)]
pub struct Finding {
    /// nessus, nmap, burp, zap, nuclei, qualys or csv.
    pub tool: &'static str,
    /// Plugin, template, QID or issue-type id in that tool.
    pub id: String,
    pub title: String,
    /// One of SEVERITIES.
    pub severity: &'static str,
    pub host: String,
    pub port: Option<u16>,
    pub protocol: String,
    pub cves: Vec<String>,
    pub cvss: Option<f64>,
    pub description: String,
    pub solution: String,
    pub evidence: String,
}

#[derive(Debug)]
pub struct Imported {
    pub format: &'static str,
    /// Findings past MAX_FINDINGS were dropped.
    pub truncated: bool,
    /// Most severe first, report order within a severity.
    pub findings: Vec<Finding>,
}

/// Lower is more severe, for sorting and `--fail-on`.
pub fn rank(severity: &str) -> usize {
    SEVERITIES
        .iter()
        .position(|s| *s == severity)
        .unwrap_or(SEVERITIES.len())
}

pub fn import(path: &Path) -> anyhow::Result<Imported> {
    let size = std::fs::metadata(path)
        .with_context(|| format!("cannot read {}", path.display()))?
        .len();
    if size > MAX_REPORT_BYTES {
        bail!(
            "{} is {} MiB; reports over {} MiB are refused",
            path.display(),
            size >> 20,
            MAX_REPORT_BYTES >> 20
        );
    }
    let bytes = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    parse(&String::from_utf8_lossy(&bytes))
}

/// Picks the parser from the content, not the file name.
fn parse(text: &str) -> anyhow::Result<Imported> {
    let text = text.trim_start_matches('\u{feff}').trim_start();
    let (format, mut findings) = match text.chars().next() {
        Some('<') => parse_xml(text)?,
        Some('{' | '[') => parse_json(text)?,
        _ => (
            "csv",
            parse_csv(text)
                .ok_or_else(|| anyhow!("unrecognized report format; supported: {SUPPORTED}"))?,
        ),
    };
    let truncated = findings.len() > MAX_FINDINGS;
    findings.truncate(MAX_FINDINGS);
    for f in &mut findings {
        if f.title.is_empty() {
            f.title = if f.id.is_empty() {
                "Untitled".into()
            } else {
                f.id.clone()
            };
        }
        if f.evidence.chars().count() > MAX_EVIDENCE_CHARS {
            f.evidence = f
                .evidence
                .chars()
                .take(MAX_EVIDENCE_CHARS)
                .collect::<String>()
                + "…";
        }
    }
    findings.sort_by_key(|f| rank(f.severity));
    Ok(Imported {
        format,
        truncated,
        findings,
    })
}

// ── Records ──────────────────────────────────────────────────────────────

/// One report item flattened: child element / JSON key → text, `elem@attr` →
/// attribute (the item's own attributes are `@attr`). Repeats join with newlines.
type Record = HashMap<String, String>;

fn append(r: &mut Record, key: &str, value: &str) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    r.entry(key.to_string())
        .and_modify(|v| {
            v.push('\n');
            v.push_str(value)
        })
        .or_insert_with(|| value.to_string());
}

/// The value of the first of `keys` present (stored values are never empty).
fn get<'a>(r: &'a Record, keys: &[&str]) -> &'a str {
    keys.iter()
        .find_map(|k| r.get(*k))
        .map_or("", |s| s.as_str())
}

fn join(parts: &[&str], sep: &str) -> String {
    let parts: Vec<&str> = parts.iter().copied().filter(|p| !p.is_empty()).collect();
    parts.join(sep)
}

fn parse_port(s: &str) -> Option<u16> {
    s.trim().parse().ok().filter(|p| *p != 0)
}

/// "7.5" or "7.5 (AV:N/...)".
fn cvss(s: &str) -> Option<f64> {
    s.split_whitespace().next()?.parse().ok()
}

/// The CVE ids in `text`, upper-cased, sorted and de-duplicated.
fn cves(text: &str) -> Vec<String> {
    let mut out: Vec<String> = text
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .filter(|t| {
            t.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("cve-"))
                && t[4..].starts_with(|c: char| c.is_ascii_digit())
        })
        .map(str::to_ascii_uppercase)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// "https://h:8443/x" → (h, 8443, https); "h:22" → (h, 22, "").
fn endpoint(s: &str) -> (String, Option<u16>, String) {
    let s = s.trim();
    if let Ok(u) = url::Url::parse(s) {
        if let Some(host) = u.host_str() {
            let port = u.port_or_known_default();
            return (host.to_string(), port, u.scheme().to_string());
        }
    }
    match s.rsplit_once(':') {
        Some((host, p)) if parse_port(p).is_some() => {
            (host.to_string(), parse_port(p), String::new())
        }
        _ => (s.to_string(), None, String::new()),
    }
}

fn severity_word(s: &str) -> Option<&'static str> {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" => Some("critical"),
        "high" => Some("high"),
        "medium" => Some("medium"),
        "low" => Some("low"),
        "info" | "information" | "informational" | "none" => Some("info"),
        _ => None,
    }
}

// ── XML: Nessus, Nmap, Burp, ZAP, Qualys ─────────────────────────────────

/// The format and its per-finding elements, from the root element.
fn xml_kind(root: &str) -> anyhow::Result<(&'static str, &'static [&'static str])> {
    Ok(match root {
        "NessusClientData_v2" => ("nessus", &["ReportItem"]),
        "nmaprun" => ("nmap", &["port"]),
        "issues" => ("burp", &["issue"]),
        "OWASPZAPReport" => ("zap", &["alertitem"]),
        // Confirmed, potential and information-gathered vulnerabilities.
        "SCAN" => ("qualys", &["VULN", "PRACTICE", "INFO"]),
        other => bail!("unrecognized XML report (root element <{other}>); supported: {SUPPORTED}"),
    })
}

fn attrs(prefix: &str, e: &BytesStart) -> anyhow::Result<Vec<(String, String)>> {
    e.attributes()
        .map(|a| {
            let a = a.context("malformed XML attribute")?;
            let value = a
                .normalized_value(XmlVersion::Implicit1_0)
                .map_or_else(|_| a.value.to_string(), |v| v.into_owned());
            Ok((format!("{}@{}", prefix, a.key.local_name().as_ref()), value))
        })
        .collect()
}

/// `&amp;` and `&#10;` become their character; any other entity stays as written.
fn push_ref(buf: &mut String, r: &BytesRef) {
    match r.resolve_char_ref() {
        Ok(Some(c)) => buf.push(c),
        _ => match quick_xml::escape::resolve_predefined_entity(r) {
            Some(s) => buf.push_str(s),
            None => buf.push_str(&format!("&{};", &**r)),
        },
    }
}

/// Streams the document once; no tree is built.
fn parse_xml(text: &str) -> anyhow::Result<(&'static str, Vec<Finding>)> {
    let mut reader = Reader::from_str(text);
    let mut kind: Option<(&'static str, &'static [&'static str])> = None;
    // Attributes of each open element above the current item, plus those of
    // its empty children: nmap's <address/> sits beside <ports>, not above it.
    let mut frames: Vec<Vec<(String, String)>> = Vec::new();
    let mut item: Option<(String, Record)> = None;
    let mut open: Vec<String> = Vec::new(); // elements open inside the item
    let mut text_buf = String::new();
    let mut findings = Vec::new();
    loop {
        let event = reader
            .read_event()
            .with_context(|| format!("malformed XML near byte {}", reader.error_position()))?;
        match &event {
            // quick-xml expands no entities and fetches no DTDs; declarations are
            // refused anyway (XXE, billion laughs). A bare DOCTYPE is accepted:
            // Nmap, Burp and Qualys exports all carry one.
            Event::DocType(d) if d.to_ascii_uppercase().contains("<!ENTITY") => {
                bail!("XML entity declarations are not allowed (XXE / entity expansion)")
            }
            Event::Start(e) | Event::Empty(e) => {
                let name = e.local_name().as_ref().to_string();
                let empty = matches!(event, Event::Empty(_));
                if kind.is_none() {
                    kind = Some(xml_kind(&name)?);
                }
                let items = kind.map_or(&[][..], |k| k.1);
                if let Some((_, rec)) = &mut item {
                    for (k, v) in attrs(&name, e)? {
                        append(rec, &k, &v);
                    }
                    if !empty {
                        open.push(name);
                        text_buf.clear();
                    }
                } else if !empty && items.contains(&name.as_str()) {
                    let mut rec = Record::new();
                    for (k, v) in frames.iter().rev().flatten() {
                        rec.entry(k.clone()).or_insert_with(|| v.clone());
                    }
                    for (k, v) in attrs("", e)? {
                        append(&mut rec, &k, &v);
                    }
                    item = Some((name, rec));
                } else if empty {
                    if let Some(top) = frames.last_mut() {
                        for (k, v) in attrs(&name, e)? {
                            if !top.iter().any(|(seen, _)| *seen == k) {
                                top.push((k, v));
                            }
                        }
                    }
                } else {
                    frames.push(attrs(&name, e)?);
                }
            }
            Event::End(_) => {
                if let Some(child) = open.pop() {
                    if let Some((_, rec)) = &mut item {
                        append(rec, &child, &text_buf);
                    }
                    text_buf.clear();
                } else if let Some((tag, rec)) = item.take() {
                    findings.extend(xml_finding(kind.map_or("", |k| k.0), &tag, &rec));
                    if findings.len() > MAX_FINDINGS {
                        break;
                    }
                } else {
                    frames.pop();
                }
            }
            Event::Text(t) if item.is_some() => text_buf.push_str(&t.xml10_content()),
            Event::CData(t) if item.is_some() => text_buf.push_str(t),
            Event::GeneralRef(r) if item.is_some() => push_ref(&mut text_buf, r),
            Event::Eof => {
                if !frames.is_empty() || item.is_some() {
                    bail!("XML ends inside an open element (truncated file?)");
                }
                break;
            }
            _ => {}
        }
    }
    let (format, _) =
        kind.ok_or_else(|| anyhow!("XML has no root element; supported: {SUPPORTED}"))?;
    Ok((format, findings))
}

fn xml_finding(format: &str, tag: &str, r: &Record) -> Option<Finding> {
    match format {
        "nessus" => Some(nessus(r)),
        "nmap" => nmap(r),
        "burp" => Some(burp(r)),
        "zap" => Some(zap(r)),
        _ => Some(qualys(tag, r)),
    }
}

fn nessus(r: &Record) -> Finding {
    Finding {
        tool: "nessus",
        id: get(r, &["@pluginID"]).into(),
        title: get(r, &["@pluginName", "plugin_name"]).into(),
        severity: severity_word(get(r, &["risk_factor"])).unwrap_or("low"),
        host: get(r, &["ReportHost@name"]).into(),
        port: parse_port(get(r, &["@port"])),
        protocol: get(r, &["@protocol"]).into(),
        cves: cves(get(r, &["cve"])),
        cvss: cvss(get(
            r,
            &["cvss4_base_score", "cvss3_base_score", "cvss_base_score"],
        )),
        description: get(r, &["description"]).into(),
        solution: get(r, &["solution"]).into(),
        evidence: get(r, &["plugin_output"]).into(),
    }
}

/// An open port is a low finding, as in VulnBoard; other states are skipped.
fn nmap(r: &Record) -> Option<Finding> {
    if get(r, &["state@state"]) != "open" {
        return None;
    }
    let (portid, protocol, host) = (
        get(r, &["@portid"]),
        get(r, &["@protocol"]),
        get(r, &["address@addr"]),
    );
    let service = match get(r, &["service@name"]) {
        "" => "unknown",
        s => s,
    };
    let banner = join(
        &[
            get(r, &["service@product"]),
            get(r, &["service@version"]),
            get(r, &["service@extrainfo"]),
        ],
        " ",
    );
    Some(Finding {
        tool: "nmap",
        id: format!("{portid}/{protocol}"),
        title: format!("Open port {portid}/{protocol} ({service})"),
        severity: "low",
        host: host.into(),
        port: parse_port(portid),
        protocol: protocol.into(),
        description: format!("Port {portid}/{protocol} is open running {service} on host {host}."),
        evidence: join(&[&banner, get(r, &["script@output"])], "\n"),
        ..Default::default()
    })
}

fn burp(r: &Record) -> Finding {
    let (host, port, scheme) = endpoint(get(r, &["host"]));
    Finding {
        tool: "burp",
        id: get(r, &["type"]).into(),
        title: get(r, &["name"]).into(),
        severity: severity_word(get(r, &["severity"])).unwrap_or("medium"),
        host: if host.is_empty() {
            get(r, &["host@ip"]).into()
        } else {
            host
        },
        port,
        protocol: scheme,
        description: get(r, &["issueDetail", "issueBackground"]).into(),
        solution: get(r, &["remediationDetail", "remediationBackground"]).into(),
        evidence: get(r, &["path"]).into(),
        ..Default::default()
    }
}

/// XML <alertitem> or JSON alert, flattened the same way.
fn zap(r: &Record) -> Finding {
    let (host, port, scheme) = endpoint(get(r, &["site@name"]));
    Finding {
        tool: "zap",
        id: get(r, &["pluginid", "alertRef"]).into(),
        title: get(r, &["name", "alert"]).into(),
        severity: match get(r, &["riskcode"]).parse::<u8>() {
            Ok(3..) => "high",
            Ok(2) => "medium",
            Ok(0) => "info",
            _ => "low",
        },
        host: if host.is_empty() {
            get(r, &["site@host"]).into()
        } else {
            host
        },
        port: port.or_else(|| parse_port(get(r, &["site@port"]))),
        protocol: scheme,
        description: get(r, &["desc"]).into(),
        solution: get(r, &["solution"]).into(),
        evidence: join(&[get(r, &["uri"]), get(r, &["evidence"])], "\n"),
        ..Default::default()
    }
}

fn qualys(tag: &str, r: &Record) -> Finding {
    let level: u8 = get(r, &["@severity"]).parse().unwrap_or(0);
    Finding {
        tool: "qualys",
        id: get(r, &["@number"]).into(),
        title: get(r, &["TITLE"]).into(),
        severity: match (tag, level) {
            ("INFO", _) => "info",
            (_, 5..) => "critical",
            (_, 4) => "high",
            (_, 3) => "medium",
            _ => "low",
        },
        host: get(r, &["IP@value"]).into(),
        port: parse_port(get(r, &["CAT@port"])),
        protocol: get(r, &["CAT@protocol"]).into(),
        // <ID> holds CVE and Bugtraq ids alike; cves() keeps the CVEs.
        cves: cves(&format!("{} {}", get(r, &["ID"]), get(r, &["@cveid"]))),
        cvss: cvss(get(r, &["CVSS3_BASE", "CVSS_BASE"])),
        description: get(r, &["DIAGNOSIS"]).into(),
        solution: get(r, &["SOLUTION"]).into(),
        evidence: get(r, &["RESULT"]).into(),
    }
}

// ── JSON: ZAP, Nuclei ────────────────────────────────────────────────────

/// Every leaf under its own key name, as XML children are.
fn flatten(v: &Value, key: &str, r: &mut Record) {
    match v {
        Value::Object(map) => map.iter().for_each(|(k, v)| flatten(v, k, r)),
        Value::Array(items) => items.iter().for_each(|v| flatten(v, key, r)),
        Value::String(s) => append(r, key, s),
        Value::Number(_) | Value::Bool(_) => append(r, key, &v.to_string()),
        Value::Null => {}
    }
}

fn one_or_many(v: Option<&Value>) -> Vec<&Value> {
    match v {
        Some(Value::Array(items)) => items.iter().collect(),
        Some(Value::Null) | None => Vec::new(),
        Some(v) => vec![v],
    }
}

fn parse_json(text: &str) -> anyhow::Result<(&'static str, Vec<Finding>)> {
    // A whole document (ZAP, `nuclei -json-export`) or one result per line (`nuclei -jsonl`).
    let docs: Vec<Value> = match serde_json::from_str::<Value>(text) {
        Ok(Value::Array(items)) => items,
        Ok(doc) => vec![doc],
        Err(e) => {
            let mut skipped = 0;
            let docs: Vec<Value> = text
                .lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(|l| serde_json::from_str(l).map_err(|_| skipped += 1).ok())
                .collect();
            if docs.is_empty() {
                bail!("invalid JSON: {e}");
            }
            if skipped > 0 {
                eprintln!("warning: skipped {skipped} unparseable JSONL line(s)");
            }
            docs
        }
    };
    if let [doc] = docs.as_slice() {
        if doc.get("site").is_some() {
            return Ok(("zap", zap_json(doc)));
        }
    }
    let is_nuclei = |d: &Value| {
        d.get("info").is_some() && (d.get("template-id").is_some() || d.get("template").is_some())
    };
    if docs.first().is_some_and(is_nuclei) {
        let findings = docs
            .iter()
            .filter(|d| d.get("info").is_some())
            .map(|d| {
                let mut r = Record::new();
                flatten(d, "", &mut r);
                nuclei(&r)
            })
            .take(MAX_FINDINGS + 1)
            .collect();
        return Ok(("nuclei", findings));
    }
    bail!("unrecognized JSON report; supported: {SUPPORTED}")
}

fn zap_json(doc: &Value) -> Vec<Finding> {
    let mut out = Vec::new();
    for site in one_or_many(doc.get("site")) {
        let mut ctx = Record::new();
        for key in ["name", "host", "port", "ssl"] {
            if let Some(v) = site.get(format!("@{key}")) {
                flatten(v, &format!("site@{key}"), &mut ctx);
            }
        }
        for alert in one_or_many(site.get("alerts").or(site.get("alert"))) {
            let mut r = ctx.clone();
            flatten(alert, "", &mut r);
            out.push(zap(&r));
        }
    }
    out
}

fn nuclei(r: &Record) -> Finding {
    let (host, port, scheme) = endpoint(get(r, &["host"]));
    Finding {
        tool: "nuclei",
        id: get(r, &["template-id", "template_id", "template"]).into(),
        title: get(r, &["name"]).into(),
        severity: severity_word(get(r, &["severity"])).unwrap_or("low"),
        host: if host.is_empty() {
            get(r, &["ip"]).into()
        } else {
            host
        },
        port: parse_port(get(r, &["port"]))
            .or(port)
            .or_else(|| endpoint(get(r, &["matched-at"])).1),
        protocol: if scheme.is_empty() {
            get(r, &["type"]).into()
        } else {
            scheme
        },
        cves: cves(get(r, &["cve-id"])),
        cvss: cvss(get(r, &["cvss-score"])),
        description: get(r, &["description"]).into(),
        solution: get(r, &["remediation"]).into(),
        evidence: join(
            &[get(r, &["matched-at"]), get(r, &["extracted-results"])],
            "\n",
        ),
    }
}

// ── CSV ──────────────────────────────────────────────────────────────────

/// RFC 4180 rows: quoted fields may hold commas, doubled quotes and newlines.
fn csv_rows(text: &str) -> Vec<Vec<String>> {
    let (mut rows, mut row, mut field, mut quoted) = (Vec::new(), Vec::new(), String::new(), false);
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => row.push(std::mem::take(&mut field)),
            '\n' if !quoted => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            '\r' if !quoted => {}
            _ => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

/// VulnBoard's generic CSV import (a header row with a title, finding or name
/// column); Nessus CSV exports fit it. None without such a column.
fn parse_csv(text: &str) -> Option<Vec<Finding>> {
    let mut rows = csv_rows(text).into_iter();
    let header: Vec<String> = rows
        .next()?
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();
    if !header
        .iter()
        .any(|h| matches!(h.as_str(), "title" | "finding" | "name"))
    {
        return None;
    }
    let findings = rows
        .filter_map(|row| {
            let mut r = Record::new();
            for (h, v) in header.iter().zip(&row) {
                append(&mut r, h, v);
            }
            csv_finding(&r)
        })
        .take(MAX_FINDINGS + 1)
        .collect();
    Some(findings)
}

fn csv_finding(r: &Record) -> Option<Finding> {
    let title = get(r, &["title", "finding", "name"]);
    if title.is_empty() {
        return None;
    }
    let risk = get(r, &["severity", "risk", "level"]);
    Some(Finding {
        tool: "csv",
        id: get(r, &["plugin id", "id"]).into(),
        title: title.into(),
        severity: severity_word(risk).unwrap_or(match risk {
            "4" => "critical",
            "3" => "high",
            "2" => "medium",
            "0" => "info",
            _ => "low",
        }),
        host: get(r, &["host", "ip"]).into(),
        port: parse_port(get(r, &["port"])),
        protocol: get(r, &["protocol"]).into(),
        cves: cves(get(r, &["cve"])),
        cvss: cvss(get(
            r,
            &["cvss", "cvss v3.0 base score", "cvss v2.0 base score"],
        )),
        description: get(r, &["description", "desc"]).into(),
        solution: get(r, &["recommendation", "remediation", "solution"]).into(),
        evidence: get(r, &["evidence", "proof", "plugin output"]).into(),
    })
}

// ── Output ───────────────────────────────────────────────────────────────

/// host:port, or just the host.
fn location(f: &Finding) -> String {
    match f.port {
        Some(p) if !f.host.is_empty() => format!("{}:{}", f.host, p),
        _ => f.host.clone(),
    }
}

fn counts(imp: &Imported) -> Vec<(&'static str, usize)> {
    SEVERITIES
        .iter()
        .map(|s| (*s, imp.findings.iter().filter(|f| f.severity == *s).count()))
        .collect()
}

pub fn format_text(imp: &Imported, file: &Path) -> String {
    let summary: Vec<String> = counts(imp)
        .iter()
        .map(|(s, n)| format!("{n} {s}"))
        .collect();
    let mut out = format!(
        "KalaScan import: {} report {}\n{} findings: {}\n\n",
        imp.format,
        file.display(),
        imp.findings.len(),
        summary.join(", ")
    );
    for f in &imp.findings {
        let loc = location(f);
        out.push_str(&format!(
            "  [{}] {}  {}",
            f.severity.to_uppercase(),
            if loc.is_empty() { "-" } else { &loc },
            f.title
        ));
        if !f.id.is_empty() && !f.title.contains(&f.id) {
            out.push_str(&format!(" ({})", f.id));
        }
        if !f.cves.is_empty() {
            out.push_str(&format!("  {}", f.cves.join(", ")));
        }
        if let Some(score) = f.cvss {
            out.push_str(&format!("  CVSS {score}"));
        }
        out.push('\n');
    }
    out.truncate(out.trim_end().len()); // the caller's println! ends the last line
    out
}

pub fn format_json(imp: &Imported, file: &Path) -> String {
    let mut summary = serde_json::Map::new();
    summary.insert("total".into(), imp.findings.len().into());
    for (s, n) in counts(imp) {
        summary.insert(s.into(), n.into());
    }
    serde_json::to_string_pretty(&json!({
        "format": imp.format,
        "file": file.display().to_string(),
        "summary": summary,
        "truncated": imp.truncated,
        "findings": imp.findings,
    }))
    .unwrap_or_else(|_| "{}".to_string())
}

/// One rule per tool id; results carry a logical host:port location, not a
/// file, so this is for SARIF viewers (GitHub Code Scanning needs files).
pub fn format_sarif(imp: &Imported) -> String {
    let mut rules: Vec<Value> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut results = Vec::new();
    for f in &imp.findings {
        let key = if f.id.is_empty() { &f.title } else { &f.id };
        let id = export::rule_id(&format!("{}-{}", f.tool, key));
        let rule_index = *index.entry(id.clone()).or_insert_with(|| {
            let mut rule = json!({
                "id": id,
                "name": f.title,
                "shortDescription": { "text": f.title },
                "defaultConfiguration": { "level": export::sarif_level(f.severity) },
            });
            if !f.description.is_empty() {
                rule["fullDescription"] = json!({ "text": f.description });
            }
            if !f.solution.is_empty() {
                rule["help"] = json!({ "text": f.solution });
            }
            rules.push(rule);
            rules.len() - 1
        });
        let loc = location(f);
        let mut result = json!({
            "ruleId": id,
            "ruleIndex": rule_index,
            "level": export::sarif_level(f.severity),
            "message": { "text": if loc.is_empty() { f.title.clone() } else { format!("{} on {}", f.title, loc) } },
            "properties": { "severity": f.severity, "cves": f.cves, "cvss": f.cvss },
        });
        if !loc.is_empty() {
            result["locations"] = json!([{ "logicalLocations": [{ "name": loc }] }]);
        }
        results.push(result);
    }
    export::sarif_log(rules, results)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/import")
            .join(name)
    }

    fn fixture(name: &str) -> Imported {
        import(&path(name)).unwrap()
    }

    fn severities(i: &Imported) -> Vec<&str> {
        i.findings.iter().map(|f| f.severity).collect()
    }

    #[test]
    fn nessus_items_keep_host_port_cves_and_cvss() {
        let i = fixture("nessus.nessus");
        assert_eq!(i.format, "nessus");
        assert_eq!(severities(&i), ["critical", "high", "info"]);
        let ssh = &i.findings[0];
        assert_eq!(ssh.id, "67890");
        assert_eq!(
            (ssh.host.as_str(), ssh.port, ssh.protocol.as_str()),
            ("192.168.1.100", Some(22), "tcp")
        );
        assert_eq!(ssh.cves, ["CVE-2008-5161", "CVE-2023-48795"]);
        assert_eq!(ssh.cvss, Some(5.9));
        assert_eq!(ssh.evidence, "Weak cipher: 3des-cbc detected");
        assert!(i.findings[1].solution.starts_with("Renew the SSL"));
        assert!(format_text(&i, Path::new("x")).contains(
            "[CRITICAL] 192.168.1.100:22  SSH Weak Cipher Enabled (67890)  CVE-2008-5161, CVE-2023-48795  CVSS 5.9"
        ));
    }

    #[test]
    fn nmap_reports_open_ports_and_accepts_its_doctype() {
        // The fixture starts with <!DOCTYPE nmaprun>, as real nmap -oX output does.
        let i = fixture("nmap.xml");
        assert_eq!(i.format, "nmap");
        let got: Vec<_> = i
            .findings
            .iter()
            .map(|f| (f.host.as_str(), f.port, f.severity))
            .collect();
        assert_eq!(
            got,
            [
                ("192.168.1.1", Some(22), "low"),
                ("192.168.1.1", Some(80), "low")
            ]
        );
        assert_eq!(i.findings[0].title, "Open port 22/tcp (ssh)");
        assert_eq!(i.findings[0].evidence, "OpenSSH 8.2p1 Ubuntu 4ubuntu0.5");
    }

    #[test]
    fn burp_issues_take_host_and_port_from_the_url() {
        let i = fixture("burp.xml");
        assert_eq!(i.format, "burp");
        assert_eq!(severities(&i), ["high", "medium"]);
        let sqli = &i.findings[0];
        assert_eq!(
            (sqli.title.as_str(), sqli.id.as_str()),
            ("SQL Injection", "5244416")
        );
        assert_eq!(
            (sqli.host.as_str(), sqli.port, sqli.protocol.as_str()),
            ("example.com", Some(443), "https")
        );
        assert_eq!(sqli.evidence, "/api/users?id=1");
        assert!(sqli.solution.starts_with("Use parameterized queries"));
    }

    #[test]
    fn zap_json_and_xml_map_alike() {
        let j = fixture("zap.json");
        assert_eq!(j.format, "zap");
        assert_eq!(severities(&j), ["high", "medium"]);
        assert_eq!(j.findings[0].title, "Absence of Anti-CSRF Tokens");
        assert_eq!(
            (j.findings[0].host.as_str(), j.findings[0].port),
            ("localhost", Some(8080))
        );

        let x = fixture("zap.xml");
        assert_eq!(x.format, "zap");
        assert_eq!(severities(&x), ["high", "medium", "info"]);
        let xss = &x.findings[0];
        assert_eq!(xss.id, "40012");
        assert_eq!(
            (xss.host.as_str(), xss.port),
            ("shop.example.com", Some(443))
        );
        assert_eq!(
            xss.evidence,
            "https://shop.example.com/search?q=%3Cscript%3E\n<script>alert(1);</script>"
        );
        assert!(xss.description.starts_with("<p>Cross-site"));
        assert_eq!(
            x.findings[2].title,
            "Server Leaks Information via \"X-Powered-By\""
        );
    }

    #[test]
    fn nuclei_array_and_jsonl() {
        let a = fixture("nuclei.json");
        assert_eq!(a.format, "nuclei");
        assert_eq!(severities(&a), ["high", "info"]);
        let panel = &a.findings[0];
        assert_eq!(
            (panel.id.as_str(), panel.title.as_str()),
            ("exposed-panel", "Exposed Login Panel")
        );
        assert_eq!(
            (panel.host.as_str(), panel.port),
            ("192.168.1.100", Some(80))
        );
        assert_eq!(
            (a.findings[1].host.as_str(), a.findings[1].port),
            ("localhost", Some(3389))
        );

        // The last line is cut off and skipped.
        let l = fixture("nuclei.jsonl");
        assert_eq!(severities(&l), ["critical", "info"]);
        let log4j = &l.findings[0];
        assert_eq!(log4j.cves, ["CVE-2021-44228"]);
        assert_eq!(log4j.cvss, Some(10.0));
        assert_eq!(
            (log4j.host.as_str(), log4j.port),
            ("app.example.com", Some(8443))
        );
        assert!(log4j.solution.starts_with("Upgrade"));
        assert_eq!(
            (l.findings[1].host.as_str(), l.findings[1].port),
            ("203.0.113.10", Some(22))
        );
    }

    #[test]
    fn qualys_vulns_practices_and_infos() {
        // Carries an external DOCTYPE, which is never fetched.
        let i = fixture("qualys.xml");
        assert_eq!(i.format, "qualys");
        assert_eq!(severities(&i), ["critical", "medium", "info"]);
        let v = &i.findings[0];
        assert_eq!(
            (v.id.as_str(), v.host.as_str(), v.port),
            ("150262", "198.51.100.20", Some(443))
        );
        assert_eq!(v.cves, ["CVE-2021-41773", "CVE-2021-42013"]); // Bugtraq id dropped
        assert_eq!(v.cvss, Some(9.8));
        assert_eq!(v.evidence, "Server: Apache/2.4.49 (Unix)");
        assert_eq!(i.findings[1].port, Some(22));
        // A <CAT> without a port does not inherit the previous one.
        assert_eq!(i.findings[2].port, None);
    }

    #[test]
    fn csv_with_quoted_fields() {
        let i = fixture("findings.csv");
        assert_eq!(i.format, "csv");
        assert_eq!(severities(&i), ["high", "medium", "info"]);
        let php = &i.findings[0];
        assert_eq!(
            (php.id.as_str(), php.host.as_str(), php.port),
            ("58987", "10.0.0.5", Some(80))
        );
        assert_eq!(php.cves, ["CVE-2012-1823"]);
        assert_eq!(php.cvss, Some(7.5));
        assert!(php.description.contains("remote host\nis no longer"));
        assert!(i.findings[2]
            .description
            .contains("type, \"and the version\", of"));
    }

    #[test]
    fn entity_declarations_are_refused() {
        let err = import(&path("xxe.xml")).unwrap_err().to_string();
        assert!(err.contains("entity declarations"), "{err}");
        let lol = r#"<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]><issues><issue><name>&lol2;</name></issue></issues>"#;
        assert!(parse(lol).is_err());
    }

    #[test]
    fn malformed_xml_is_an_error() {
        for xml in [
            "<nmaprun><host><ports>",
            "<issues><issue><name>x<severity>High</severity></issue></issues>",
        ] {
            assert!(parse(xml).is_err(), "{xml}");
        }
    }

    #[test]
    fn oversize_files_are_refused_before_reading() {
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len(MAX_REPORT_BYTES + 1).unwrap(); // sparse
        let err = import(file.path()).unwrap_err().to_string();
        assert!(err.contains("refused"), "{err}");
    }

    #[test]
    fn unknown_formats_list_the_supported_ones() {
        for text in [
            "just some notes\n",
            "<html><body/></html>",
            r#"{"a": 1}"#,
            "",
        ] {
            let err = parse(text).unwrap_err().to_string();
            assert!(
                err.contains("Nessus") && err.contains("Qualys"),
                "{text}: {err}"
            );
        }
    }

    #[test]
    fn stops_at_the_findings_cap() {
        let i = parse(&format!("title\n{}", "x\n".repeat(MAX_FINDINGS + 5))).unwrap();
        assert!(i.truncated);
        assert_eq!(i.findings.len(), MAX_FINDINGS);
    }

    #[test]
    fn sarif_has_one_rule_per_id_and_logical_locations() {
        let sarif: Value = serde_json::from_str(&format_sarif(&fixture("nessus.nessus"))).unwrap();
        assert_eq!(sarif["version"], "2.1.0");
        let run = &sarif["runs"][0];
        let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
        let results = run["results"].as_array().unwrap();
        assert_eq!((rules.len(), results.len()), (3, 3));
        for r in results {
            let index = r["ruleIndex"].as_u64().unwrap() as usize;
            assert_eq!(rules[index]["id"], r["ruleId"]);
        }
        let first = &results[0];
        assert_eq!(first["ruleId"], "nessus-67890");
        assert_eq!(first["level"], "error");
        assert_eq!(
            first["locations"][0]["logicalLocations"][0]["name"],
            "192.168.1.100:22"
        );
        assert!(first["locations"][0].get("physicalLocation").is_none());
        assert_eq!(first["properties"]["cves"][1], "CVE-2023-48795");

        let same_plugin = parse("Plugin ID,Name,Host\n1,A,h1\n1,A,h2\n").unwrap();
        let sarif: Value = serde_json::from_str(&format_sarif(&same_plugin)).unwrap();
        assert_eq!(
            sarif["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), 2);
    }
}
