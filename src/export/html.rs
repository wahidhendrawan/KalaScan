//! HTML report: one self-contained page per scan.

use super::*;

/// The report's whole stylesheet: a rule for each utility class the page
/// uses, values as in Tailwind 3. The page loads nothing, so it opens
/// offline and behind the server's Content-Security-Policy. A class used
/// below without a rule here fails `html_report_loads_nothing`.
pub(super) const REPORT_CSS: &str = include_str!("report.css");

pub fn export_html(result: &ScanResult) -> String {
    let level = risk_score_to_level(result.risk_score);
    let (badge_class, badge_label) = render_risk_badge(result.risk_score);

    let severity_class = |s: &str| -> &str {
        match s {
            "critical" => "bg-red-700 text-white",
            "high" => "bg-orange-600 text-white",
            "medium" => "bg-yellow-500 text-black",
            _ => "bg-gray-500 text-white",
        }
    };

    let ai_section = match &result.ai_analysis {
        Some(ai) => format!(
            r#"
      <div class="mb-6">
        <h2 class="text-xl font-semibold text-gray-100 mb-3">AI Deep Analysis</h2>
        <div class="grid grid-cols-2 gap-3 mb-3">
          <div class="bg-gray-800 p-3 rounded"><span class="text-gray-400">Malicious:</span> <span class="{}">{}</span></div>
          <div class="bg-gray-800 p-3 rounded"><span class="text-gray-400">Type:</span> {}</div>
          <div class="bg-gray-800 p-3 rounded col-span-2"><span class="text-gray-400">Threat:</span> {}</div>
          <div class="bg-gray-800 p-3 rounded col-span-2"><span class="text-gray-400">Recommendation:</span> <strong>{}</strong></div>
        </div>
        {}
      </div>"#,
            if ai.is_malicious { "text-red-400 font-bold" } else { "text-green-400" },
            if ai.is_malicious { "YES" } else { "No" },
            escape_html(&ai.malware_type),
            escape_html(&ai.threat_summary),
            escape_html(&ai.recommendation),
            if ai.suspicious_lines.is_empty() {
                String::new()
            } else {
                let lines_html: Vec<String> = ai
                    .suspicious_lines
                    .iter()
                    .map(|l| format!("            <li><code>{}</code></li>", escape_html(l)))
                    .collect();
                format!(
                    "        <h3 class=\"text-lg font-medium text-gray-200 mb-2\">Suspicious Code</h3>\n        <ul class=\"list-disc list-inside space-y-1 text-sm font-mono text-gray-300 bg-gray-900 p-3 rounded\">\n{}\n        </ul>",
                    lines_html.join("\n")
                )
            },
        ),
        None => concat!(
            "      <div class=\"mb-6\">\n",
            "        <h2 class=\"text-xl font-semibold text-gray-100 mb-3\">AI Deep Analysis</h2>\n",
            "        <p class=\"text-gray-400 italic\">AI analysis was not performed.</p>\n",
            "      </div>"
        ).to_string(),
    };

    let matches_section = if result.rule_matches.is_empty() {
        "<p class=\"text-gray-400 italic\">No rule matches found.</p>".to_string()
    } else {
        let mut sorted = result.rule_matches.clone();
        sorted.sort_by_key(|m| severity_sort_key(&m.severity));

        let rows: Vec<String> = sorted
            .iter()
            .map(|m| {
                let ctx_safe = escape_html(&m.context);
                let ctx_trunc: String = ctx_safe.chars().take(120).collect();
                let ctx_display = ctx_trunc.replace('\n', "<br>");
                let sev_cls = severity_class(&m.severity);

                format!(
                    r#"          <tr class="border-b border-gray-700 hover:bg-gray-800">
            <td class="py-2 px-3"><span class="inline-block px-2 py-0.5 rounded text-xs font-semibold {}">{}</span></td>
            <td class="py-2 px-3">{}</td>
            <td class="py-2 px-3 text-sm">{}</td>
            <td class="py-2 px-3 text-right text-sm text-gray-400">{}</td>
            <td class="py-2 px-3 text-xs font-mono text-gray-300">{}</td>
          </tr>"#,
                    sev_cls, m.severity, escape_html(&m.matched_pattern), escape_html(&m.file_path), m.line_number, ctx_display,
                )
            })
            .collect();

        format!(
            r#"      <div class="mb-6">
        <h2 class="text-xl font-semibold text-gray-100 mb-3">Rule Matches <span class="text-sm font-normal text-gray-400">({} total)</span></h2>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm">
            <thead>
              <tr class="border-b border-gray-600 text-gray-400 uppercase text-xs">
                <th class="py-2 px-3">Severity</th>
                <th class="py-2 px-3">Pattern</th>
                <th class="py-2 px-3">File</th>
                <th class="py-2 px-3 text-right">Line</th>
                <th class="py-2 px-3">Context</th>
              </tr>
            </thead>
            <tbody>
{}
            </tbody>
          </table>
        </div>
      </div>"#,
            result.rule_matches.len(),
            rows.join("\n"),
        )
    };

    let deobfuscation_section = html_deobfuscation(result);
    let emulation_section = html_emulation(result);
    let sandbox_section = html_sandbox(result);
    let ttp_section = html_ttp(result);

    let warnings_section = if result.warnings.is_empty() {
        String::new()
    } else {
        let items: Vec<String> = result
            .warnings
            .iter()
            .map(|w| format!("<li>{}</li>", escape_html(w)))
            .collect();
        format!(
            r#"<div class="mb-6 rounded border border-yellow-600 bg-yellow-900/40 p-3 text-sm text-yellow-200" role="alert">
      <h2 class="font-semibold mb-1">Warnings</h2>
      <ul class="list-disc list-inside">{}</ul>
    </div>"#,
            items.join("")
        )
    };

    let triage_section = match &result.triage {
        None => concat!(
            "      <div class=\"mb-6\">\n",
            "        <h2 class=\"text-xl font-semibold text-gray-100 mb-3\">Deep Static Triage</h2>\n",
            "        <p class=\"text-gray-400 italic\">Deep static triage was not performed.</p>\n",
            "      </div>"
        ).to_string(),
        Some(triage) => {
            let file_types: Vec<String> = triage
                .file_types
                .iter()
                .map(|kind| {
                    format!(
                        "<span class=\"inline-block bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs mr-1 mb-1\">{} <strong class=\"text-blue-400\">{}</strong></span>",
                        escape_html(&kind.kind),
                        kind.count
                    )
                })
                .collect();

            let techniques: Vec<String> = triage
                .attack_techniques
                .iter()
                .map(|technique| {
                    format!(
                        "<span class=\"inline-block bg-purple-500/10 border border-purple-500/30 text-purple-300 rounded px-2 py-1 text-xs mr-1 mb-1\" title=\"{}\"{}<strong>{}</strong> {}</span>",
                        escape_html(&technique.tactic),
                        ">",
                        escape_html(&technique.id),
                        escape_html(&technique.name),
                    )
                })
                .collect();

            let binary_rows: Vec<String> = triage
                .binaries
                .iter()
                .map(|binary| {
                    let packer = match &binary.packer {
                        Some(packer) => format!(
                            "<span class=\"text-amber-400\">{}</span> <span class=\"text-gray-500\">({})</span><div class=\"text-xs text-gray-500\">{}</div>",
                            escape_html(&packer.name),
                            escape_html(&packer.confidence),
                            escape_html(&packer.evidence),
                        ),
                        None => "<span class=\"text-gray-600\">-</span>".to_string(),
                    };
                    let indicators = if binary.indicators.is_empty() {
                        String::new()
                    } else {
                        format!(
                            "<div class=\"text-xs text-gray-500 mt-1\">{}</div>",
                            escape_html(&binary.indicators.join("; "))
                        )
                    };
                    format!(
                        r#"          <tr class="border-b border-gray-700 hover:bg-gray-800 align-top">
            <td class="py-2 px-3 font-mono text-xs text-blue-400">{}</td>
            <td class="py-2 px-3 text-xs">{}<div class="text-gray-500">{}</div></td>
            <td class="py-2 px-3 text-xs">{}</td>
            <td class="py-2 px-3 text-right text-xs">{:.2}</td>
            <td class="py-2 px-3 font-mono text-[10px] text-gray-400 break-all">{}</td>
            <td class="py-2 px-3 text-xs">{}{}</td>
          </tr>"#,
                        escape_html(&binary.path),
                        escape_html(&binary.file_type),
                        binary
                            .architecture
                            .as_deref()
                            .map(escape_html)
                            .unwrap_or_else(|| "unknown".to_string()),
                        binary.bits.map(|bits| format!("{}-bit", bits)).unwrap_or_default(),
                        binary.entropy,
                        escape_html(&binary.sha256),
                        packer,
                        indicators,
                    )
                })
                .collect();

            let capability_rows: Vec<String> = triage
                .capabilities
                .iter()
                .map(|capability| {
                    let attack = if capability.attack.is_empty() {
                        "-".to_string()
                    } else {
                        capability
                            .attack
                            .iter()
                            .map(|technique| escape_html(&technique.id))
                            .collect::<Vec<_>>()
                            .join(", ")
                    };
                    format!(
                        r#"          <tr class="border-b border-gray-700 hover:bg-gray-800 align-top">
            <td class="py-2 px-3"><span class="inline-block px-2 py-0.5 rounded text-xs font-semibold {}">{}</span></td>
            <td class="py-2 px-3 text-xs text-gray-400">{}</td>
            <td class="py-2 px-3 text-xs">{}</td>
            <td class="py-2 px-3 font-mono text-[10px] text-gray-400">{}</td>
            <td class="py-2 px-3 text-xs text-purple-300">{}</td>
          </tr>"#,
                        severity_class(&capability.severity),
                        escape_html(&capability.severity),
                        escape_html(&capability.source),
                        escape_html(&capability.name),
                        escape_html(&capability.file_path),
                        attack,
                    )
                })
                .collect();

            let tools: Vec<String> = triage
                .tools
                .iter()
                .map(|tool| {
                    format!(
                        "<span class=\"inline-block rounded px-2 py-1 text-xs mr-1 mb-1 {}\">{}: {}</span>",
                        if tool.available {
                            "bg-green-500/10 border border-green-500/30 text-green-300"
                        } else {
                            "bg-gray-800 border border-gray-700 text-gray-500"
                        },
                        escape_html(&tool.name),
                        escape_html(tool.version.as_deref().unwrap_or(&tool.status)),
                    )
                })
                .collect();

            let notes: Vec<String> = triage
                .notes
                .iter()
                .map(|note| format!("<li>{}</li>", escape_html(note)))
                .collect();

            format!(
                r#"      <div class="mb-6">
        <h2 class="text-xl font-semibold text-gray-100 mb-3">Deep Static Triage</h2>
        <div class="grid grid-cols-2 md:grid-cols-5 gap-3 mb-4">
          <div class="bg-gray-800 p-3 rounded text-center"><div class="text-2xl font-bold text-gray-100">{files}</div><div class="text-xs text-gray-400 mt-1">Files Analyzed</div></div>
          <div class="bg-gray-800 p-3 rounded text-center"><div class="text-2xl font-bold text-blue-400">{binaries}</div><div class="text-xs text-gray-400 mt-1">Binaries</div></div>
          <div class="bg-gray-800 p-3 rounded text-center"><div class="text-2xl font-bold text-orange-400">{capabilities}</div><div class="text-xs text-gray-400 mt-1">Capabilities</div></div>
          <div class="bg-gray-800 p-3 rounded text-center"><div class="text-2xl font-bold text-purple-400">{techniques_count}</div><div class="text-xs text-gray-400 mt-1">ATT&CK</div></div>
          <div class="bg-gray-800 p-3 rounded text-center"><div class="text-2xl font-bold text-green-400">{deep}</div><div class="text-xs text-gray-400 mt-1">Deep Tools</div></div>
        </div>
        <div class="mb-4"><div class="text-xs text-gray-500 mb-1">File Types</div>{file_types}</div>
        <div class="mb-4"><div class="text-xs text-gray-500 mb-1">MITRE ATT&CK</div>{techniques}</div>
        <h3 class="text-lg font-medium text-gray-200 mb-2">Binaries</h3>
        <div class="overflow-x-auto mb-4">
          <table class="w-full text-left text-sm">
            <thead><tr class="border-b border-gray-600 text-gray-400 uppercase text-xs"><th class="py-2 px-3">File</th><th class="py-2 px-3">Type</th><th class="py-2 px-3">Arch</th><th class="py-2 px-3 text-right">Entropy</th><th class="py-2 px-3">SHA-256</th><th class="py-2 px-3">Packer / Indicators</th></tr></thead>
            <tbody>{binary_rows}</tbody>
          </table>
        </div>
        <h3 class="text-lg font-medium text-gray-200 mb-2">Capabilities</h3>
        <div class="overflow-x-auto mb-4">
          <table class="w-full text-left text-sm">
            <thead><tr class="border-b border-gray-600 text-gray-400 uppercase text-xs"><th class="py-2 px-3">Severity</th><th class="py-2 px-3">Source</th><th class="py-2 px-3">Capability</th><th class="py-2 px-3">File</th><th class="py-2 px-3">ATT&CK</th></tr></thead>
            <tbody>{capability_rows}</tbody>
          </table>
        </div>
        <div class="mb-4"><div class="text-xs text-gray-500 mb-1">Deep Analysis Tools</div>{tools}</div>
        <div class="text-xs text-gray-500"><ul class="list-disc list-inside">{notes}</ul></div>
      </div>"#,
                files = triage.files_scanned,
                binaries = triage.binaries.len(),
                capabilities = triage.capabilities.len(),
                techniques_count = triage.attack_techniques.len(),
                deep = if triage.deep { "enabled" } else { "off" },
                file_types = file_types.join(""),
                techniques = if techniques.is_empty() { "<span class=\"text-gray-600\">None mapped</span>".to_string() } else { techniques.join("") },
                binary_rows = if binary_rows.is_empty() { "<tr><td colspan=\"6\" class=\"py-3 px-3 text-gray-500 italic\">No binaries found.</td></tr>".to_string() } else { binary_rows.join("\n") },
                capability_rows = if capability_rows.is_empty() { "<tr><td colspan=\"5\" class=\"py-3 px-3 text-gray-500 italic\">No capabilities mapped.</td></tr>".to_string() } else { capability_rows.join("\n") },
                tools = if tools.is_empty() { "<span class=\"text-gray-600\">Deep triage disabled.</span>".to_string() } else { tools.join("") },
                notes = if notes.is_empty() { "<li>None.</li>".to_string() } else { notes.join("") },
            )
        }
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>KalaScan Report — {repo_url}</title>
  <style>{css}</style>
</head>
<body class="bg-gray-950 text-gray-200 min-h-screen">
  <div class="max-w-5xl mx-auto px-4 py-8">

    <!-- Header -->
    <div class="mb-8">
      <h1 class="text-3xl font-bold text-gray-100 mb-2">KalaScan Report</h1>
      <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm text-gray-400">
        <dt class="font-medium">Repository</dt>
        <dd class="font-mono">{repo_url}</dd>
        <dt class="font-medium">Scan ID</dt>
        <dd class="font-mono text-xs">{id}</dd>
        <dt class="font-medium">Timestamp</dt>
        <dd>{timestamp}</dd>
        <dt class="font-medium">Status</dt>
        <dd>{status}</dd>
      </dl>
    </div>

    <!-- Risk Score Badge -->
    <div class="mb-6">
      <span class="inline-block px-4 py-2 rounded-lg text-lg font-bold {badge_class}">{badge_label}</span>
      <span class="ml-2 text-sm text-gray-400 uppercase">{level}</span>
    </div>

    <!-- Warnings -->
    {warnings_section}

    <!-- Summary Table -->
    <div class="mb-6">
      <h2 class="text-xl font-semibold text-gray-100 mb-3">Summary</h2>
      <div class="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div class="bg-gray-800 p-3 rounded text-center">
          <div class="text-2xl font-bold text-gray-100">{total_files}</div>
          <div class="text-xs text-gray-400 mt-1">Total Files</div>
        </div>
        <div class="bg-gray-800 p-3 rounded text-center">
          <div class="text-2xl font-bold text-blue-400">{scanned_files}</div>
          <div class="text-xs text-gray-400 mt-1">Scanned</div>
        </div>
        <div class="bg-gray-800 p-3 rounded text-center">
          <div class="text-2xl font-bold text-orange-400">{matches}</div>
          <div class="text-xs text-gray-400 mt-1">Matches</div>
        </div>
        <div class="bg-gray-800 p-3 rounded text-center">
          <div class="text-2xl font-bold text-purple-400">{ai_status}</div>
          <div class="text-xs text-gray-400 mt-1">AI Analysis</div>
        </div>
        <div class="bg-gray-800 p-3 rounded text-center">
          <div class="text-2xl font-bold {risk_text}">{risk_score}</div>
          <div class="text-xs text-gray-400 mt-1">Risk Score</div>
        </div>
      </div>
    </div>

    <!-- AI Analysis -->
    {ai_section}

    <!-- Deep Static Triage -->
    {triage_section}

    <!-- Deobfuscation -->
    {deobfuscation_section}

    <!-- Safe Static Emulation -->
    {emulation_section}

    <!-- Docker Sandbox -->
    {sandbox_section}

    <!-- TTP Coverage -->
    {ttp_section}

    <!-- Rule Matches -->
    {matches_section}

    <!-- Footer -->
    <footer class="mt-12 pt-4 border-t border-gray-800 text-center text-xs text-gray-600">
      Generated by KalaScan v{version}
    </footer>
  </div>
</body>
</html>"#,
        css = REPORT_CSS.trim_end(),
        repo_url = escape_html(&result.repo_url),
        id = escape_html(&result.id),
        version = env!("CARGO_PKG_VERSION"),
        timestamp = escape_html(&result.timestamp),
        status = escape_html(&result.status),
        badge_class = badge_class,
        badge_label = badge_label,
        level = level.to_uppercase(),
        total_files = result.total_files,
        scanned_files = result.scanned_files,
        matches = result.total_matches,
        ai_status = if result.ai_analysis.is_some() {
            "Yes"
        } else {
            "N/A"
        },
        risk_score = result.risk_score,
        risk_text = match level {
            "safe" => "text-green-400",
            "warning" => "text-yellow-400",
            _ => "text-red-400",
        },
        warnings_section = warnings_section,
        ai_section = ai_section,
        triage_section = triage_section,
        deobfuscation_section = deobfuscation_section,
        emulation_section = emulation_section,
        sandbox_section = sandbox_section,
        ttp_section = ttp_section,
        matches_section = matches_section,
    )
}

fn html_deobfuscation(result: &ScanResult) -> String {
    match &result.deobfuscation {
        None => concat!(
            "      <div class=\"mb-6\">\n",
            "        <h2 class=\"text-xl font-semibold text-gray-100 mb-3\">Deobfuscation</h2>\n",
            "        <p class=\"text-gray-400 italic\">Deobfuscation was not performed.</p>\n",
            "      </div>"
        )
        .to_string(),
        Some(report) => {
            let rows: Vec<String> = report
                .artifacts
                .iter()
                .map(|artifact| {
                    let decoded: String = artifact.decoded.chars().take(200).collect();
                    format!(
                        r#"          <tr class="border-b border-gray-700 hover:bg-gray-800 align-top">
            <td class="py-2 px-3 text-xs"><span class="inline-block px-2 py-0.5 rounded bg-gray-800 border border-gray-700">{}</span></td>
            <td class="py-2 px-3 text-xs">{}</td>
            <td class="py-2 px-3 font-mono text-[10px] text-blue-400">{}</td>
            <td class="py-2 px-3 text-right text-xs">{}</td>
            <td class="py-2 px-3 text-xs text-amber-300">{}</td>
            <td class="py-2 px-3 text-xs font-mono break-all text-gray-300">{}</td>
          </tr>"#,
                        escape_html(&artifact.confidence),
                        escape_html(&artifact.encoding),
                        escape_html(&artifact.file_path),
                        artifact.line_number,
                        escape_html(&artifact.indicators.join(", ")),
                        escape_html(&decoded),
                    )
                })
                .collect();

            let techniques: Vec<String> = report
                .attack_techniques
                .iter()
                .map(|technique| {
                    format!(
                        "<span class=\"inline-block bg-purple-500/10 border border-purple-500/30 text-purple-300 rounded px-2 py-1 text-xs mr-1 mb-1\"><strong>{}</strong> {}</span>",
                        escape_html(&technique.id),
                        escape_html(&technique.name),
                    )
                })
                .collect();

            let notes: Vec<String> = report
                .notes
                .iter()
                .map(|note| format!("<li>{}</li>", escape_html(note)))
                .collect();

            format!(
                r#"      <div class="mb-6">
        <h2 class="text-xl font-semibold text-gray-100 mb-3">Deobfuscation</h2>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
          <div class="bg-gray-800 p-3 rounded text-center"><div class="text-2xl font-bold text-gray-100">{files}</div><div class="text-xs text-gray-400 mt-1">Files Analyzed</div></div>
          <div class="bg-gray-800 p-3 rounded text-center"><div class="text-2xl font-bold text-orange-400">{artifacts}</div><div class="text-xs text-gray-400 mt-1">Artifacts</div></div>
          <div class="bg-gray-800 p-3 rounded text-center"><div class="text-2xl font-bold text-purple-400">{techniques_count}</div><div class="text-xs text-gray-400 mt-1">ATT&CK</div></div>
          <div class="bg-gray-800 p-3 rounded text-center"><div class="text-xs text-gray-400 mt-1">Engine</div><div class="text-xs font-mono text-gray-300 mt-1">{engine}</div></div>
        </div>
        <div class="mb-4">{techniques}</div>
        <div class="overflow-x-auto mb-4">
          <table class="w-full text-left text-sm">
            <thead><tr class="border-b border-gray-600 text-gray-400 uppercase text-xs"><th class="py-2 px-3">Confidence</th><th class="py-2 px-3">Encoding</th><th class="py-2 px-3">File</th><th class="py-2 px-3 text-right">Line</th><th class="py-2 px-3">Indicators</th><th class="py-2 px-3">Decoded Preview</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </div>
        <div class="text-xs text-gray-500"><ul class="list-disc list-inside">{notes}</ul></div>
      </div>"#,
                files = report.files_scanned,
                artifacts = report.artifacts.len(),
                techniques_count = report.attack_techniques.len(),
                engine = escape_html(&report.engine),
                techniques = if techniques.is_empty() {
                    "<span class=\"text-gray-600\">No ATT&CK techniques mapped.</span>".to_string()
                } else {
                    techniques.join("")
                },
                rows = if rows.is_empty() {
                    "<tr><td colspan=\"6\" class=\"py-3 px-3 text-gray-500 italic\">No encoded payloads recovered.</td></tr>".to_string()
                } else {
                    rows.join("\n")
                },
                notes = if notes.is_empty() {
                    "<li>None.</li>".to_string()
                } else {
                    notes.join("")
                },
            )
        }
    }
}

fn html_emulation(result: &ScanResult) -> String {
    match &result.emulation {
        None => concat!(
            "      <div class=\"mb-6\">\n",
            "        <h2 class=\"text-xl font-semibold text-gray-100 mb-3\">Safe Static Emulation</h2>\n",
            "        <p class=\"text-gray-400 italic\">Static emulation was not performed.</p>\n",
            "      </div>"
        )
        .to_string(),
        Some(report) => {
            let traces: Vec<String> = report
                .traces
                .iter()
                .map(|trace| {
                    let api_calls = if trace.api_calls.is_empty() {
                        "-".to_string()
                    } else {
                        trace.api_calls.join(", ")
                    };
                    let strings = if trace.recovered_strings.is_empty() {
                        "-".to_string()
                    } else {
                        trace.recovered_strings.join(" | ")
                    };
                    let indicators = if trace.indicators.is_empty() {
                        "-".to_string()
                    } else {
                        trace.indicators.join("; ")
                    };
                    let api_and_indicators = format!(
                        "<div>{}</div><div class=\"text-amber-300 mt-1\">{}</div>",
                        escape_html(&api_calls),
                        escape_html(&indicators)
                    );
                    let attack = if trace.attack.is_empty() {
                        "-".to_string()
                    } else {
                        trace
                            .attack
                            .iter()
                            .map(|technique| technique.id.clone())
                            .collect::<Vec<_>>()
                            .join(", ")
                    };
                    format!(
                        r#"          <tr class="border-b border-gray-700 hover:bg-gray-800 align-top">
            <td class="py-2 px-3 font-mono text-xs text-blue-400">{}</td>
            <td class="py-2 px-3 text-xs">{}<div class="text-gray-500">entry {}</div></td>
            <td class="py-2 px-3 text-right text-xs">{}</td>
            <td class="py-2 px-3 text-xs">{}</td>
            <td class="py-2 px-3 text-xs text-amber-300">{}</td>
            <td class="py-2 px-3 text-xs font-mono break-all text-gray-300">{}</td>
            <td class="py-2 px-3 text-xs text-purple-300">{}</td>
          </tr>"#,
                        escape_html(&trace.file_path),
                        escape_html(&trace.architecture),
                        escape_html(&trace.entrypoint),
                        trace.instructions,
                        escape_html(&trace.stopped_reason),
                        api_and_indicators,
                        escape_html(&strings),
                        escape_html(&attack),
                    )
                })
                .collect();

            let notes: Vec<String> = report
                .notes
                .iter()
                .map(|note| format!("<li>{}</li>", escape_html(note)))
                .collect();

            format!(
                r#"      <div class="mb-6">
        <h2 class="text-xl font-semibold text-gray-100 mb-3">Safe Static Emulation</h2>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
          <div class="bg-gray-800 p-3 rounded text-center"><div class="text-2xl font-bold text-gray-100">{files}</div><div class="text-xs text-gray-400 mt-1">Files Analyzed</div></div>
          <div class="bg-gray-800 p-3 rounded text-center"><div class="text-2xl font-bold text-blue-400">{traces}</div><div class="text-xs text-gray-400 mt-1">Traces</div></div>
          <div class="bg-gray-800 p-3 rounded text-center"><div class="text-2xl font-bold text-purple-400">{techniques}</div><div class="text-xs text-gray-400 mt-1">ATT&CK</div></div>
          <div class="bg-gray-800 p-3 rounded text-center"><div class="text-xs text-gray-400 mt-1">Engine</div><div class="text-xs font-mono text-gray-300 mt-1">{engine}</div></div>
        </div>
        <div class="overflow-x-auto mb-4">
          <table class="w-full text-left text-sm">
            <thead><tr class="border-b border-gray-600 text-gray-400 uppercase text-xs"><th class="py-2 px-3">File</th><th class="py-2 px-3">Arch</th><th class="py-2 px-3 text-right">Instructions</th><th class="py-2 px-3">Stopped</th><th class="py-2 px-3">API Calls / Indicators</th><th class="py-2 px-3">Recovered Strings</th><th class="py-2 px-3">ATT&CK</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </div>
        <div class="text-xs text-gray-500"><ul class="list-disc list-inside">{notes}</ul></div>
      </div>"#,
                files = report.files_scanned,
                traces = report.traces.len(),
                techniques = report.attack_techniques.len(),
                engine = escape_html(&report.engine),
                rows = if traces.is_empty() {
                    "<tr><td colspan=\"7\" class=\"py-3 px-3 text-gray-500 italic\">No emulation traces produced.</td></tr>".to_string()
                } else {
                    traces.join("\n")
                },
                notes = if notes.is_empty() {
                    "<li>None.</li>".to_string()
                } else {
                    notes.join("")
                },
            )
        }
    }
}

fn html_sandbox(result: &ScanResult) -> String {
    match &result.sandbox {
        None => concat!(
            "      <div class=\"mb-6\">\n",
            "        <h2 class=\"text-xl font-semibold text-gray-100 mb-3\">Docker Sandbox</h2>\n",
            "        <p class=\"text-gray-400 italic\">Docker sandbox was not enabled.</p>\n",
            "      </div>"
        )
        .to_string(),
        Some(report) => {
            let rows: Vec<String> = report
                .executions
                .iter()
                .map(|execution| {
                    let processes = if execution.processes.is_empty() {
                        "-".to_string()
                    } else {
                        execution.processes.join(", ")
                    };
                    let network = if execution.network_attempts.is_empty() {
                        "-".to_string()
                    } else {
                        execution.network_attempts.join(" | ")
                    };
                    let files = if execution.file_accesses.is_empty() {
                        "-".to_string()
                    } else {
                        execution.file_accesses.join(" | ")
                    };
                    let indicators = if execution.indicators.is_empty() {
                        "-".to_string()
                    } else {
                        execution.indicators.join("; ")
                    };
                    format!(
                        r#"          <tr class="border-b border-gray-700 hover:bg-gray-800 align-top">
            <td class="py-2 px-3 font-mono text-xs text-blue-400">{}</td>
            <td class="py-2 px-3 text-xs">{}</td>
            <td class="py-2 px-3 text-right text-xs">{:?}</td>
            <td class="py-2 px-3 text-right text-xs">{}</td>
            <td class="py-2 px-3 text-right text-xs">{}</td>
            <td class="py-2 px-3 text-xs">{}</td>
            <td class="py-2 px-3 text-xs text-amber-300">{}</td>
            <td class="py-2 px-3 text-xs font-mono break-all text-gray-300">{}</td>
            <td class="py-2 px-3 text-xs text-amber-300">{}</td>
          </tr>"#,
                        escape_html(&execution.file_path),
                        escape_html(&execution.architecture),
                        execution.exit_code,
                        execution.duration_ms,
                        execution.syscalls,
                        escape_html(&processes),
                        escape_html(&network),
                        escape_html(&files),
                        escape_html(&indicators),
                    )
                })
                .collect();

            let notes: Vec<String> = report
                .notes
                .iter()
                .map(|note| format!("<li>{}</li>", escape_html(note)))
                .collect();

            format!(
                r#"      <div class="mb-6">
        <h2 class="text-xl font-semibold text-gray-100 mb-3">Docker Sandbox</h2>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
          <div class="bg-gray-800 p-3 rounded text-center"><div class="text-2xl font-bold text-gray-100">{files}</div><div class="text-xs text-gray-400 mt-1">Files Analyzed</div></div>
          <div class="bg-gray-800 p-3 rounded text-center"><div class="text-2xl font-bold text-cyan-400">{executions}</div><div class="text-xs text-gray-400 mt-1">Executions</div></div>
          <div class="bg-gray-800 p-3 rounded text-center"><div class="text-2xl font-bold {available_class}">{available}</div><div class="text-xs text-gray-400 mt-1">Available</div></div>
          <div class="bg-gray-800 p-3 rounded text-center"><div class="text-xs text-gray-400 mt-1">Image</div><div class="text-xs font-mono text-gray-300 mt-1">{image}</div></div>
        </div>
        <div class="overflow-x-auto mb-4">
          <table class="w-full text-left text-sm">
            <thead><tr class="border-b border-gray-600 text-gray-400 uppercase text-xs"><th class="py-2 px-3">File</th><th class="py-2 px-3">Arch</th><th class="py-2 px-3 text-right">Exit</th><th class="py-2 px-3 text-right">ms</th><th class="py-2 px-3 text-right">Syscalls</th><th class="py-2 px-3">Processes</th><th class="py-2 px-3">Network</th><th class="py-2 px-3">Sensitive Files</th><th class="py-2 px-3">Indicators</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </div>
        <div class="text-xs text-gray-500"><ul class="list-disc list-inside">{notes}</ul></div>
      </div>"#,
                files = report.files_analyzed,
                executions = report.executions.len(),
                available = if report.available { "yes" } else { "no" },
                available_class = if report.available {
                    "text-green-400"
                } else {
                    "text-gray-500"
                },
                image = escape_html(&report.image),
                rows = if rows.is_empty() {
                    "<tr><td colspan=\"9\" class=\"py-3 px-3 text-gray-500 italic\">No sandbox executions produced.</td></tr>".to_string()
                } else {
                    rows.join("\n")
                },
                notes = if notes.is_empty() {
                    "<li>None.</li>".to_string()
                } else {
                    notes.join("")
                },
            )
        }
    }
}

fn html_ttp(result: &ScanResult) -> String {
    match &result.ttp {
        None => concat!(
            "      <div class=\"mb-6\">\n",
            "        <h2 class=\"text-xl font-semibold text-gray-100 mb-3\">TTP / ATT&CK Coverage</h2>\n",
            "        <p class=\"text-gray-400 italic\">TTP mapping was not performed.</p>\n",
            "      </div>"
        )
        .to_string(),
        Some(report) => {
            let rows: Vec<String> = report
                .techniques
                .iter()
                .map(|technique| {
                    format!(
                        r#"          <tr class="border-b border-gray-700 hover:bg-gray-800 align-top">
            <td class="py-2 px-3 text-xs uppercase text-amber-300">{}</td>
            <td class="py-2 px-3 font-mono text-xs text-purple-300">{}</td>
            <td class="py-2 px-3 text-xs">{}</td>
            <td class="py-2 px-3 text-xs text-gray-400">{}</td>
            <td class="py-2 px-3 text-right text-xs">{}</td>
            <td class="py-2 px-3 text-xs text-gray-400">{}</td>
          </tr>"#,
                        escape_html(&technique.severity),
                        escape_html(&technique.id),
                        escape_html(&technique.name),
                        escape_html(&technique.tactic),
                        technique.observations,
                        escape_html(&technique.sources.join(", ")),
                    )
                })
                .collect();

            let tactics: Vec<String> = report
                .tactics
                .iter()
                .map(|tactic| {
                    format!(
                        "<span class=\"inline-block bg-purple-500/10 border border-purple-500/30 text-purple-300 rounded px-2 py-1 text-xs mr-1 mb-1\"><strong>{}</strong> {}</span>",
                        escape_html(&tactic.tactic),
                        tactic.techniques.len(),
                    )
                })
                .collect();

            format!(
                r#"      <div class="mb-6">
        <h2 class="text-xl font-semibold text-gray-100 mb-3">TTP / ATT&CK Coverage</h2>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
          <div class="bg-gray-800 p-3 rounded text-center"><div class="text-2xl font-bold text-purple-400">{techniques}</div><div class="text-xs text-gray-400 mt-1">Techniques</div></div>
          <div class="bg-gray-800 p-3 rounded text-center"><div class="text-2xl font-bold text-blue-400">{tactics_count}</div><div class="text-xs text-gray-400 mt-1">Tactics</div></div>
          <div class="bg-gray-800 p-3 rounded text-center"><div class="text-2xl font-bold text-orange-400">{coverage}%</div><div class="text-xs text-gray-400 mt-1">Coverage</div></div>
          <div class="bg-gray-800 p-3 rounded text-center"><div class="text-xs text-gray-400 mt-1">Engine</div><div class="text-xs font-mono text-gray-300 mt-1">{engine}</div></div>
        </div>
        <div class="mb-4">{tactic_chips}</div>
        <div class="overflow-x-auto mb-4">
          <table class="w-full text-left text-sm">
            <thead><tr class="border-b border-gray-600 text-gray-400 uppercase text-xs"><th class="py-2 px-3">Severity</th><th class="py-2 px-3">ID</th><th class="py-2 px-3">Technique</th><th class="py-2 px-3">Tactic</th><th class="py-2 px-3 text-right">Obs</th><th class="py-2 px-3">Sources</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </div>
      </div>"#,
                techniques = report.techniques.len(),
                tactics_count = report.tactics.len(),
                coverage = report.coverage_score,
                engine = escape_html(&report.engine),
                tactic_chips = if tactics.is_empty() {
                    "<span class=\"text-gray-600\">No tactics observed.</span>".to_string()
                } else {
                    tactics.join("")
                },
                rows = if rows.is_empty() {
                    "<tr><td colspan=\"6\" class=\"py-3 px-3 text-gray-500 italic\">No ATT&CK techniques observed.</td></tr>".to_string()
                } else {
                    rows.join("\n")
                },
            )
        }
    }
}
