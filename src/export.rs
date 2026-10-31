use crate::ScanResult;

/// Map numeric risk score to severity level string.
pub fn risk_score_to_level(score: u8) -> &'static str {
    match score {
        0..=29 => "safe",
        30..=69 => "warning",
        _ => "danger",
    }
}

/// Return (css_class, label) for risk badge rendering.
/// Levels: safe → green, warning → yellow/amber, danger → red.
pub fn render_risk_badge(score: u8) -> (String, String) {
    match score {
        0..=29 => (
            "bg-green-600 text-white".into(),
            format!("SAFE ({})", score),
        ),
        30..=69 => (
            "bg-yellow-500 text-black".into(),
            format!("WARNING ({})", score),
        ),
        _ => (
            "bg-red-500 text-white".into(),
            format!("HIGH RISK ({})", score),
        ),
    }
}

fn severity_sort_key(s: &str) -> u8 {
    match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        _ => 3,
    }
}

// ── Markdown export ──────────────────────────────────────────────────────

pub fn export_markdown(result: &ScanResult) -> String {
    let level = risk_score_to_level(result.risk_score);
    let (_, badge) = render_risk_badge(result.risk_score);
    let mut md = String::new();

    md.push_str(&format!(
        concat!(
            "# KalaScan Report\n\n",
            "**Repository:** `{}`  \n",
            "**Scan ID:** `{}`  \n",
            "**Timestamp:** {}  \n",
            "**Status:** {}  \n\n",
            "## Risk Score\n\n",
            "**{}** — `{}`  \n\n",
            "## Summary\n\n",
            "| Metric | Value |\n",
            "|--------|-------|\n",
            "| Total Files | {} |\n",
            "| Scanned Files | {} |\n",
            "| Rule Matches | {} |\n",
            "| AI Analysis | {} |\n",
            "| Risk Level | {} |\n\n",
        ),
        result.repo_url,
        result.id,
        result.timestamp,
        result.status,
        badge,
        level.to_uppercase(),
        result.total_files,
        result.scanned_files,
        result.total_matches,
        if result.ai_analysis.is_some() {
            "Enabled"
        } else {
            "N/A"
        },
        level,
    ));

    // AI analysis section
    if let Some(ref ai) = result.ai_analysis {
        md.push_str("## AI Deep Analysis\n\n");
        md.push_str(&format!(
            concat!(
                "- **Malicious:** {}\n",
                "- **Malware Type:** {}\n",
                "- **Threat Summary:** {}\n",
                "- **Recommendation:** {}\n\n",
            ),
            if ai.is_malicious { "YES" } else { "No" },
            ai.malware_type,
            ai.threat_summary,
            ai.recommendation,
        ));

        if !ai.suspicious_lines.is_empty() {
            md.push_str("### Suspicious Code Lines\n\n");
            for line in &ai.suspicious_lines {
                md.push_str(&format!("- `{}`\n", line));
            }
            md.push('\n');
        }
    } else {
        md.push_str("## AI Deep Analysis\n\n*AI analysis was not performed.*\n\n");
    }

    // Deep static triage section
    if let Some(ref triage) = result.triage {
        md.push_str("## Deep Static Triage\n\n");
        md.push_str(&format!(
            "**Engine:** `{}`  \n**Files Analyzed:** {}  \n**Binaries:** {}  \n**Capabilities:** {}  \n**ATT&CK Techniques:** {}  \n\n",
            triage.engine,
            triage.files_scanned,
            triage.binaries.len(),
            triage.capabilities.len(),
            triage.attack_techniques.len(),
        ));

        if !triage.file_types.is_empty() {
            md.push_str("### File Types\n\n| Type | Count |\n|------|-------|\n");
            for kind in &triage.file_types {
                md.push_str(&format!("| {} | {} |\n", md_cell(&kind.kind), kind.count));
            }
            md.push('\n');
        }

        if !triage.attack_techniques.is_empty() {
            md.push_str("### MITRE ATT&CK Techniques\n\n| ID | Technique | Tactic |\n|----|-----------|--------|\n");
            for technique in &triage.attack_techniques {
                md.push_str(&format!(
                    "| {} | {} | {} |\n",
                    technique.id,
                    md_cell(&technique.name),
                    md_cell(&technique.tactic),
                ));
            }
            md.push('\n');
        }

        if !triage.binaries.is_empty() {
            md.push_str("### Binaries\n\n| File | Type | Arch | Entropy | SHA-256 | Packer |\n|------|------|------|---------|---------|--------|\n");
            for binary in &triage.binaries {
                let packer = binary
                    .packer
                    .as_ref()
                    .map(|packer| format!("{} ({})", packer.name, packer.confidence))
                    .unwrap_or_else(|| "-".to_string());
                md.push_str(&format!(
                    "| `{}` | {} | {} | {:.2} | `{}` | {} |\n",
                    md_cell(&binary.path),
                    binary.file_type,
                    binary.architecture.as_deref().unwrap_or("unknown"),
                    binary.entropy,
                    binary.sha256,
                    md_cell(&packer),
                ));
            }
            md.push('\n');
        }

        if !triage.capabilities.is_empty() {
            md.push_str("### Capabilities\n\n| Severity | Source | Capability | File | ATT&CK |\n|----------|--------|------------|------|--------|\n");
            for capability in &triage.capabilities {
                let attack = capability
                    .attack
                    .iter()
                    .map(|technique| technique.id.clone())
                    .collect::<Vec<_>>()
                    .join(", ");
                md.push_str(&format!(
                    "| {} | {} | {} | `{}` | {} |\n",
                    capability.severity,
                    capability.source,
                    md_cell(&capability.name),
                    md_cell(&capability.file_path),
                    if attack.is_empty() {
                        "-".to_string()
                    } else {
                        attack
                    },
                ));
            }
            md.push('\n');
        }

        if triage.deep {
            md.push_str("### Deep Analysis Tools\n\n| Tool | Available | Status | Version |\n|------|-----------|--------|---------|\n");
            for tool in &triage.tools {
                md.push_str(&format!(
                    "| {} | {} | {} | {} |\n",
                    tool.name,
                    if tool.available { "yes" } else { "no" },
                    md_cell(&tool.status),
                    md_cell(tool.version.as_deref().unwrap_or("-")),
                ));
            }
            md.push('\n');
        }

        if !triage.notes.is_empty() {
            md.push_str("### Triage Notes\n\n");
            for note in &triage.notes {
                md.push_str(&format!("- {}\n", md_cell(note)));
            }
            md.push('\n');
        }
    } else {
        md.push_str("## Deep Static Triage\n\n*Deep static triage was not performed.*\n\n");
    }

    markdown_deobfuscation(&mut md, result);
    markdown_emulation(&mut md, result);
    markdown_sandbox(&mut md, result);
    markdown_ttp(&mut md, result);

    // Rule matches table
    if result.rule_matches.is_empty() {
        md.push_str("## Rule Matches\n\n*No rule matches found.*\n\n");
    } else {
        md.push_str("## Rule Matches\n\n");
        md.push_str("| # | Severity | Pattern | File | Line | Context |\n");
        md.push_str("|---|----------|---------|------|------|---------|\n");

        let mut sorted = result.rule_matches.clone();
        sorted.sort_by_key(|m| severity_sort_key(&m.severity));

        for (i, m) in sorted.iter().enumerate() {
            let ctx_escaped = m.context.replace('|', "\\|");
            let ctx_trunc: String = ctx_escaped.chars().take(120).collect();
            let ctx_safe = ctx_trunc.replace('\n', " ");

            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                i + 1,
                m.severity,
                m.matched_pattern,
                m.file_path,
                m.line_number,
                ctx_safe,
            ));
        }
        md.push('\n');
    }

    md.push_str(&format!(
        "---\n*Report generated by KalaScan v{}*\n",
        env!("CARGO_PKG_VERSION")
    ));
    md
}

fn markdown_deobfuscation(md: &mut String, result: &ScanResult) {
    let Some(report) = &result.deobfuscation else {
        md.push_str("## Deobfuscation\n\n*Deobfuscation was not performed.*\n\n");
        return;
    };
    md.push_str("## Deobfuscation\n\n");
    md.push_str(&format!(
        "**Engine:** `{}`  \n**Files Analyzed:** {}  \n**Artifacts:** {}  \n**ATT&CK Techniques:** {}  \n\n",
        report.engine,
        report.files_scanned,
        report.artifacts.len(),
        report.attack_techniques.len(),
    ));

    if report.artifacts.is_empty() {
        md.push_str("*No encoded payloads were recovered.*\n\n");
    } else {
        md.push_str("| Confidence | Encoding | File | Line | Indicators | Decoded Preview |\n");
        md.push_str("|------------|----------|------|------|------------|-----------------|\n");
        for artifact in &report.artifacts {
            let decoded: String = artifact.decoded.chars().take(200).collect();
            let indicators = if artifact.indicators.is_empty() {
                "-".to_string()
            } else {
                artifact.indicators.join(", ")
            };
            md.push_str(&format!(
                "| {} | {} | `{}` | {} | {} | {} |\n",
                artifact.confidence,
                md_cell(&artifact.encoding),
                md_cell(&artifact.file_path),
                artifact.line_number,
                md_cell(&indicators),
                md_cell(&decoded),
            ));
        }
        md.push('\n');
    }

    if !report.attack_techniques.is_empty() {
        md.push_str("### Deobfuscation ATT&CK Techniques\n\n| ID | Technique | Tactic |\n|----|-----------|--------|\n");
        for technique in &report.attack_techniques {
            md.push_str(&format!(
                "| {} | {} | {} |\n",
                technique.id,
                md_cell(&technique.name),
                md_cell(&technique.tactic),
            ));
        }
        md.push('\n');
    }

    if !report.notes.is_empty() {
        md.push_str("### Deobfuscation Notes\n\n");
        for note in &report.notes {
            md.push_str(&format!("- {}\n", md_cell(note)));
        }
        md.push('\n');
    }
}

fn markdown_emulation(md: &mut String, result: &ScanResult) {
    let Some(report) = &result.emulation else {
        md.push_str("## Safe Static Emulation\n\n*Static emulation was not performed.*\n\n");
        return;
    };
    md.push_str("## Safe Static Emulation\n\n");
    md.push_str(&format!(
        "**Engine:** `{}`  \n**Files Analyzed:** {}  \n**Traces:** {}  \n**ATT&CK Techniques:** {}  \n\n",
        report.engine,
        report.files_scanned,
        report.traces.len(),
        report.attack_techniques.len(),
    ));

    if report.traces.is_empty() {
        md.push_str("*No emulation traces were produced.*\n\n");
    } else {
        for trace in &report.traces {
            md.push_str(&format!(
                "### `{}` ({})\n\n- **Entrypoint:** `{}`\n- **Instructions:** {}\n- **Stopped:** {}\n",
                md_cell(&trace.file_path),
                trace.architecture,
                trace.entrypoint,
                trace.instructions,
                md_cell(&trace.stopped_reason),
            ));
            if !trace.api_calls.is_empty() {
                md.push_str(&format!(
                    "- **API Calls:** {}\n",
                    md_cell(&trace.api_calls.join(", "))
                ));
            }
            if !trace.recovered_strings.is_empty() {
                md.push_str(&format!(
                    "- **Recovered Strings:** {}\n",
                    md_cell(&trace.recovered_strings.join(" | "))
                ));
            }
            if !trace.indicators.is_empty() {
                md.push_str(&format!(
                    "- **Indicators:** {}\n",
                    md_cell(&trace.indicators.join("; "))
                ));
            }
            if !trace.attack.is_empty() {
                let attack = trace
                    .attack
                    .iter()
                    .map(|technique| technique.id.clone())
                    .collect::<Vec<_>>()
                    .join(", ");
                md.push_str(&format!("- **ATT&CK:** {}\n", attack));
            }
            md.push('\n');
        }
    }

    if !report.notes.is_empty() {
        md.push_str("### Emulation Notes\n\n");
        for note in &report.notes {
            md.push_str(&format!("- {}\n", md_cell(note)));
        }
        md.push('\n');
    }
}

fn markdown_sandbox(md: &mut String, result: &ScanResult) {
    let Some(report) = &result.sandbox else {
        md.push_str("## Docker Sandbox\n\n*Docker sandbox was not enabled.*\n\n");
        return;
    };
    md.push_str("## Docker Sandbox\n\n");
    md.push_str(&format!(
        "**Engine:** `{}`  \n**Available:** {}  \n**Image:** `{}`  \n**Files Analyzed:** {}  \n**Executions:** {}  \n\n",
        report.engine,
        if report.available { "yes" } else { "no" },
        md_cell(&report.image),
        report.files_analyzed,
        report.executions.len(),
    ));

    if report.executions.is_empty() {
        md.push_str("*No sandbox executions were produced.*\n\n");
    } else {
        for execution in &report.executions {
            md.push_str(&format!(
                "### `{}` ({})\n\n- **Exit Code:** {:?}\n- **Duration:** {} ms\n- **Syscalls:** {}\n- **Timed Out:** {}\n",
                md_cell(&execution.file_path),
                execution.architecture,
                execution.exit_code,
                execution.duration_ms,
                execution.syscalls,
                execution.timed_out,
            ));
            if !execution.processes.is_empty() {
                md.push_str(&format!(
                    "- **Processes:** {}\n",
                    md_cell(&execution.processes.join(", "))
                ));
            }
            if !execution.network_attempts.is_empty() {
                md.push_str(&format!(
                    "- **Network Attempts:** {}\n",
                    md_cell(&execution.network_attempts.join(" | "))
                ));
            }
            if !execution.file_accesses.is_empty() {
                md.push_str(&format!(
                    "- **Sensitive Files:** {}\n",
                    md_cell(&execution.file_accesses.join(" | "))
                ));
            }
            if !execution.indicators.is_empty() {
                md.push_str(&format!(
                    "- **Indicators:** {}\n",
                    md_cell(&execution.indicators.join("; "))
                ));
            }
            md.push('\n');
        }
    }

    if !report.notes.is_empty() {
        md.push_str("### Sandbox Notes\n\n");
        for note in &report.notes {
            md.push_str(&format!("- {}\n", md_cell(note)));
        }
        md.push('\n');
    }
}

fn markdown_ttp(md: &mut String, result: &ScanResult) {
    let Some(report) = &result.ttp else {
        md.push_str("## TTP / ATT&CK Coverage\n\n*TTP mapping was not performed.*\n\n");
        return;
    };
    md.push_str("## TTP / ATT&CK Coverage\n\n");
    md.push_str(&format!(
        "**Engine:** `{}`  \n**Techniques:** {}  \n**Tactics:** {}  \n**Coverage:** {}%  \n\n",
        report.engine,
        report.techniques.len(),
        report.tactics.len(),
        report.coverage_score,
    ));

    if report.techniques.is_empty() {
        md.push_str("*No ATT&CK techniques were observed.*\n\n");
    } else {
        md.push_str("| Severity | ID | Technique | Tactic | Observations | Sources |\n");
        md.push_str("|----------|----|-----------|--------|--------------|---------|\n");
        for technique in &report.techniques {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                technique.severity,
                technique.id,
                md_cell(&technique.name),
                md_cell(&technique.tactic),
                technique.observations,
                md_cell(&technique.sources.join(", ")),
            ));
        }
        md.push('\n');
    }

    if !report.tactics.is_empty() {
        md.push_str("### Kill Chain\n\n| Tactic | Techniques | Observations |\n|--------|------------|--------------|\n");
        for tactic in &report.tactics {
            md.push_str(&format!(
                "| {} | {} | {} |\n",
                md_cell(&tactic.tactic),
                md_cell(&tactic.techniques.join(", ")),
                tactic.observations,
            ));
        }
        md.push('\n');
    }

    if !report.notes.is_empty() {
        for note in &report.notes {
            md.push_str(&format!("- {}\n", md_cell(note)));
        }
        md.push('\n');
    }
}

fn md_cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}

// ── SARIF export ──────────────────────────────────────────────────────────
// GitHub Code Scanning compatible output. Upload with `actions/upload-sarif`.

pub fn export_sarif(result: &ScanResult) -> String {
    use crate::baseline::fingerprint;

    let mut sorted = result.rule_matches.clone();
    sorted.sort_by_key(|m| severity_sort_key(&m.severity));

    let mut rules: Vec<serde_json::Value> = Vec::new();
    let mut rule_indices: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for m in &sorted {
        if !rule_indices.contains_key(&m.matched_pattern) {
            rule_indices.insert(m.matched_pattern.clone(), rules.len());
            rules.push(serde_json::json!({
                "id": rule_id(&m.matched_pattern),
                "name": m.matched_pattern,
                "shortDescription": { "text": m.matched_pattern },
                "defaultConfiguration": { "level": sarif_level(&m.severity) },
            }));
        }
    }

    let mut results: Vec<serde_json::Value> = Vec::new();
    for m in &sorted {
        results.push(serde_json::json!({
            "ruleId": rule_id(&m.matched_pattern),
            "ruleIndex": rule_indices.get(&m.matched_pattern).copied().unwrap_or(0),
            "level": sarif_level(&m.severity),
            "message": { "text": format!("{} detected in {}", m.matched_pattern, m.file_path) },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": m.file_path.replace('\\', "/") },
                    "region": { "startLine": m.line_number }
                }
            }],
            "partialFingerprints": { "kalascan/v1": fingerprint(m) },
        }));
    }

    serde_json::to_string_pretty(&serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "KalaScan",
                    "informationUri": "https://github.com/wahidhendrawan/KalaScan",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }))
    .unwrap_or_else(|_| "{}".to_string())
}

fn rule_id(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
}

fn sarif_level(severity: &str) -> &'static str {
    match severity {
        "critical" | "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}

// ── HTML export ──────────────────────────────────────────────────────────

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
  <script src="https://cdn.tailwindcss.com"></script>
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

/// CSV export: one row per finding, suitable for spreadsheets and CI artifacts.
pub fn export_csv(result: &ScanResult) -> String {
    let mut out = String::from("severity,rule,file,line,context\n");
    for m in &result.rule_matches {
        out.push_str(&format!(
            "{},{},{},{},{}\n",
            csv_field(&m.severity),
            csv_field(&m.matched_pattern),
            csv_field(&m.file_path),
            m.line_number,
            csv_field(&m.context),
        ));
    }
    out
}

fn csv_field(value: &str) -> String {
    if value.chars().any(|c| matches!(c, ',' | '"' | '\n' | '\r')) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// JUnit XML export for CI systems that only understand test reports. Every
/// finding is a failed test case, so a scan with findings fails the suite.
pub fn export_junit(result: &ScanResult) -> String {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!(
        "<testsuite name=\"kalascan\" tests=\"{}\" failures=\"{}\" errors=\"0\" time=\"{:.3}\">\n",
        result.rule_matches.len(),
        result.rule_matches.len(),
        result.duration_ms.unwrap_or(0) as f64 / 1000.0,
    ));
    out.push_str(&format!(
        "  <properties><property name=\"target\" value=\"{}\"/><property name=\"risk_score\" value=\"{}\"/></properties>\n",
        escape_xml(&result.repo_url),
        result.risk_score
    ));
    for m in &result.rule_matches {
        out.push_str(&format!(
            "  <testcase classname=\"{}\" name=\"{}:{} {}\">\n",
            escape_xml(&m.file_path),
            escape_xml(&m.file_path),
            m.line_number,
            escape_xml(&m.matched_pattern)
        ));
        out.push_str(&format!(
            "    <failure type=\"{}\" message=\"{}\">{}</failure>\n",
            escape_xml(&m.severity),
            escape_xml(&m.matched_pattern),
            escape_xml(&m.context)
        ));
        out.push_str("  </testcase>\n");
    }
    out.push_str("</testsuite>\n");
    out
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// GitHub Actions annotations (`::error file=...,line=...::message`). Works in
/// any workflow without GitHub API credentials; unresolved findings fail the
/// step because `::error` is emitted.
pub fn export_github(result: &ScanResult) -> String {
    let mut out = String::new();
    for m in &result.rule_matches {
        let level = match sarif_level(&m.severity) {
            "error" => "error",
            "warning" => "warning",
            _ => "notice",
        };
        out.push_str(&format!(
            "::{} file={},line={},title={}::{}\n",
            level,
            gh_escape_prop(&m.file_path),
            m.line_number,
            gh_escape_prop(&format!(
                "[{}] {}",
                m.severity.to_uppercase(),
                m.matched_pattern
            )),
            gh_escape_data(&m.context),
        ));
    }
    out
}

fn gh_escape_data(s: &str) -> String {
    s.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

fn gh_escape_prop(s: &str) -> String {
    gh_escape_data(s).replace(':', "%3A").replace(',', "%2C")
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Render a CycloneDX 1.5 JSON SBOM from manifest-derived dependency packages.
pub fn export_cyclonedx(
    packages: &[crate::cve::DependencyPackage],
    root: &std::path::Path,
) -> String {
    let mut components: Vec<serde_json::Value> = Vec::with_capacity(packages.len());
    for p in packages {
        let purl = match p.ecosystem.as_str() {
            "npm" => format!("pkg:npm/{}@{}", p.name, p.version),
            "crates.io" => format!("pkg:cargo/{}@{}", p.name, p.version),
            "PyPI" => format!("pkg:pypi/{}@{}", p.name, p.version),
            "Go" => format!("pkg:golang/{}@{}", p.name, p.version),
            "Maven" => format!("pkg:maven/{}@{}", p.name, p.version),
            "RubyGems" => format!("pkg:gem/{}@{}", p.name, p.version),
            other => format!("pkg:generic/{}@{}", p.name, other),
        };
        components.push(serde_json::json!({
            "type": "library",
            "name": p.name,
            "version": p.version,
            "purl": purl,
            "properties": [
                { "name": "kalascan:ecosystem", "value": p.ecosystem },
                { "name": "kalascan:manifest", "value": p.manifest_file },
            ],
        }));
    }

    serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "version": 1,
        "metadata": {
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "kalascan",
                        "version": env!("CARGO_PKG_VERSION"),
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": root
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "root".to_string()),
            },
        },
        "components": components,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attack::AttackTechnique;
    use crate::deobfuscate::{DeobfuscatedArtifact, DeobfuscationReport};
    use crate::emulate::{EmulationReport, EmulationTrace};
    use crate::sandbox::{SandboxExecution, SandboxReport};
    use crate::triage::{
        BinaryArtifact, CapabilityFinding, FileTypeCount, PackerFinding, SectionInfo, ToolStatus,
        TriageReport,
    };
    use crate::ttp::{TacticSummary, TtpReport, TtpTechnique};
    use crate::{AiAnalysis, RuleMatch};

    fn sample_triage() -> TriageReport {
        TriageReport {
            engine: format!("kalascan-static-triage/{}", env!("CARGO_PKG_VERSION")),
            deep: true,
            files_scanned: 45,
            file_types: vec![
                FileTypeCount {
                    kind: "PE".into(),
                    count: 1,
                },
                FileTypeCount {
                    kind: "Python source".into(),
                    count: 3,
                },
            ],
            binaries: vec![BinaryArtifact {
                path: "dist/evil.exe".into(),
                sha256: "a".repeat(64),
                size: 4096,
                file_type: "PE".into(),
                architecture: Some("x86_64".into()),
                bits: Some(64),
                entrypoint: Some("0x1000".into()),
                entropy: 7.42,
                sections: vec![SectionInfo {
                    name: "UPX0".into(),
                    size: 2048,
                    entropy: 7.6,
                    executable: true,
                    writable: true,
                }],
                imports: vec!["kernel32.dll!VirtualAllocEx".into()],
                packer: Some(PackerFinding {
                    name: "UPX".into(),
                    confidence: "high".into(),
                    evidence: "Section 'UPX0' matches UPX signature.".into(),
                }),
                indicators: vec!["Suspicious import: VirtualAllocEx".into()],
                decoded_strings: vec!["https://example.invalid/c2".into()],
            }],
            capabilities: vec![CapabilityFinding {
                name: "inject thread".into(),
                namespace: "capa".into(),
                description: "Detected by capa.".into(),
                severity: "critical".into(),
                source: "capa".into(),
                file_path: "dist/evil.exe".into(),
                attack: vec![AttackTechnique {
                    id: "T1055".into(),
                    name: "Process Injection".into(),
                    tactic: "Defense Evasion".into(),
                }],
            }],
            attack_techniques: vec![AttackTechnique {
                id: "T1055".into(),
                name: "Process Injection".into(),
                tactic: "Defense Evasion".into(),
            }],
            tools: vec![ToolStatus {
                name: "capa".into(),
                available: true,
                status: "available".into(),
                version: Some("capa 9.0.0".into()),
            }],
            notes: vec!["capa timed out for one binary".into()],
        }
    }

    fn sample_deobfuscation() -> DeobfuscationReport {
        DeobfuscationReport {
            engine: format!("kalascan-deobfuscation/{}", env!("CARGO_PKG_VERSION")),
            files_scanned: 12,
            artifacts: vec![DeobfuscatedArtifact {
                file_path: "src/installer.py".into(),
                line_number: 7,
                encoding: "base64 -> utf-16le".into(),
                original: "cABvAHcAZQBy...".into(),
                decoded: "powershell -EncodedCommand ...".into(),
                decoded_bytes: 42,
                depth: 2,
                confidence: "high".into(),
                indicators: vec!["PowerShell execution".into()],
                attack: vec![AttackTechnique {
                    id: "T1059.001".into(),
                    name: "PowerShell".into(),
                    tactic: "Execution".into(),
                }],
            }],
            attack_techniques: vec![AttackTechnique {
                id: "T1059.001".into(),
                name: "PowerShell".into(),
                tactic: "Execution".into(),
            }],
            notes: vec!["Recursive decode depth capped at 3".into()],
        }
    }

    fn sample_emulation() -> EmulationReport {
        EmulationReport {
            engine: format!("kalascan-emulation/{}", env!("CARGO_PKG_VERSION")),
            files_scanned: 1,
            traces: vec![EmulationTrace {
                file_path: "dist/evil.exe".into(),
                file_type: "PE".into(),
                architecture: "x86_64".into(),
                entrypoint: "0x140001000".into(),
                instructions: 128,
                stopped_reason: "external API call: kernel32.dll!VirtualAlloc".into(),
                recovered_strings: vec!["https://example.invalid/c2".into()],
                api_calls: vec!["kernel32.dll!VirtualAlloc".into()],
                indicators: vec!["Process injection or native API use".into()],
                attack: vec![AttackTechnique {
                    id: "T1055".into(),
                    name: "Process Injection".into(),
                    tactic: "Defense Evasion".into(),
                }],
            }],
            attack_techniques: vec![AttackTechnique {
                id: "T1055".into(),
                name: "Process Injection".into(),
                tactic: "Defense Evasion".into(),
            }],
            notes: vec!["Entrypoint was emulated with a bounded instruction budget".into()],
        }
    }

    fn sample_sandbox() -> SandboxReport {
        SandboxReport {
            engine: format!("kalascan-sandbox/{}", env!("CARGO_PKG_VERSION")),
            available: true,
            image: "kalascan-sandbox:latest".into(),
            files_analyzed: 1,
            executions: vec![SandboxExecution {
                file_path: "dist/evil.elf".into(),
                file_type: "ELF".into(),
                architecture: "x86_64".into(),
                exit_code: Some(0),
                timed_out: false,
                duration_ms: 420,
                syscalls: 37,
                processes: vec!["/tmp/sample".into(), "/bin/sh".into()],
                network_attempts: vec!["connect(3, 1.2.3.4:4444)".into()],
                file_accesses: vec!["openat: /etc/passwd".into()],
                indicators: vec![
                    "Sandbox: outbound network attempt".into(),
                    "Sandbox: credential file access".into(),
                ],
                attack: vec![AttackTechnique {
                    id: "T1071".into(),
                    name: "Application Layer Protocol".into(),
                    tactic: "Command and Control".into(),
                }],
                trace_excerpt: vec!["execve(\"/tmp/sample\") = 0".into()],
            }],
            attack_techniques: vec![AttackTechnique {
                id: "T1071".into(),
                name: "Application Layer Protocol".into(),
                tactic: "Command and Control".into(),
            }],
            notes: vec!["Container network disabled".into()],
        }
    }

    fn sample_ttp() -> TtpReport {
        TtpReport {
            engine: format!("kalascan-ttp/{}", env!("CARGO_PKG_VERSION")),
            techniques: vec![TtpTechnique {
                id: "T1071".into(),
                name: "Application Layer Protocol".into(),
                tactic: "Command and Control".into(),
                sources: vec!["rule:Discord Webhook".into(), "sandbox".into()],
                observations: 2,
                severity: "high".into(),
            }],
            tactics: vec![TacticSummary {
                tactic: "Command and Control".into(),
                techniques: vec!["T1071".into()],
                observations: 2,
            }],
            coverage_score: 7,
            notes: vec!["1 techniques across 1 tactics observed.".into()],
        }
    }

    fn sample_result() -> ScanResult {
        ScanResult {
            id: "test-123".into(),
            repo_url: "https://github.com/example/repo".into(),
            timestamp: "2026-07-27T12:00:00Z".into(),
            total_files: 100,
            scanned_files: 45,
            total_matches: 3,
            risk_score: 75,
            ai_analysis: Some(AiAnalysis {
                is_malicious: true,
                risk_score: 80,
                malware_type: "Information Stealer".into(),
                threat_summary: "Collects browser credentials and sends via webhook.".into(),
                suspicious_lines: vec![
                    "eval(base64.b64decode(encoded))".into(),
                    "discord.com/api/webhooks/...".into(),
                ],
                recommendation: "Do Not Execute".into(),
            }),
            triage: Some(sample_triage()),
            deobfuscation: Some(sample_deobfuscation()),
            emulation: Some(sample_emulation()),
            ttp: Some(sample_ttp()),
            sandbox: Some(sample_sandbox()),
            rule_matches: vec![
                RuleMatch {
                    file_path: "src/main.py".into(),
                    line_number: 42,
                    matched_pattern: "Discord Webhook".into(),
                    severity: "critical".into(),
                    context: "requests.post('https://discord.com/api/webhooks/...')".into(),
                },
                RuleMatch {
                    file_path: "src/utils.py".into(),
                    line_number: 15,
                    matched_pattern: "eval() Usage".into(),
                    severity: "high".into(),
                    context: "eval(base64_decode(data))".into(),
                },
                RuleMatch {
                    file_path: "src/config.py".into(),
                    line_number: 3,
                    matched_pattern: "Generic API Key".into(),
                    severity: "high".into(),
                    context: "api_key = 'sk-abc123def456'".into(),
                },
            ],
            status: "completed".into(),
            duration_ms: None,
            iocs: Vec::new(),
        }
    }

    #[test]
    fn test_risk_score_to_level() {
        assert_eq!(risk_score_to_level(0), "safe");
        assert_eq!(risk_score_to_level(15), "safe");
        assert_eq!(risk_score_to_level(29), "safe");
        assert_eq!(risk_score_to_level(30), "warning");
        assert_eq!(risk_score_to_level(50), "warning");
        assert_eq!(risk_score_to_level(69), "warning");
        assert_eq!(risk_score_to_level(70), "danger");
        assert_eq!(risk_score_to_level(100), "danger");
    }

    #[test]
    fn test_render_risk_badge() {
        let (cls, lbl) = render_risk_badge(15);
        assert!(cls.contains("green"));
        assert!(lbl.contains("SAFE"));
        let (cls, lbl) = render_risk_badge(50);
        assert!(cls.contains("yellow"));
        assert!(lbl.contains("WARNING"));
        let (cls, lbl) = render_risk_badge(85);
        assert!(cls.contains("red"));
        assert!(lbl.contains("HIGH RISK"));
    }

    #[test]
    fn test_export_markdown_contains_sections() {
        let r = sample_result();
        let md = export_markdown(&r);
        assert!(md.contains("KalaScan Report"));
        assert!(md.contains("Risk Score"));
        assert!(md.contains("Summary"));
        assert!(md.contains("AI Deep Analysis"));
        assert!(md.contains("Rule Matches"));
        assert!(md.contains("HIGH RISK"));
        assert!(md.contains("Rule Matches") && md.contains("3"));
        assert!(md.contains("Information Stealer"));
        assert!(md.contains("Discord Webhook"));
        assert!(md.contains("Deep Static Triage"));
        assert!(md.contains("T1055"));
        assert!(md.contains("UPX"));
        assert!(md.contains("Deobfuscation"));
        assert!(md.contains("Safe Static Emulation"));
        assert!(md.contains("T1059.001"));
        assert!(md.contains("Docker Sandbox"));
        assert!(md.contains("TTP / ATT&CK Coverage"));
        assert!(md.contains("T1071"));
    }

    #[test]
    fn test_export_markdown_no_triage() {
        let mut r = sample_result();
        r.triage = None;
        let md = export_markdown(&r);
        assert!(md.contains("Deep static triage was not performed"));
    }

    #[test]
    fn test_export_markdown_no_ai() {
        let mut r = sample_result();
        r.ai_analysis = None;
        let md = export_markdown(&r);
        assert!(md.contains("AI analysis was not performed"));
    }

    #[test]
    fn test_export_markdown_no_matches() {
        let mut r = sample_result();
        r.rule_matches.clear();
        r.total_matches = 0;
        let md = export_markdown(&r);
        assert!(md.contains("No rule matches found"));
    }

    #[test]
    fn test_export_html_contains_sections() {
        let r = sample_result();
        let html = export_html(&r);
        assert!(html.contains("KalaScan Report"));
        assert!(html.contains("AI Deep Analysis"));
        assert!(html.contains("Rule Matches"));
        assert!(html.contains("tailwindcss"));
        assert!(html.contains("Information Stealer"));
        assert!(html.contains("Discord Webhook"));
        assert!(html.contains("bg-red-500"));
        assert!(html.contains("Deep Static Triage"));
        assert!(html.contains("T1055"));
        assert!(html.contains("UPX"));
        assert!(html.contains("Deobfuscation"));
        assert!(html.contains("Safe Static Emulation"));
        assert!(html.contains("T1059.001"));
        assert!(html.contains("Docker Sandbox"));
        assert!(html.contains("TTP / ATT&CK Coverage"));
        assert!(html.contains("T1071"));
    }

    #[test]
    fn test_export_markdown_no_sandbox() {
        let mut r = sample_result();
        r.sandbox = None;
        let md = export_markdown(&r);
        assert!(md.contains("Docker sandbox was not enabled"));
    }

    #[test]
    fn test_export_html_no_ttp() {
        let mut r = sample_result();
        r.ttp = None;
        let html = export_html(&r);
        assert!(html.contains("TTP mapping was not performed"));
    }

    #[test]
    fn test_export_markdown_no_deobfuscation() {
        let mut r = sample_result();
        r.deobfuscation = None;
        let md = export_markdown(&r);
        assert!(md.contains("Deobfuscation was not performed"));
    }

    #[test]
    fn test_export_html_no_emulation() {
        let mut r = sample_result();
        r.emulation = None;
        let html = export_html(&r);
        assert!(html.contains("Static emulation was not performed"));
    }

    #[test]
    fn test_export_html_no_triage() {
        let mut r = sample_result();
        r.triage = None;
        let html = export_html(&r);
        assert!(html.contains("Deep static triage was not performed"));
    }

    #[test]
    fn test_export_html_no_ai() {
        let mut r = sample_result();
        r.ai_analysis = None;
        let html = export_html(&r);
        assert!(html.contains("AI analysis was not performed"));
    }

    #[test]
    fn test_export_html_no_matches() {
        let mut r = sample_result();
        r.rule_matches.clear();
        r.total_matches = 0;
        let html = export_html(&r);
        assert!(html.contains("No rule matches found"));
    }

    #[test]
    fn test_export_html_escapes_html() {
        let mut r = sample_result();
        r.repo_url = "https://evil.com/?x=<script>alert(1)</script>".into();
        r.rule_matches[0].context = "<bad>context</bad>".into();
        let html = export_html(&r);
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("&lt;bad&gt;"));
    }

    #[test]
    fn test_markdown_pipe_escaped() {
        let mut r = sample_result();
        r.rule_matches[0].context = "value | more | data".into();
        let md = export_markdown(&r);
        assert!(md.contains("value \\| more \\| data"));
    }

    #[test]
    fn sarif_output_has_valid_shape() {
        let r = sample_result();
        let parsed: serde_json::Value = serde_json::from_str(&export_sarif(&r)).unwrap();

        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(
            parsed["$schema"],
            "https://json.schemastore.org/sarif-2.1.0.json"
        );
        let run = &parsed["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "KalaScan");

        let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
        assert!(!rules.is_empty());
        for rule in rules {
            assert!(rule["id"].as_str().is_some_and(|s| !s.is_empty()));
        }

        let results = run["results"].as_array().unwrap();
        assert_eq!(results.len(), r.rule_matches.len());
        for result in results {
            // Every result must point at a declared rule.
            let index = result["ruleIndex"].as_u64().unwrap() as usize;
            assert_eq!(rules[index]["id"], result["ruleId"]);
            let location = &result["locations"][0]["physicalLocation"];
            assert!(location["artifactLocation"]["uri"].as_str().is_some());
            assert!(location["region"]["startLine"].as_u64().is_some());
            assert!(result["partialFingerprints"]["kalascan/v1"]
                .as_str()
                .is_some_and(|s| !s.is_empty()));
        }
    }

    #[test]
    fn sarif_severity_maps_to_level() {
        assert_eq!(sarif_level("critical"), "error");
        assert_eq!(sarif_level("medium"), "warning");
        assert_eq!(sarif_level("low"), "note");
    }

    #[test]
    fn csv_quotes_fields_with_commas() {
        let mut r = sample_result();
        r.rule_matches[0].context = "a, b \"c\"".into();
        let csv = export_csv(&r);
        assert!(csv.starts_with("severity,rule,file,line,context\n"));
        assert!(csv.contains("\"a, b \"\"c\"\"\""));
    }

    #[test]
    fn junit_counts_findings_as_failures() {
        let mut r = sample_result();
        r.rule_matches[0].context = "<script>alert(1)</script>".into();
        let xml = export_junit(&r);
        assert!(xml.contains("<testsuite name=\"kalascan\""));
        assert!(xml.contains(&format!("tests=\"{}\"", r.rule_matches.len())));
        assert!(xml.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    #[test]
    fn github_annotations_escape_workflow_commands() {
        let mut r = sample_result();
        r.rule_matches[0].file_path = "src/a,b.ts".into();
        r.rule_matches[0].context = "100%\ndone".into();
        let out = export_github(&r);
        assert!(out.starts_with("::error file="));
        assert!(out.contains("src/a%2Cb.ts"));
        assert!(out.contains("100%25%0Adone"));
    }

    #[test]
    fn cyclonedx_emits_components_with_purls() {
        let pkgs = vec![
            crate::cve::DependencyPackage {
                name: "lodash".into(),
                version: "4.17.21".into(),
                ecosystem: "npm".into(),
                manifest_file: "package.json".into(),
            },
            crate::cve::DependencyPackage {
                name: "serde".into(),
                version: "1.0.0".into(),
                ecosystem: "crates.io".into(),
                manifest_file: "Cargo.lock".into(),
            },
        ];
        let json = export_cyclonedx(&pkgs, std::path::Path::new("my-repo"));
        assert!(json.contains("\"bomFormat\":\"CycloneDX\""));
        assert!(json.contains("pkg:npm/lodash@4.17.21"));
        assert!(json.contains("pkg:cargo/serde@1.0.0"));
        assert!(json.contains("\"name\":\"my-repo\""));
    }
}
