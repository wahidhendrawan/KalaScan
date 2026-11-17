//! OSV record of one scan: a malicious-package report in the shape the
//! OpenSSF malicious-packages repository uses.

use crate::ScanResult;
use serde_json::json;

/// The schema version the record was checked against.
const SCHEMA_VERSION: &str = "1.9.2";

/// Findings named in `details`; the rest are in the scan itself.
const MAX_FINDINGS: usize = 20;

/// Fails unless the scan is of one exact npm / PyPI version and reached
/// "danger": any OSV record with `affected` reads as "this is malicious"
/// to its consumers, whatever the summary says.
pub fn export_osv(result: &ScanResult) -> anyhow::Result<String> {
    // The target, not the unpacked manifest: a local directory can claim
    // any name, and a record would then accuse the real package.
    let pkg = crate::vsix::parse_package_target(&result.repo_url)
        .filter(|pkg| ["npm", "pypi"].contains(&pkg.ecosystem));
    // `npm:name@latest` parses, and says nothing about what was fetched.
    let version = pkg
        .as_ref()
        .and_then(|pkg| pkg.version.as_deref())
        .filter(|v| v.starts_with(|c: char| c.is_ascii_digit()));
    let (Some(pkg), Some(version)) = (&pkg, version) else {
        anyhow::bail!(
            "an OSV record needs an npm or PyPI package with an exact version \
             (npm:name@1.2.3, pypi:name==1.2.3), not '{}'",
            result.repo_url
        );
    };
    let level = super::risk_score_to_level(result.risk_score);
    if level != "danger" {
        anyhow::bail!(
            "no OSV record for {}: risk score {} ({}) is below the danger level, \
             so the scan did not find the package malicious",
            result.repo_url,
            result.risk_score,
            level
        );
    }
    let (ecosystem, name) = match pkg.ecosystem {
        "npm" => ("npm", pkg.name.clone()),
        // PEP 503: lower case, runs of `-`, `_` and `.` are one `-`.
        _ => (
            "PyPI",
            pkg.name
                .to_ascii_lowercase()
                .split(['-', '_', '.'])
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join("-"),
        ),
    };

    let mut details = format!(
        "KalaScan {} scanned {} {}@{} statically. Risk score: {}/100 ({}).\n",
        env!("CARGO_PKG_VERSION"),
        ecosystem,
        name,
        version,
        result.risk_score,
        level
    );
    if let Some(breakdown) = result.score_breakdown.as_ref() {
        details.push_str(&format!("\nScore (model {}):\n", breakdown.model));
        for part in &breakdown.parts {
            details.push_str(&format!("- {}: {}\n", part.name, part.points));
        }
    }
    let critical: Vec<_> = result
        .rule_matches
        .iter()
        .filter(|m| m.severity == "critical")
        .collect();
    if !critical.is_empty() {
        details.push_str("\nCritical findings:\n");
        for m in critical.iter().take(MAX_FINDINGS) {
            details.push_str(&format!(
                "- {} ({}:{})\n",
                m.matched_pattern, m.file_path, m.line_number
            ));
        }
        if critical.len() > MAX_FINDINGS {
            details.push_str(&format!("- and {} more\n", critical.len() - MAX_FINDINGS));
        }
    }

    let time = super::stix::timestamp(result)?;
    Ok(serde_json::to_string_pretty(&json!({
        "schema_version": SCHEMA_VERSION,
        // `x_`: the schema's prefix for a database OSV.dev does not aggregate.
        "id": format!("x_KALASCAN-{}", result.id),
        "modified": time,
        "published": time,
        "summary": format!("Malicious code in {} ({})", name, ecosystem),
        "details": details,
        "affected": [{
            "package": { "ecosystem": ecosystem, "name": name },
            "versions": [version],
        }],
        "database_specific": {
            "id_status": "local KalaScan id, not an assigned MAL- id",
            "kalascan_version": env!("CARGO_PKG_VERSION"),
            "risk_score": result.risk_score,
            "score_model": result.score_breakdown.as_ref().map(|b| b.model.as_str()),
            "ruleset_version": crate::scanner::RULESET_VERSION,
        },
    }))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::tests::sample_result;
    use crate::score::{ScoreBreakdown, ScorePart};

    fn package_scan(target: &str) -> ScanResult {
        let mut r = sample_result();
        r.repo_url = target.into();
        r.timestamp = "2026-07-27T12:00:00.5+00:00".into();
        r.score_breakdown = Some(ScoreBreakdown {
            model: "v1".into(),
            parts: vec![
                ScorePart {
                    name: "critical findings".into(),
                    points: 70,
                },
                ScorePart {
                    name: "high findings".into(),
                    points: 5,
                },
            ],
            known_vulnerabilities: 0,
        });
        r
    }

    fn record(result: &ScanResult) -> serde_json::Value {
        serde_json::from_str(&export_osv(result).unwrap()).unwrap()
    }

    #[test]
    fn osv_record_for_an_npm_package() {
        let v = record(&package_scan("npm:@evil/left-pad@1.0.3"));
        assert_eq!(v["id"], "x_KALASCAN-test-123");
        assert_eq!(v["modified"], "2026-07-27T12:00:00.500Z");
        assert_eq!(v["published"], v["modified"]);
        assert_eq!(v["summary"], "Malicious code in @evil/left-pad (npm)");
        assert_eq!(
            v["affected"],
            json!([{
                "package": { "ecosystem": "npm", "name": "@evil/left-pad" },
                "versions": ["1.0.3"],
            }])
        );
        let details = v["details"].as_str().unwrap();
        assert!(details.contains("Risk score: 75/100 (danger)"), "{details}");
        assert!(details.contains("- critical findings: 70\n"), "{details}");
        assert!(
            details.contains("- Discord Webhook (src/main.py:42)\n"),
            "{details}"
        );
        assert!(!details.contains("eval() Usage"), "{details}");
        let db = &v["database_specific"];
        assert_eq!(db["risk_score"], 75);
        assert_eq!(db["score_model"], "v1");
        assert_eq!(db["ruleset_version"], crate::scanner::RULESET_VERSION);
        assert!(db["id_status"]
            .as_str()
            .unwrap()
            .contains("not an assigned"));
    }

    #[test]
    fn osv_record_for_a_pypi_package() {
        let v = record(&package_scan("pypi:Evil_Requests.Kit==2.0"));
        assert_eq!(v["summary"], "Malicious code in evil-requests-kit (PyPI)");
        assert_eq!(
            v["affected"][0],
            json!({
                "package": { "ecosystem": "PyPI", "name": "evil-requests-kit" },
                "versions": ["2.0"],
            })
        );
    }

    #[test]
    fn osv_refuses_a_scan_below_danger() {
        let mut r = package_scan("npm:left-pad@1.0.3");
        r.risk_score = 69;
        let err = export_osv(&r).unwrap_err().to_string();
        assert!(err.contains("below the danger level"), "{err}");
        r.risk_score = 70;
        assert!(export_osv(&r).is_ok());
    }

    #[test]
    fn osv_refuses_a_target_without_a_package_identity() {
        for target in [
            "https://github.com/example/repo",
            "/tmp/unpacked",
            "ms-python.python@2026.4.1",
            "crates:serde@1.0.0",
            "npm:left-pad",
            "npm:left-pad@latest",
            "pypi:requests",
        ] {
            let err = export_osv(&package_scan(target)).unwrap_err().to_string();
            assert!(err.contains("exact version"), "{target}: {err}");
        }
    }
}
