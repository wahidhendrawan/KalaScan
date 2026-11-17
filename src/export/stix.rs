//! STIX 2.1 bundle of one scan, for threat-intel platforms (MISP, OpenCTI).

use crate::ScanResult;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// The identity never changes, so neither may its timestamps: a platform
/// then keeps one KalaScan producer across every imported bundle.
const IDENTITY_CREATED: &str = "2026-01-01T00:00:00.000Z";

/// STIX and OSV want UTC ending in `Z` with milliseconds; older scans in
/// the history carry an offset (`+00:00`) and microseconds.
pub(super) fn timestamp(result: &ScanResult) -> anyhow::Result<String> {
    let rfc3339 = &time::format_description::well_known::Rfc3339;
    let parsed = time::OffsetDateTime::parse(&result.timestamp, rfc3339).map_err(|e| {
        anyhow::anyhow!(
            "scan timestamp '{}' is not RFC 3339: {}",
            result.timestamp,
            e
        )
    })?;
    let t = parsed.to_offset(time::UtcOffset::UTC);
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
        t.millisecond()
    ))
}

/// `<type>--<uuid>`, the same on every export of the same scan. The bytes
/// are a SHA-256 in UUIDv4 layout: STIX asks for v4 on these objects, and a
/// real name-based v5 needs the uuid crate's `v5` feature.
fn id(kind: &str, key: &str) -> String {
    let digest = Sha256::digest(format!("{kind}\0{key}"));
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    format!(
        "{kind}--{}",
        uuid::Builder::from_random_bytes(bytes).into_uuid()
    )
}

/// A pattern string literal: the grammar escapes `\` and `'`, nothing else.
fn literal(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

/// The properties every STIX object must carry, then its own.
fn object(kind: &str, id: &str, time: &str, own: Value) -> Value {
    let mut object = json!({
        "type": kind,
        "spec_version": "2.1",
        "id": id,
        "created": time,
        "modified": time,
    });
    if let (Some(object), Value::Object(own)) = (object.as_object_mut(), own) {
        object.extend(own);
    }
    object
}

pub fn export_stix(result: &ScanResult) -> anyhow::Result<String> {
    let time = timestamp(result)?;
    let scoped = |kind: &str, key: &str| id(kind, &format!("{}\0{}", result.id, key));
    let identity = id("identity", "KalaScan");
    let mut objects = vec![object(
        "identity",
        &identity,
        IDENTITY_CREATED,
        json!({ "name": "KalaScan", "identity_class": "system" }),
    )];

    let mut techniques: BTreeMap<&str, String> = BTreeMap::new();
    for technique in result.ttp.iter().flat_map(|report| &report.techniques) {
        let attack_pattern = scoped("attack-pattern", &technique.id);
        if techniques
            .insert(&technique.id, attack_pattern.clone())
            .is_some()
        {
            continue;
        }
        objects.push(object(
            "attack-pattern",
            &attack_pattern,
            &time,
            json!({
                "created_by_ref": identity,
                "name": technique.name,
                "external_references": [
                    { "source_name": "mitre-attack", "external_id": technique.id },
                ],
            }),
        ));
    }

    // Low findings are hygiene hints, not observed behaviour (ttp.rs).
    let findings: Vec<_> = result
        .rule_matches
        .iter()
        .filter(|m| m.severity != "low")
        .map(|m| (m, crate::baseline::matched_text(&m.context)))
        .collect();
    let mut linked = BTreeSet::new();
    for ioc in &result.iocs {
        let host = || match ioc.host.parse::<std::net::Ipv4Addr>() {
            Ok(_) => format!("[ipv4-addr:value = {}]", literal(&ioc.host)),
            Err(_) => format!("[domain-name:value = {}]", literal(&ioc.host)),
        };
        // A URL's host is not an indicator of its own: one bad file on a
        // shared host (raw.githubusercontent.com) would flag all of it.
        let (pattern, seen) = match ioc.kind.as_str() {
            "ip" => (host(), "Referenced in"),
            "sandbox-host" => (host(), "Contacted in the sandbox by"),
            _ => (
                format!("[url:value = {}]", literal(&ioc.value)),
                "Referenced in",
            ),
        };
        let indicator = scoped("indicator", &format!("{}\0{}", ioc.kind, ioc.value));
        objects.push(object(
            "indicator",
            &indicator,
            &time,
            json!({
                "created_by_ref": identity,
                "name": ioc.value,
                "description": format!("{} {}", seen, ioc.files.join(", ")),
                // Every external URL is listed, whatever the verdict on the code.
                "indicator_types": ["unknown"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": time,
            }),
        ));

        // `indicates` only where the line a finding matched on holds the
        // URL: sharing a file, or the lines around it, is not evidence. On
        // a minified line that is the 80 bytes each side of the match. A
        // sandbox host is a bare name, and need not be in the source at all.
        if ioc.kind == "sandbox-host" {
            continue;
        }
        for (m, _) in findings
            .iter()
            .filter(|(_, line)| line.contains(&ioc.value))
        {
            for technique in crate::attack::for_finding(&m.matched_pattern) {
                let Some(attack_pattern) = techniques.get(technique.id.as_str()) else {
                    continue;
                };
                let relationship = scoped(
                    "relationship",
                    &format!("{}\0{}", indicator, attack_pattern),
                );
                if !linked.insert(relationship.clone()) {
                    continue;
                }
                objects.push(object(
                    "relationship",
                    &relationship,
                    &time,
                    json!({
                        "created_by_ref": identity,
                        "relationship_type": "indicates",
                        "source_ref": indicator,
                        "target_ref": attack_pattern,
                        "description": format!("{} in {}", m.matched_pattern, m.file_path),
                    }),
                ));
            }
        }
    }

    let refs: Vec<&Value> = objects.iter().map(|object| &object["id"]).collect();
    let report = object(
        "report",
        &scoped("report", ""),
        &time,
        json!({
            "created_by_ref": identity,
            "name": format!("KalaScan scan of {}", result.repo_url),
            "description": format!(
                "Risk score {}/100 ({}), {} findings.",
                result.risk_score,
                super::risk_score_to_level(result.risk_score),
                result.total_matches
            ),
            "published": time,
            "object_refs": refs,
        }),
    );
    objects.push(report);

    Ok(serde_json::to_string_pretty(&json!({
        "type": "bundle",
        "id": scoped("bundle", ""),
        "objects": objects,
    }))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::tests::sample_result;
    use crate::iocs::Ioc;

    fn ioc(kind: &str, value: &str, host: &str) -> Ioc {
        Ioc {
            kind: kind.into(),
            value: value.into(),
            host: host.into(),
            files: vec!["src/main.py".into()],
        }
    }

    fn bundle(result: &ScanResult) -> Value {
        serde_json::from_str(&export_stix(result).unwrap()).unwrap()
    }

    fn of_type<'a>(bundle: &'a Value, kind: &str) -> Vec<&'a Value> {
        bundle["objects"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["type"] == kind)
            .collect()
    }

    #[test]
    fn stix_bundle_has_valid_shape() {
        let mut r = sample_result();
        r.timestamp = "2026-07-27T14:00:00.123456789+02:00".into();
        r.iocs = vec![
            ioc("url", "https://discord.com/api/webhooks/...", "discord.com"),
            ioc("ip", "http://91.92.242.133/support", "91.92.242.133"),
            ioc("sandbox-host", "c2.example.ru", "c2.example.ru"),
        ];
        let parsed = bundle(&r);
        assert_eq!(parsed["type"], "bundle");
        assert!(parsed["id"].as_str().unwrap().starts_with("bundle--"));
        assert!(parsed.get("spec_version").is_none());

        let objects = parsed["objects"].as_array().unwrap();
        let mut ids = BTreeSet::new();
        for o in objects {
            // What STIX 2.1 requires of every SDO and SRO.
            assert_eq!(o["spec_version"], "2.1", "{}", o);
            let (kind, uuid) = o["id"].as_str().unwrap().split_once("--").unwrap();
            assert_eq!(o["type"], kind);
            assert_eq!(uuid::Uuid::parse_str(uuid).unwrap().get_version_num(), 4);
            for key in ["created", "modified"] {
                let time = o[key].as_str().unwrap();
                assert!(time.ends_with('Z'), "{}", time);
                ::time::OffsetDateTime::parse(
                    time,
                    &::time::format_description::well_known::Rfc3339,
                )
                .unwrap();
            }
            assert!(ids.insert(o["id"].as_str().unwrap()), "duplicate {}", o);
        }

        assert_eq!(of_type(&parsed, "identity")[0]["name"], "KalaScan");
        let patterns: Vec<&str> = of_type(&parsed, "indicator")
            .iter()
            .map(|i| {
                assert_eq!(i["pattern_type"], "stix");
                assert_eq!(i["valid_from"], "2026-07-27T12:00:00.123Z");
                i["pattern"].as_str().unwrap()
            })
            .collect();
        assert_eq!(
            patterns,
            vec![
                "[url:value = 'https://discord.com/api/webhooks/...']",
                "[ipv4-addr:value = '91.92.242.133']",
                "[domain-name:value = 'c2.example.ru']",
            ]
        );

        let attack = of_type(&parsed, "attack-pattern");
        assert_eq!(attack.len(), 1);
        assert_eq!(
            attack[0]["external_references"][0],
            json!({ "source_name": "mitre-attack", "external_id": "T1071" })
        );

        // The report references every other object, and nothing else.
        let report = of_type(&parsed, "report")[0];
        assert_eq!(report["published"], "2026-07-27T12:00:00.123Z");
        let refs: BTreeSet<&str> = report["object_refs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap())
            .collect();
        ids.remove(report["id"].as_str().unwrap());
        assert_eq!(refs, ids);

        // Same scan, same bundle.
        assert_eq!(export_stix(&r).unwrap(), export_stix(&r).unwrap());
    }

    #[test]
    fn stix_relationships_need_a_finding_on_the_url() {
        let mut r = sample_result();
        // The line above the eval() finding, inside its context window.
        r.rule_matches[1].context =
            "u = 'https://other.example.ru/x'\nx = \n>>> eval( <<<\nbase64_decode(data))".into();
        r.ttp = Some(crate::ttp::build(&r.rule_matches, None, None, None, None));
        r.iocs = vec![
            // On the line of the Discord Webhook finding.
            ioc("url", "https://discord.com/api/webhooks/...", "discord.com"),
            ioc("url", "https://other.example.ru/x", "other.example.ru"),
        ];
        let parsed = bundle(&r);
        let indicators = of_type(&parsed, "indicator");
        let attack = of_type(&parsed, "attack-pattern");
        let external_id = |id: &Value| {
            attack.iter().find(|a| a["id"] == *id).unwrap()["external_references"][0]["external_id"]
                .clone()
        };
        let relationships = of_type(&parsed, "relationship");
        let mut linked = Vec::new();
        for relationship in &relationships {
            assert_eq!(relationship["relationship_type"], "indicates");
            assert_eq!(relationship["source_ref"], indicators[0]["id"]);
            assert_eq!(
                relationship["description"],
                "Discord Webhook in src/main.py"
            );
            linked.push(external_id(&relationship["target_ref"]));
        }
        let expected: Vec<Value> = crate::attack::for_finding("Discord Webhook")
            .into_iter()
            .map(|t| t.id.into())
            .collect();
        assert!(!expected.is_empty());
        assert_eq!(linked, expected);
        // The eval() techniques are reported, and linked to neither URL.
        assert!(attack.len() > expected.len(), "{:?}", attack);

        // A technique the scan does not report is not linked to either.
        r.ttp = None;
        let parsed = bundle(&r);
        assert!(of_type(&parsed, "relationship").is_empty());
        assert!(of_type(&parsed, "attack-pattern").is_empty());
    }

    #[test]
    fn stix_patterns_escape_hostile_values() {
        let mut r = sample_result();
        let hostile = "http://evil.example.ru/a'] OR [x:y = '\\\nb\"";
        r.iocs = vec![ioc("url", hostile, "evil.example.ru")];
        let out = export_stix(&r).unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        let indicator = of_type(&parsed, "indicator")[0];
        assert_eq!(
            indicator["pattern"],
            "[url:value = 'http://evil.example.ru/a\\'] OR [x:y = \\'\\\\\nb\"']"
        );
        assert_eq!(indicator["name"], hostile);
        // One string literal: every `'` and `\` inside it is escaped.
        let pattern = indicator["pattern"].as_str().unwrap();
        let inner = &pattern["[url:value = '".len()..pattern.len() - "']".len()];
        assert!(!inner
            .replace("\\\\", "")
            .replace("\\'", "")
            .contains(['\'', '\\']));
    }

    #[test]
    fn stix_scan_without_iocs_is_identity_and_report() {
        let mut r = sample_result();
        r.ttp = None;
        let parsed = bundle(&r);
        let types: Vec<&str> = parsed["objects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["type"].as_str().unwrap())
            .collect();
        assert_eq!(types, vec!["identity", "report"]);
        let report = of_type(&parsed, "report")[0];
        assert_eq!(
            report["object_refs"],
            json!([of_type(&parsed, "identity")[0]["id"]])
        );
    }

    #[test]
    fn stix_rejects_a_timestamp_it_cannot_convert() {
        let mut r = sample_result();
        r.timestamp = "yesterday".into();
        assert!(export_stix(&r).is_err());
    }
}
