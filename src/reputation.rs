//! Who published an extension, and is it pretending to be someone else?
//!
//! Offline checks read the extension's own package.json, so they work on a
//! local .vsix long after the marketplace has removed it. The online check
//! asks the VS Marketplace for install count, age and publisher verification.

use crate::RuleMatch;
use regex::Regex;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::LazyLock;
use std::time::Duration;

pub const INVISIBLE_NAME: &str = "Extension Name Spoofing (invisible characters)";
pub const PUBLISHER_LOOKALIKE: &str = "Publisher Impersonation (look-alike name)";
pub const BRAND_IMPERSONATION: &str = "Possible Brand Impersonation";
pub const UNVERIFIED_PUBLISHER: &str = "Unverified Publisher";
pub const LOW_INSTALLS: &str = "Low Install Count";
pub const RECENTLY_PUBLISHED: &str = "Recently Published Extension";
pub const REPACKAGED_COPY: &str = "Repackaged Copy of Popular Extension";

/// `repository -> [publisher.name]` for the most-installed extensions
/// (rules/gen_popular_extensions.py). shortcut: a snapshot; regenerate when
/// a clone of a newly popular extension slips through.
static POPULAR_REPOS: LazyLock<HashMap<&'static str, Vec<&'static str>>> = LazyLock::new(|| {
    let mut map: HashMap<_, Vec<_>> = HashMap::new();
    for line in include_str!("../rules/popular_extensions.tsv").lines() {
        if let Some((repo, ext)) = line.split_once('\t').filter(|_| !line.starts_with('#')) {
            map.entry(repo).or_default().push(ext);
        }
    }
    map
});

/// Every publisher in that list. Official publishers share monorepos
/// (`ms-vscode` and `ms-vscode-remote` both ship vscode-remote-release).
static POPULAR_REPO_PUBLISHERS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    POPULAR_REPOS
        .values()
        .flatten()
        .filter_map(|ext| ext.split('.').next())
        .collect()
});

static REPO_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(github\.com|gitlab\.com|bitbucket\.org)[/:]([\w.-]+)/([\w.-]+)").unwrap()
});

/// `git+https://github.com/Foo/bar.git#main` -> `github.com/foo/bar`; same
/// normalisation as the generator. npm shorthand `foo/bar` means GitHub.
fn repo_key(url: &str) -> Option<String> {
    let url = url.trim().trim_start_matches("github:");
    let caps = REPO_URL
        .captures(url)
        .map(|c| (c[1].to_string(), c[2].to_string(), c[3].to_string()));
    let (host, owner, repo) = caps.or_else(|| {
        let (owner, repo) = url.split_once('/')?;
        (!url.contains(':') && !repo.contains('/'))
            .then(|| ("github.com".into(), owner.into(), repo.into()))
    })?;
    let repo = repo.strip_suffix(".git").unwrap_or(&repo);
    Some(format!("{}/{}/{}", host, owner, repo).to_lowercase())
}

/// Publishers of widely installed extensions (marketplace ids, lowercase).
const POPULAR_PUBLISHERS: &[&str] = &[
    "microsoft",
    "ms-python",
    "ms-toolsai",
    "ms-vscode",
    "ms-vscode-remote",
    "ms-azuretools",
    "ms-dotnettools",
    "ms-ceintl",
    "github",
    "esbenp",
    "dbaeumer",
    "eamodio",
    "redhat",
    "golang",
    "rust-lang",
    "juanblanco",
    "nomicfoundation",
    "dracula-theme",
    "pkief",
    "vscodevim",
    "ritwickdey",
    "formulahendry",
    "christian-kohler",
    "streetsidesoftware",
    "usernamehw",
    "johnpapa",
    "visualstudioexptteam",
    "gitkraken",
    "bradlc",
    "prisma",
    "svelte",
    "vue",
    "anthropic",
    "openai",
    "continue",
    "hashicorp",
    "denoland",
];

/// Distinctive product names and their official publishers.
const BRANDS: &[(&str, &[&str])] = &[
    ("gitlens", &["eamodio", "gitkraken"]),
    ("prettier", &["esbenp", "prettier"]),
    ("error lens", &["usernamehw"]),
    ("peacock", &["johnpapa"]),
    ("dracula", &["dracula-theme"]),
    ("pylance", &["ms-python"]),
    ("copilot", &["github"]),
    ("live server", &["ritwickdey", "ms-vscode"]),
];

/// Characters that render as nothing (or reorder text) in a marketplace listing.
fn is_invisible(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{FEFF}')
}

/// Fold characters that look alike in the marketplace font: `I`/`1` → `l`,
/// `0` → `o`, `rn` → `m`, separators dropped.
fn skeleton(s: &str) -> String {
    let mapped: String = s
        .chars()
        .filter(|c| !matches!(c, '-' | '_' | '.'))
        .map(|c| match c {
            'I' | '1' | '|' => 'l',
            '0' => 'o',
            c => c.to_ascii_lowercase(),
        })
        .collect();
    mapped.replace("rn", "m").replace("vv", "w")
}

/// Offline identity checks on a VS Code extension root.
pub fn identity_matches(root: &Path) -> Vec<RuleMatch> {
    let Some(pkg) = std::fs::read_to_string(root.join("package.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .filter(|v| v["engines"]["vscode"].is_string())
    else {
        return Vec::new();
    };
    let publisher = pkg["publisher"].as_str().unwrap_or_default();
    let name = pkg["name"].as_str().unwrap_or_default();
    let display = pkg["displayName"].as_str().unwrap_or(name);
    let finding = |rule: &str, severity: &str, context: String| RuleMatch {
        file_path: "package.json".to_string(),
        line_number: 1,
        matched_pattern: rule.to_string(),
        severity: severity.to_string(),
        context,
    };
    let mut out = Vec::new();

    if [publisher, name, display]
        .iter()
        .any(|s| s.chars().any(is_invisible))
    {
        out.push(finding(
            INVISIBLE_NAME,
            "critical",
            format!(
                "Name {:?} / publisher {:?} contain invisible characters — used to clone a popular listing",
                display, publisher
            ),
        ));
    }

    let publisher_lower = publisher.to_ascii_lowercase();
    if let Some(real) = POPULAR_PUBLISHERS
        .iter()
        .find(|p| skeleton(publisher) == skeleton(p) && publisher_lower != **p)
    {
        out.push(finding(
            PUBLISHER_LOOKALIKE,
            "critical",
            format!("Publisher '{}' is a look-alike of '{}'", publisher, real),
        ));
    }

    let visible: String = format!("{} {}", publisher, display)
        .chars()
        .filter(|c| !is_invisible(*c))
        .collect::<String>()
        .to_lowercase();
    for (brand, owners) in BRANDS {
        if visible.contains(brand) && !owners.contains(&publisher_lower.as_str()) {
            out.push(finding(
                BRAND_IMPERSONATION,
                "medium",
                format!(
                    "'{}' by '{}' uses the '{}' brand, published by {}",
                    display,
                    publisher,
                    brand,
                    owners.join(" / ")
                ),
            ));
            break;
        }
    }

    // The code is the original's; only the listing is new (csvmech.csvrainbow
    // republishing mechatroner/vscode_rainbow_csv).
    let repository = pkg["repository"]["url"]
        .as_str()
        .or(pkg["repository"].as_str());
    if let Some(key) = repository.and_then(repo_key) {
        if let Some(owners) = POPULAR_REPOS.get(key.as_str()) {
            if !POPULAR_REPO_PUBLISHERS.contains(publisher_lower.as_str()) {
                out.push(finding(
                    REPACKAGED_COPY,
                    "critical",
                    format!(
                        "Declares {} as its source, which is {}, but is published by '{}'",
                        key,
                        owners.join(" / "),
                        publisher
                    ),
                ));
            }
        }
    }
    out
}

#[derive(Deserialize)]
struct QueryResponse {
    results: Vec<QueryResult>,
}
#[derive(Deserialize)]
struct QueryResult {
    extensions: Vec<Extension>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Extension {
    publisher: Publisher,
    published_date: Option<String>,
    #[serde(default)]
    statistics: Vec<Statistic>,
}
#[derive(Deserialize)]
struct Publisher {
    #[serde(default)]
    flags: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Statistic {
    statistic_name: String,
    value: f64,
}

/// Marketplace reputation for `publisher.name`. Informational (low/medium):
/// plenty of good extensions are new or small. Network errors yield nothing.
pub async fn marketplace_matches(publisher: &str, name: &str) -> Vec<RuleMatch> {
    let body = serde_json::json!({
        "filters": [{"criteria": [{"filterType": 7, "value": format!("{}.{}", publisher, name)}]}],
        "flags": 914
    });
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
    else {
        return Vec::new();
    };
    let Ok(resp) = client
        .post("https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery")
        .header("Accept", "application/json;api-version=7.2-preview.1")
        .json(&body)
        .send()
        .await
    else {
        return Vec::new();
    };
    let Ok(parsed) = resp.json::<QueryResponse>().await else {
        return Vec::new();
    };
    let Some(ext) = parsed.results.into_iter().flat_map(|r| r.extensions).next() else {
        return Vec::new();
    };
    let installs = ext
        .statistics
        .iter()
        .find(|s| s.statistic_name == "install")
        .map_or(0.0, |s| s.value);
    let age_days = ext
        .published_date
        .as_deref()
        .and_then(|d| chrono::DateTime::parse_from_rfc3339(d).ok())
        .map(|d| (chrono::Utc::now() - d.with_timezone(&chrono::Utc)).num_days());
    reputation_findings(ext.publisher.flags.contains("verified"), installs, age_days)
}

fn reputation_findings(verified: bool, installs: f64, age_days: Option<i64>) -> Vec<RuleMatch> {
    let finding = |rule: &str, severity: &str, context: String| RuleMatch {
        file_path: "marketplace".to_string(),
        line_number: 1,
        matched_pattern: rule.to_string(),
        severity: severity.to_string(),
        context,
    };
    let mut out = Vec::new();
    if !verified {
        out.push(finding(
            UNVERIFIED_PUBLISHER,
            "low",
            "Publisher has no verified domain".into(),
        ));
    }
    if installs < 1000.0 {
        out.push(finding(
            LOW_INSTALLS,
            "low",
            format!("{} installs", installs as u64),
        ));
    }
    if let Some(days) = age_days.filter(|d| *d < 30) {
        out.push(finding(
            RECENTLY_PUBLISHED,
            "medium",
            format!("First published {} days ago", days),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ext(publisher: &str, display: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let pkg = serde_json::json!({
            "publisher": publisher, "name": "x", "displayName": display,
            "engines": {"vscode": "^1.80.0"}
        });
        std::fs::write(dir.path().join("package.json"), pkg.to_string()).unwrap();
        dir
    }

    fn names(dir: &tempfile::TempDir) -> Vec<String> {
        identity_matches(dir.path())
            .into_iter()
            .map(|m| m.matched_pattern)
            .collect()
    }

    #[test]
    fn real_impersonation_samples() {
        // From the DataDog dataset.
        assert_eq!(
            names(&ext(
                "JohnGaffney",
                "Solidity Language\u{200b}\u{200b}\u{200b}"
            )),
            vec![INVISIBLE_NAME]
        );
        assert_eq!(
            names(&ext("juanbIanco", "solidity\u{200b}")),
            vec![INVISIBLE_NAME, PUBLISHER_LOOKALIKE]
        );
        assert_eq!(
            names(&ext("GitlensPro", "Error Lens Ultra")),
            vec![BRAND_IMPERSONATION]
        );
        assert_eq!(
            names(&ext("QuantumCodeLabs", "Dracula Pro Theme")),
            vec![BRAND_IMPERSONATION]
        );
    }

    #[test]
    fn genuine_listings_are_quiet() {
        assert!(names(&ext("JuanBlanco", "solidity")).is_empty());
        assert!(names(&ext("eamodio", "GitLens — Git supercharged")).is_empty());
        assert!(names(&ext("usernamehw", "Error Lens")).is_empty());
        assert!(names(&ext("ms-python", "Pylance")).is_empty());
        assert!(names(&ext("someone", "Python Indent")).is_empty());
        // Not an extension: no engines.vscode.
        let npm = tempfile::tempdir().unwrap();
        std::fs::write(npm.path().join("package.json"), r#"{"name":"gitlens-pro"}"#).unwrap();
        assert!(identity_matches(npm.path()).is_empty());
    }

    fn ext_with_repo(publisher: &str, repository: serde_json::Value) -> tempfile::TempDir {
        let dir = ext(publisher, "CSV Rainbow");
        let mut pkg: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("package.json")).unwrap(),
        )
        .unwrap();
        pkg["repository"] = repository;
        std::fs::write(dir.path().join("package.json"), pkg.to_string()).unwrap();
        dir
    }

    #[test]
    fn repackaged_popular_extension() {
        // Real sample: mechatroner's Rainbow CSV republished by csvmech.
        let rainbow = "https://github.com/mechatroner/vscode_rainbow_csv";
        assert_eq!(
            names(&ext_with_repo("csvmech", serde_json::json!(rainbow))),
            vec![REPACKAGED_COPY]
        );
        assert_eq!(
            names(&ext_with_repo(
                "csvmech",
                serde_json::json!({"type": "git", "url": "git+https://github.com/Mechatroner/vscode_rainbow_csv.git"})
            )),
            vec![REPACKAGED_COPY]
        );
        // The real publisher, and an official sibling sharing a monorepo.
        assert!(names(&ext_with_repo("mechatroner", serde_json::json!(rainbow))).is_empty());
        assert!(names(&ext_with_repo(
            "ms-vscode",
            serde_json::json!("https://github.com/microsoft/vscode-remote-release")
        ))
        .is_empty());
        // Someone's own repo.
        assert!(names(&ext_with_repo(
            "someone",
            serde_json::json!("someone/csv-tools")
        ))
        .is_empty());
    }

    #[test]
    fn repo_keys_normalise() {
        let k = |s| repo_key(s).unwrap();
        assert_eq!(
            k("git+https://github.com/Foo/bar.git#main"),
            "github.com/foo/bar"
        );
        assert_eq!(k("git@github.com:foo/bar.git"), "github.com/foo/bar");
        assert_eq!(k("github:foo/bar"), "github.com/foo/bar");
        assert_eq!(k("foo/bar"), "github.com/foo/bar");
        assert_eq!(repo_key("https://example.com/foo"), None);
    }

    #[test]
    fn marketplace_signals() {
        let rules = |v, i, a| -> Vec<String> {
            reputation_findings(v, i, a)
                .into_iter()
                .map(|m| m.matched_pattern)
                .collect()
        };
        assert!(rules(true, 10_000_000.0, Some(2000)).is_empty());
        assert_eq!(
            rules(false, 12.0, Some(3)),
            vec![UNVERIFIED_PUBLISHER, LOW_INSTALLS, RECENTLY_PUBLISHED]
        );
    }
}
