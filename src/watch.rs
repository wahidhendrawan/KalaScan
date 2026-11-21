//! `kalascan watch`: scan what npm or PyPI publishes, as it is published.
//!
//! npm: the registry's CouchDB changes feed (`replicate.npmjs.com`), from the
//! moment the watch starts; each changed package is scanned at its `latest`
//! version. PyPI: the recent-updates RSS feed, polled. Every new version is
//! scanned as someone else's code; one at or above `min_risk` is printed with
//! its findings and, with `osv_dir`, written as an OSV malicious-package
//! record. With `log`, every scanned release is appended to a JSON-lines
//! file, flagged or not, so the scores can be compared later with what the
//! registry took down (eval/watch_outcome.py). Runs until interrupted.
//! shortcut: a version published and superseded between two polls is not
//! seen, and the PyPI feed holds the last 100 updates only; a busy hour can
//! outrun a short feed. The remedy is a shorter interval.

use crate::{commands, execute_scan, ScanRequest};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const NPM_CHANGES: &str = "https://replicate.npmjs.com/registry/_changes";
const PYPI_UPDATES: &str = "https://pypi.org/rss/updates.xml";
/// Versions remembered so a re-announced one is not scanned twice.
const MAX_SEEN: usize = 200_000;

pub async fn run(
    ecosystem: &str,
    interval: u64,
    min_risk: u8,
    jobs: usize,
    osv_dir: Option<PathBuf>,
    log: Option<PathBuf>,
) -> anyhow::Result<()> {
    use std::io::Write;
    if let Some(dir) = &osv_dir {
        std::fs::create_dir_all(dir)?;
    }
    let mut log = match log {
        Some(path) => Some(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?,
        ),
        None => None,
    };
    let client = crate::vsix::http_client()?;
    let mut seen: HashSet<String> = HashSet::new();
    let mut since = match ecosystem {
        "npm" => {
            let head: serde_json::Value = client
                .get(format!("{NPM_CHANGES}?descending=true&limit=1"))
                .send()
                .await?
                .json()
                .await?;
            head["last_seq"].as_u64().unwrap_or(0)
        }
        "pypi" => 0,
        other => anyhow::bail!("kalascan watch knows npm and pypi, not `{other}`"),
    };
    eprintln!("kalascan watch: scanning new {ecosystem} releases every {interval}s; risk {min_risk} or more is reported");
    let permits = Arc::new(tokio::sync::Semaphore::new(jobs.max(1)));
    loop {
        let found = match ecosystem {
            "npm" => npm_releases(&client, &mut since).await,
            _ => pypi_releases(&client).await,
        };
        let targets = match found {
            Ok(targets) => targets,
            Err(e) => {
                // A registry hiccup: try again at the next poll.
                eprintln!("kalascan watch: {e}");
                Vec::new()
            }
        };
        if seen.len() > MAX_SEEN {
            seen.clear();
        }
        let mut tasks = tokio::task::JoinSet::new();
        for target in targets.into_iter().filter(|t| seen.insert(t.clone())) {
            let permits = permits.clone();
            tasks.spawn(async move {
                let _permit = permits.acquire_owned().await;
                let mut req: ScanRequest = serde_json::from_value(serde_json::json!({
                    "repo_url": target,
                    "check_cve": false,
                }))
                .expect("static request");
                req.third_party = true;
                (target, execute_scan(req).await)
            });
        }
        while let Some(joined) = tasks.join_next().await {
            let (target, result) = joined?;
            if let Some(file) = &mut log {
                writeln!(file, "{}", log_line(&target, &result))?;
            }
            let r = match result {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("   ?  {target}: not scanned: {e}");
                    continue;
                }
            };
            if r.risk_score < min_risk {
                continue;
            }
            println!(
                "{:>4}  {:<48} {}",
                r.risk_score,
                target,
                commands::strong_findings(&r).join(", ")
            );
            if let Some(dir) = &osv_dir {
                match crate::export::export_osv(&r) {
                    Ok(record) => {
                        let file: String = target
                            .chars()
                            .map(|c| {
                                if c.is_ascii_alphanumeric() || ".-_".contains(c) {
                                    c
                                } else {
                                    '_'
                                }
                            })
                            .collect();
                        std::fs::write(dir.join(format!("{file}.json")), record)?;
                    }
                    Err(e) => eprintln!("      no OSV record: {e}"),
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(interval)).await;
    }
}

/// One line of the `--log` file: when, what, and the score with its strong
/// findings and the ruleset and detection fingerprint that gave it, or why
/// there is none.
fn log_line(target: &str, result: &anyhow::Result<crate::ScanResult>) -> serde_json::Value {
    match result {
        Ok(r) => serde_json::json!({
            "ts": r.timestamp,
            "target": target,
            "risk": r.risk_score,
            "findings": commands::strong_findings(r),
            "ruleset": crate::scanner::RULESET_VERSION,
            "detection": crate::scanner::DETECTION_FINGERPRINT,
        }),
        Err(e) => serde_json::json!({
            "ts": crate::now_rfc3339(),
            "target": target,
            "error": e.to_string().lines().next().unwrap_or_default(),
        }),
    }
}

/// Packages changed on npm since `since`, as `npm:name@version` for the
/// version `latest` points at now; moves `since` forward.
async fn npm_releases(client: &reqwest::Client, since: &mut u64) -> anyhow::Result<Vec<String>> {
    let page: serde_json::Value = client
        .get(format!("{NPM_CHANGES}?since={since}&limit=500"))
        .send()
        .await?
        .json()
        .await?;
    let mut names: Vec<String> = page["results"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| c["deleted"].as_bool() != Some(true))
        .filter_map(|c| c["id"].as_str().map(str::to_string))
        .filter(|n| !n.starts_with("_design/"))
        .collect();
    names.sort();
    names.dedup();
    if let Some(next) = page["last_seq"].as_u64() {
        *since = next;
    }
    let mut out = Vec::new();
    for name in names {
        let latest: serde_json::Value = match client
            .get(format!(
                "https://registry.npmjs.org/{}/latest",
                name.replace('/', "%2F")
            ))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => resp.json().await.unwrap_or_default(),
            _ => continue,
        };
        if let Some(version) = latest["version"].as_str() {
            out.push(format!("npm:{name}@{version}"));
        }
    }
    Ok(out)
}

/// The versions in PyPI's recent-updates feed, as `pypi:name==version`.
async fn pypi_releases(client: &reqwest::Client) -> anyhow::Result<Vec<String>> {
    Ok(pypi_releases_from(
        &client.get(PYPI_UPDATES).send().await?.text().await?,
    ))
}

fn pypi_releases_from(feed: &str) -> Vec<String> {
    static TITLE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"<item>\s*<title>([^<\s]+) ([^<\s]+)</title>").unwrap()
    });
    TITLE
        .captures_iter(feed)
        .map(|c| format!("pypi:{}=={}", &c[1], &c[2]))
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_failed_scan_is_logged_with_its_reason() {
        let line = super::log_line("npm:x@1.0.0", &Err(anyhow::anyhow!("gone\nmore")));
        assert_eq!(line["target"], "npm:x@1.0.0");
        assert_eq!(line["error"], "gone");
        assert!(line["ts"].as_str().unwrap().ends_with('Z'));
    }

    #[test]
    fn pypi_feed_titles_become_targets() {
        let feed = "<rss><channel><item>\n      <title>vmware-harden 1.20.1</title>\n      <link>x</link></item><item>   <title>abx-dl 1.13.366</title></item></channel></rss>";
        let found: Vec<String> = super::pypi_releases_from(feed);
        assert_eq!(
            found,
            ["pypi:vmware-harden==1.20.1", "pypi:abx-dl==1.13.366"]
        );
    }
}
