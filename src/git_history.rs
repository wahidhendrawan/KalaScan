use crate::scanner::{build_rules, get_context, get_extension, is_critical_file};
use crate::RuleMatch;
use std::collections::HashSet;
use std::path::Path;
use tokio::process::Command;

/// Scan ALL commits in a cloned git repo for suspicious patterns.
/// Reuses scanner.rs regex rules against historical file content.
///
/// For each (commit, file) pair where the file matches critical extensions:
/// - `git show <commit>:<file>` retrieves content at that snapshot
/// - scanner rules are run against it
///
/// Returns `Vec<RuleMatch>` with `file_path` formatted as `"commit_hash:file_path"`,
/// one per (path, rule, matched text), at the commit that introduced it:
/// the same line re-reported for every later revision made the history
/// report six times longer than the tree's. `max_commits` newest commits,
/// optionally only those after `since` (any `git log --since` date).
pub async fn scan_git_history(
    repo_path: &Path,
    max_commits: usize,
    since: Option<&str>,
) -> Vec<RuleMatch> {
    let rules = build_rules();
    let mut matches = Vec::new();
    let mut seen: HashSet<(String, String, String)> = HashSet::new();

    let log_output = match get_commits_with_files(repo_path, max_commits, since).await {
        Some(out) => out,
        None => return matches,
    };

    let entries = parse_git_log(&log_output);
    // HEAD's files are the current tree, already scanned: reporting them
    // again under `<hash>:` doubled every finding.
    let head = git(repo_path, &["rev-parse", "HEAD"])
        .await
        .map(|h| h.trim().to_string())
        .unwrap_or_default();

    // git log is newest first; oldest first makes the first sighting the
    // introducing commit.
    for (commit_hash, files) in entries.iter().rev().filter(|(hash, _)| *hash != head) {
        for file in files {
            let lower_file = file.to_lowercase();
            if !is_critical_file(&lower_file) {
                continue;
            }

            let ext = get_extension(&lower_file);

            let content = match get_file_at_commit(repo_path, commit_hash, file).await {
                Some(c) => c,
                None => continue, // deleted or binary at this commit
            };

            let history_file_path = format!("{}:{}", commit_hash, file);
            let newlines: Vec<usize> = content.match_indices('\n').map(|(i, _)| i).collect();

            for rule in &rules {
                if !rule.applies_to(ext, file) {
                    continue;
                }

                for cap in rule.pattern.find_iter(&content) {
                    if !seen.insert((file.clone(), rule.name.clone(), cap.as_str().to_string())) {
                        continue;
                    }
                    let context = get_context(&content, cap.start(), cap.end());

                    matches.push(RuleMatch {
                        file_path: history_file_path.clone(),
                        line_number: newlines.partition_point(|&i| i < cap.start()) + 1,
                        matched_pattern: rule.name.to_string(),
                        severity: rule.severity.to_string(),
                        context,
                    });
                }
            }
        }
    }

    matches
}

/// `git -C <repo> <args>` stdout, `None` on failure. kill_on_drop: a scan
/// that times out must not leave git running.
async fn git_bytes(repo_path: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_path)
        .args(args)
        .kill_on_drop(true)
        .output()
        .await
        .ok()?;
    output.status.success().then_some(output.stdout)
}

async fn git(repo_path: &Path, args: &[&str]) -> Option<String> {
    String::from_utf8(git_bytes(repo_path, args).await?).ok()
}

/// The tree path of a finding: history hits are named `<40-hex hash>:<path>`.
/// The risk score counts one (file, rule) pair once, and the same line seen
/// in five commits is still one finding.
pub fn tree_path(file_path: &str) -> &str {
    match file_path.split_once(':') {
        Some((hash, path)) if hash.len() == 40 && hash.bytes().all(|b| b.is_ascii_hexdigit()) => {
            path
        }
        _ => file_path,
    }
}

/// Commits walked by default (`--max-commits`).
pub const DEFAULT_MAX_COMMITS: usize = 1000;

/// Run `git log --diff-filter=AM --name-only --format=COMMIT:%H --max-count=N [--since=D]`
async fn get_commits_with_files(
    repo_path: &Path,
    max_commits: usize,
    since: Option<&str>,
) -> Option<String> {
    let max = format!("--max-count={}", max_commits);
    // One `--since=<date>` argument: a date can never become a second option.
    let since = since.map(|s| format!("--since={}", s));
    let mut args = vec![
        "log",
        "--diff-filter=AM",
        "--name-only",
        "--format=COMMIT:%H",
        &max,
    ];
    args.extend(since.as_deref());
    git(repo_path, &args).await
}

/// Parse git log output.
///
/// Format per commit (with `--format=COMMIT:%H --name-only`):
/// ```text
/// COMMIT:<hash>
/// <file1>
/// <file2>
/// COMMIT:<hash>
/// <file1>
/// ```
/// Blank lines are ignored, so files are never mistaken for commit hashes.
fn parse_git_log(log: &str) -> Vec<(String, Vec<String>)> {
    let mut entries = Vec::new();
    let mut current_hash = String::new();
    let mut current_files: Vec<String> = Vec::new();

    for line in log.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(hash) = line.strip_prefix("COMMIT:") {
            if !current_hash.is_empty() {
                entries.push((
                    std::mem::take(&mut current_hash),
                    std::mem::take(&mut current_files),
                ));
            }
            current_hash = hash.to_string();
        } else if !current_hash.is_empty() {
            current_files.push(line.to_string());
        }
    }

    if !current_hash.is_empty() {
        entries.push((current_hash, current_files));
    }

    entries
}

/// Get file content at a specific commit via `git show <commit>:<path>`.
///
/// Returns `None` if the file was deleted, is binary, or exceeds 1 MiB.
async fn get_file_at_commit(
    repo_path: &Path,
    commit_hash: &str,
    file_path: &str,
) -> Option<String> {
    let spec = format!("{}:{}", commit_hash, file_path);
    // `None`: deleted or binary at this commit
    let content = git(repo_path, &["show", &spec]).await?;

    // Binary content contains null bytes
    if content.contains('\0') {
        return None;
    }

    // Cap at 1 MiB
    if content.len() > 1_048_576 {
        return None;
    }

    Some(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_git_log_two_commits() {
        let log = "COMMIT:abc123def\n\nsrc/main.py\nsrc/utils.js\nCOMMIT:def789abc\n\nscript.sh\n";
        let entries = parse_git_log(log);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, "abc123def");
        assert_eq!(entries[0].1, vec!["src/main.py", "src/utils.js"]);
        assert_eq!(entries[1].0, "def789abc");
        assert_eq!(entries[1].1, vec!["script.sh"]);
    }

    #[test]
    fn test_parse_git_log_single_commit_no_trailing_blank() {
        let log = "COMMIT:abc123\n\na.py\nb.ts\n";
        let entries = parse_git_log(log);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "abc123");
        assert_eq!(entries[0].1, vec!["a.py", "b.ts"]);
    }

    #[test]
    fn test_parse_git_log_empty() {
        let entries = parse_git_log("");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_git_log_blank_only() {
        let entries = parse_git_log("\n\n");
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn history_reports_each_finding_once_at_its_first_commit() {
        let dir = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args([
                    "-c",
                    "user.name=t",
                    "-c",
                    "user.email=t@t",
                    "-c",
                    "commit.gpgsign=false",
                ])
                .args(args)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {:?}: {}",
                args,
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap()
        };
        git(&["init", "-q"]);
        let mut hashes = Vec::new();
        for body in [
            "eval(atob(p));\n",
            "// v2\neval(atob(p));\n",
            "// v3\neval(atob(p));\n",
        ] {
            std::fs::write(dir.path().join("a.js"), body).unwrap();
            git(&["add", "a.js"]);
            git(&["commit", "-q", "-m", "c"]);
            hashes.push(git(&["rev-parse", "HEAD"]).trim().to_string());
        }

        let found = scan_git_history(dir.path(), DEFAULT_MAX_COMMITS, None).await;
        let evals: Vec<_> = found
            .iter()
            .filter(|m| m.matched_pattern == "eval() Usage")
            .collect();
        assert_eq!(evals.len(), 1, "{:?}", found);
        assert_eq!(evals[0].file_path, format!("{}:a.js", hashes[0]));
        // --max-commits 1 walks HEAD only, which the tree scan already covers.
        assert!(scan_git_history(dir.path(), 1, None).await.is_empty());
        assert!(
            scan_git_history(dir.path(), DEFAULT_MAX_COMMITS, Some("2099-12-31"))
                .await
                .is_empty()
        );
    }

    #[test]
    fn test_get_context_short() {
        // "line1\nline2\nbadstuff\nline4\nline5": "badstuff" at bytes [12, 20)
        let ctx = get_context("line1\nline2\nbadstuff\nline4\nline5", 12, 20);
        assert!(ctx.contains(">>> badstuff <<<"), "context: {:?}", ctx);
    }

    #[test]
    fn test_tree_path() {
        let hash = "031a028c1f4e2b7d9a0c3e5f7a9b1d3f5e7a9c1b";
        assert_eq!(tree_path(&format!("{}:src/a.js", hash)), "src/a.js");
        assert_eq!(tree_path("src/a.js"), "src/a.js");
        assert_eq!(tree_path("C:/repo/a.js"), "C:/repo/a.js");
    }

    #[test]
    fn test_get_context_multibyte_does_not_panic() {
        let text = format!("{}中中中中中\neval(x)", "a".repeat(196));
        let at = text.find("eval").unwrap();
        assert!(get_context(&text, at, at + 5).contains(">>> eval( <<<"));
    }

    #[test]
    fn test_get_context_truncated() {
        let long = "x".repeat(500);
        let ctx = get_context(&long, 0, 50);
        assert!(ctx.len() <= 203); // 200 + "..."
    }
}
