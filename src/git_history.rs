use crate::scanner::{build_rules, get_context, get_extension, is_critical_file};
use crate::RuleMatch;
use std::path::Path;
use tokio::process::Command;

/// Scan ALL commits in a cloned git repo for suspicious patterns.
/// Reuses scanner.rs regex rules against historical file content.
///
/// For each (commit, file) pair where the file matches critical extensions:
/// - `git show <commit>:<file>` retrieves content at that snapshot
/// - scanner rules are run against it
///
/// Returns `Vec<RuleMatch>` with `file_path` formatted as `"commit_hash:file_path"`.
pub async fn scan_git_history(repo_path: &Path) -> Vec<RuleMatch> {
    let rules = build_rules();
    let mut matches = Vec::new();

    let log_output = match get_commits_with_files(repo_path).await {
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

    for (commit_hash, files) in entries.iter().filter(|(hash, _)| *hash != head) {
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

/// Run `git log --diff-filter=AM --name-only --format=COMMIT:%H`
async fn get_commits_with_files(repo_path: &Path) -> Option<String> {
    git(
        repo_path,
        &[
            "log",
            "--diff-filter=AM",
            "--name-only",
            "--format=COMMIT:%H",
        ],
    )
    .await
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
