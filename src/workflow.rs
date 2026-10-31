//! GitHub Actions workflow checks (`.github/workflows/*.yml`).
//!
//! Line-based, no YAML parser: `run:` / `script:` blocks are tracked by
//! indentation, which is how YAML scopes them anyway.

use crate::RuleMatch;
use regex::Regex;
use std::sync::LazyLock;

pub const PWN_REQUEST: &str = "GitHub Actions Pwn Request (pull_request_target + PR checkout)";
pub const SCRIPT_INJECTION: &str = "GitHub Actions Script Injection";
pub const UNPINNED_ACTION: &str = "GitHub Actions Unpinned Third-Party Action";
pub const SPOOFABLE_BOT_CHECK: &str = "GitHub Actions Spoofable Bot Check (github.actor)";

/// `github.actor` is whoever last triggered the run, not the PR author.
static ACTOR_BOT_CHECK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"github\.actor\s*==\s*['\x22][\w-]+\[bot\]['\x22]").unwrap());

/// Attacker-controlled contexts (GitHub Security Lab list).
static UNTRUSTED_EXPR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\$\{\{\s*(?:github\.head_ref|github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.(?:ref|label)|head\.repo\.default_branch)|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)|pages\.[^}]*page_name|commits\.[^}]*(?:message|author)|head_commit\.(?:message|author)|workflow_run\.(?:head_branch|head_commit)))",
    )
    .unwrap()
});

static PR_HEAD_REF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"ref:\s*\$\{\{\s*(?:github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref)",
    )
    .unwrap()
});

static USES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"uses:\s*['\x22]?([\w.-]+)/[\w./-]+@([\w.-]+)").unwrap());

pub fn is_workflow(rel_path: &str) -> bool {
    let p = rel_path.replace('\\', "/");
    p.contains(".github/workflows/") && (p.ends_with(".yml") || p.ends_with(".yaml"))
}

pub fn scan(rel_path: &str, content: &str) -> Vec<RuleMatch> {
    let mut out = Vec::new();
    let finding = |line: usize, name: &str, severity: &str, context: &str| RuleMatch {
        file_path: rel_path.to_string(),
        line_number: line,
        matched_pattern: name.to_string(),
        severity: severity.to_string(),
        context: context.trim().chars().take(200).collect(),
    };

    let pr_target = content.contains("pull_request_target");
    // Indent of the `run:`/`script:` key whose block we are inside.
    let mut block_indent: Option<usize> = None;

    for (idx, line) in content.lines().enumerate() {
        let n = idx + 1;
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        if trimmed.starts_with('#') {
            continue;
        }
        if block_indent.is_some_and(|b| !trimmed.is_empty() && indent <= b) {
            block_indent = None;
        }
        // `- run: x` puts the key two columns right of the dash.
        let key = trimmed.trim_start_matches("- ");
        let key_indent = indent + (trimmed.len() - key.len());
        if key.starts_with("run:") || key.starts_with("script:") {
            block_indent = Some(key_indent);
        }

        if block_indent.is_some() && UNTRUSTED_EXPR.is_match(line) {
            out.push(finding(n, SCRIPT_INJECTION, "high", line));
        }
        if pr_target && PR_HEAD_REF.is_match(line) {
            out.push(finding(n, PWN_REQUEST, "critical", line));
        }
        if ACTOR_BOT_CHECK.is_match(line) {
            out.push(finding(n, SPOOFABLE_BOT_CHECK, "medium", line));
        }
        if let Some(c) = USES.captures(key) {
            let (owner, git_ref) = (&c[1], &c[2]);
            let pinned = git_ref.len() == 40 && git_ref.chars().all(|ch| ch.is_ascii_hexdigit());
            if !pinned && owner != "actions" && owner != "github" {
                out.push(finding(n, UNPINNED_ACTION, "low", line));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const WF: &str = r#"on:
  pull_request_target:
  issues:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: some-org/deploy-action@v2
      - uses: other/tool@0123456789abcdef0123456789abcdef01234567
      - name: greet
        run: |
          echo "title: ${{ github.event.issue.title }}"
          echo "safe: ${{ github.event.issue.number }}"
      - name: label
        env:
          TITLE: ${{ github.event.issue.title }}
        run: echo "$TITLE"
"#;

    #[test]
    fn flags_pwn_request_injection_and_unpinned() {
        assert!(is_workflow(".github/workflows/ci.yml"));
        assert!(!is_workflow("docs/ci.yml"));

        let got: Vec<(usize, String)> = scan(".github/workflows/ci.yml", WF)
            .into_iter()
            .map(|m| (m.line_number, m.matched_pattern))
            .collect();
        assert_eq!(
            got,
            vec![
                (10, PWN_REQUEST.to_string()),
                (11, UNPINNED_ACTION.to_string()),
                (15, SCRIPT_INJECTION.to_string()),
            ]
        );
    }

    #[test]
    fn flags_actor_based_bot_check() {
        let bad = "jobs:\n  m:\n    if: github.actor == 'dependabot[bot]'\n";
        let good =
            "jobs:\n  m:\n    if: github.event.pull_request.user.login == 'dependabot[bot]'\n";
        assert_eq!(
            scan(".github/workflows/m.yml", bad)[0].matched_pattern,
            SPOOFABLE_BOT_CHECK
        );
        assert!(scan(".github/workflows/m.yml", good).is_empty());
    }

    #[test]
    fn pr_checkout_without_pull_request_target_is_fine() {
        let wf = "on: pull_request\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.head_ref }}\n";
        assert!(scan(".github/workflows/a.yml", wf).is_empty());
    }
}
