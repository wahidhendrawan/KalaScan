//! End-to-end checks of the `kalascan scan` binary on the synthetic fixtures
//! under tests/fixtures (no real malware: loader.js only evals a base64 string).

use assert_cmd::Command;
use std::path::Path;

fn fixture(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
        .to_string_lossy()
        .to_string()
}

/// `kalascan scan <args>` run from `cwd`: an empty temp dir unless the test
/// plants a kalascan.toml there, so nothing in the checkout leaks in.
fn scan(cwd: &Path, args: &[&str]) -> assert_cmd::assert::Assert {
    Command::new(env!("CARGO_BIN_EXE_kalascan"))
        .current_dir(cwd)
        .arg("scan")
        .args(args)
        .assert()
}

fn scan_json(cwd: &Path, args: &[&str]) -> serde_json::Value {
    let run = scan(cwd, args).success();
    serde_json::from_slice(&run.get_output().stdout).expect("valid JSON on stdout")
}

fn rule_names(report: &serde_json::Value) -> Vec<String> {
    report["rule_matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["matched_pattern"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn json_report_has_the_documented_shape_and_a_duration() {
    let cwd = tempfile::tempdir().unwrap();
    let v = scan_json(cwd.path(), &[&fixture("suspicious"), "--format", "json"]);
    assert_eq!(v["status"], "completed");
    assert!(
        v["duration_ms"].is_u64(),
        "duration_ms: {}",
        v["duration_ms"]
    );
    assert!(v["risk_score"].as_u64().unwrap() > 0);
    assert_eq!(v["scanned_files"], 1);
    assert_eq!(v["total_files"], 1);
    assert!(
        rule_names(&v).iter().any(|r| r == "eval() Usage"),
        "{:?}",
        rule_names(&v)
    );
    for key in [
        "id",
        "repo_url",
        "timestamp",
        "total_matches",
        "iocs",
        "ttp",
        "triage",
    ] {
        assert!(!v[key].is_null(), "missing {}", key);
    }
}

#[test]
fn sarif_driver_carries_the_version() {
    let cwd = tempfile::tempdir().unwrap();
    let v = scan_json(cwd.path(), &[&fixture("suspicious"), "--format", "sarif"]);
    let driver = &v["runs"][0]["tool"]["driver"];
    assert_eq!(driver["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(driver["semanticVersion"], env!("CARGO_PKG_VERSION"));
    assert!(!v["runs"][0]["results"].as_array().unwrap().is_empty());
}

#[test]
fn fail_on_risk_sets_the_exit_code() {
    let cwd = tempfile::tempdir().unwrap();
    scan(cwd.path(), &[&fixture("suspicious"), "--fail-on-risk", "1"]).code(1);
    scan(
        cwd.path(),
        &[&fixture("suspicious"), "--fail-on-risk", "100"],
    )
    .success();
    scan(cwd.path(), &[&fixture("clean"), "--fail-on-risk", "1"]).success();
}

#[test]
fn config_file_is_read_and_flags_win() {
    let cwd = tempfile::tempdir().unwrap();
    let target = fixture("suspicious");
    // ./kalascan.toml is picked up by default ...
    std::fs::write(cwd.path().join("kalascan.toml"), "fail_on_risk = 1\n").unwrap();
    scan(cwd.path(), &[&target]).code(1);
    // ... and a flag beats it.
    scan(cwd.path(), &[&target, "--fail-on-risk", "100"]).success();

    // --config names another file; the output format comes from it too.
    let other = cwd.path().join("policy.toml");
    std::fs::write(&other, "format = \"json\"\nfail_on_risk = 100\n").unwrap();
    let v = scan_json(cwd.path(), &[&target, "--config", other.to_str().unwrap()]);
    assert_eq!(v["status"], "completed");

    // A typo must not silently disable a gate.
    std::fs::write(&other, "fail_on_rsk = 1\n").unwrap();
    let run = scan(cwd.path(), &[&target, "--config", other.to_str().unwrap()]).failure();
    let stderr = String::from_utf8_lossy(&run.get_output().stderr);
    assert!(stderr.contains("fail_on_rsk"), "{}", stderr);
}

#[test]
fn ransom_note_ignores_threat_intel_columns() {
    let cwd = tempfile::tempdir().unwrap();
    let v = scan_json(cwd.path(), &[&fixture("clean"), "--format", "json"]);
    assert!(
        !rule_names(&v).iter().any(|r| r == "Ransom Note"),
        "{:?}",
        rule_names(&v)
    );
    assert_eq!(v["risk_score"], 0, "{}", v["rule_matches"]);
}

#[test]
fn rust_log_is_honoured() {
    let cwd = tempfile::tempdir().unwrap();
    let quiet = Command::new(env!("CARGO_BIN_EXE_kalascan"))
        .current_dir(cwd.path())
        .env("RUST_LOG", "off")
        .args(["scan", &fixture("clean")])
        .assert()
        .success();
    assert!(quiet.get_output().stderr.is_empty());
    let verbose = Command::new(env!("CARGO_BIN_EXE_kalascan"))
        .current_dir(cwd.path())
        .env("RUST_LOG", "kalascan=debug")
        .args(["scan", &fixture("clean")])
        .assert()
        .success();
    assert!(String::from_utf8_lossy(&verbose.get_output().stderr).contains("INFO"));
}
