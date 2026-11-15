//! End-to-end checks of the `kalascan` binary on the synthetic fixtures
//! under tests/fixtures (no real malware: loader.js only evals a base64 string).
//! Everything runs offline: no registry, marketplace or OSV calls.

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

/// `kalascan <args>` from an empty temp dir.
fn kalascan(args: &[&str]) -> assert_cmd::assert::Assert {
    let cwd = tempfile::tempdir().unwrap();
    Command::new(env!("CARGO_BIN_EXE_kalascan"))
        .current_dir(cwd.path())
        .args(args)
        .assert()
}

fn stdout_json(run: &assert_cmd::assert::Assert) -> serde_json::Value {
    serde_json::from_slice(&run.get_output().stdout).expect("valid JSON on stdout")
}

fn stderr(run: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&run.get_output().stderr).to_string()
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

#[test]
fn default_ignore_file_covers_the_own_checkout_only() {
    let cwd = tempfile::tempdir().unwrap();
    std::fs::write(cwd.path().join(".kalascanignore"), "*.js\n").unwrap();
    let target = fixture("suspicious");
    let own = scan_json(cwd.path(), &[&target, "--format", "json"]);
    assert_eq!(own["total_matches"], 0, "{}", own["rule_matches"]);
    // Someone else's code scanned from the same directory keeps its findings.
    let theirs = scan_json(cwd.path(), &[&target, "--untrusted", "--format", "json"]);
    assert!(rule_names(&theirs).iter().any(|r| r == "eval() Usage"));
    // An explicit --ignore applies either way.
    let explicit = scan_json(
        cwd.path(),
        &[
            &target,
            "--untrusted",
            "--ignore",
            ".kalascanignore",
            "--format",
            "json",
        ],
    );
    assert_eq!(explicit["total_matches"], 0);
}

#[cfg(unix)]
#[test]
fn closed_stdout_ends_the_run_without_a_panic() {
    // `kalascan scan … | head`: the reader is gone before the report is printed.
    let cwd = tempfile::tempdir().unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_kalascan"))
        .current_dir(cwd.path())
        .args(["scan", &fixture("suspicious"), "--format", "json"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("panicked"), "{}", err);
    // Not 0: the run was cut short before any --fail-on-risk gate.
    assert_eq!(out.status.code(), Some(141), "{}", err);
}

#[test]
fn diff_lists_what_only_the_new_version_does() {
    let (old, new) = (fixture("clean"), fixture("suspicious"));
    let run = kalascan(&["diff", &old, &new, "--format", "json"]).success();
    let v = stdout_json(&run);
    let rules: Vec<&str> = v["new_capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["rule"].as_str().unwrap())
        .collect();
    assert_eq!(rules, vec!["eval() Usage"]);
    assert!(v["new_risk"].as_u64() > v["old_risk"].as_u64());

    kalascan(&["diff", &old, &new, "--fail-on-new", "high"]).code(1);
    kalascan(&["diff", &old, &new, "--fail-on-new", "critical"]).success();
    // The other way round nothing is new.
    kalascan(&["diff", &new, &old, "--fail-on-new", "low"]).success();
    kalascan(&["diff", &old, &new, "--fail-on-new", "severe"]).failure();
}

#[test]
fn deps_needs_a_lockfile_with_registry_packages() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_str().unwrap();
    let run = kalascan(&["deps", path]).failure();
    assert!(stderr(&run).contains("yarn.lock"), "{}", stderr(&run));
    // Git dependencies are not registry packages: still nothing to scan
    // (and nothing fetched).
    std::fs::write(
        dir.path().join("yarn.lock"),
        "\"x@https://github.com/x/y.git\":\n  version \"1.0.0\"\n  resolved \"https://github.com/x/y.git#abc\"\n",
    )
    .unwrap();
    kalascan(&["deps", path]).failure();
}

#[test]
fn deps_reuses_cached_results() {
    // The cache file is named after the KalaScan and ruleset versions.
    let run = kalascan(&["rules"]).success();
    let listing = String::from_utf8_lossy(&run.get_output().stdout).to_string();
    let ruleset = listing
        .lines()
        .find_map(|l| l.strip_prefix("Ruleset version: "))
        .expect("ruleset version line")
        .trim();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(
        cache.path().join(format!(
            "deps-{}-{}.json",
            env!("CARGO_PKG_VERSION"),
            ruleset
        )),
        r#"{"npm:left-pad@1.3.0": {"risk_score": 77, "critical": ["Chain: Seeded"]}}"#,
    )
    .unwrap();
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("yarn.lock"),
        "left-pad@1.3.0:\n  version \"1.3.0\"\n  resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#abc\"\n",
    )
    .unwrap();
    let deps = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_kalascan"))
            .current_dir(project.path())
            .env("KALASCAN_CACHE_DIR", cache.path())
            .args(["deps", "."])
            .args(args)
            .assert()
    };
    // Nothing is downloaded: the only locked package is in the cache.
    let v = stdout_json(&deps(&["--format", "json"]).success());
    assert_eq!(v[0]["package"], "npm:left-pad@1.3.0");
    assert_eq!(v[0]["source"], "yarn.lock");
    assert_eq!(v[0]["risk_score"], 77);
    assert_eq!(v[0]["critical"][0], "Chain: Seeded");
    deps(&["--fail-on-risk", "70"]).code(1);
}

#[test]
fn installed_scans_the_extensions_under_home() {
    let home = tempfile::tempdir().unwrap();
    let ext = home.path().join(".vscode/extensions/acme.loader-1.0.0");
    std::fs::create_dir_all(&ext).unwrap();
    std::fs::write(
        ext.join("package.json"),
        r#"{"name":"loader","publisher":"acme","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::copy(
        Path::new(&fixture("suspicious")).join("loader.js"),
        ext.join("loader.js"),
    )
    .unwrap();
    let installed = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_kalascan"))
            .current_dir(home.path())
            .env("HOME", home.path())
            .env_remove("USERPROFILE")
            .env_remove("LOCALAPPDATA")
            .arg("installed")
            .args(args)
            .assert()
    };
    let v = stdout_json(&installed(&["--format", "json"]).success());
    let rows = v.as_array().unwrap();
    assert_eq!(rows.len(), 1, "{}", v);
    assert_eq!(rows[0]["app"], "VS Code");
    assert_eq!(rows[0]["extension"], "acme.loader-1.0.0");
    assert!(rows[0]["risk_score"].as_u64().unwrap() > 0);
    installed(&["--fail-on-risk", "1"]).code(1);
}

#[test]
fn rules_sbom_and_import_print_their_reports() {
    let run = kalascan(&["rules"]).success();
    let listing = String::from_utf8_lossy(&run.get_output().stdout).to_string();
    assert!(listing.contains("KS-EXF-001"), "{}", listing);
    kalascan(&["rules", "KS-EXF-001"]).success();

    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("package.json"),
        r#"{"name":"app","version":"1.0.0","dependencies":{"lodash":"4.17.21"}}"#,
    )
    .unwrap();
    let sbom = stdout_json(&kalascan(&["sbom", project.path().to_str().unwrap()]).success());
    assert_eq!(sbom["bomFormat"], "CycloneDX");
    assert!(
        sbom["components"].to_string().contains("lodash"),
        "{}",
        sbom["components"]
    );

    let nessus = Path::new(&fixture("import")).join("nessus.nessus");
    let nessus = nessus.to_str().unwrap();
    let v = stdout_json(&kalascan(&["import", nessus, "--format", "json"]).success());
    assert_eq!(v["format"], "nessus");
    assert_eq!(v["summary"]["total"], 3);
    kalascan(&["import", nessus, "--fail-on", "high"]).code(1);
    // Entity declarations (XXE) are refused, not expanded.
    let xxe = Path::new(&fixture("import")).join("xxe.xml");
    kalascan(&["import", xxe.to_str().unwrap()]).failure();
}

/// `kalascan serve` on a free loopback port, killed when the test ends.
struct Server {
    child: std::process::Child,
    base: String,
    _cwd: tempfile::TempDir,
}

impl Server {
    async fn start() -> Server {
        // Free port: bind to 0, read it back, release it for the server.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        // Own cwd: kalascan.db is created there.
        let cwd = tempfile::tempdir().unwrap();
        let child = std::process::Command::new(env!("CARGO_BIN_EXE_kalascan"))
            .current_dir(cwd.path())
            .env_remove("KALASCAN_TOKEN")
            .env("RUST_LOG", "off")
            .args(["serve", "--addr", &format!("127.0.0.1:{}", port)])
            .spawn()
            .unwrap();
        let server = Server {
            child,
            base: format!("http://127.0.0.1:{}", port),
            _cwd: cwd,
        };
        for _ in 0..100 {
            if reqwest::get(format!("{}/healthz", server.base))
                .await
                .is_ok()
            {
                return server;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        panic!("server did not come up on {}", server.base);
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test]
async fn web_api_scans_an_upload_and_refuses_local_paths() {
    let server = Server::start().await;
    let http = reqwest::Client::new();
    let url = |path: &str| format!("{}{}", server.base, path);

    let health = http.get(url("/healthz")).send().await.unwrap();
    assert_eq!(health.status(), 200);
    let page = http.get(url("/")).send().await.unwrap();
    assert_eq!(page.status(), 200);
    assert!(page.headers().contains_key("content-security-policy"));

    // No CORS headers, and a page on another site is refused outright.
    assert!(!health.headers().contains_key("access-control-allow-origin"));
    let foreign = http
        .get(url("/api/history"))
        .header("origin", "https://evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(foreign.status(), 403);
    let same = http
        .get(url("/api/history"))
        .header("origin", server.base.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(same.status(), 200);

    // DNS rebinding: the browser calls it same-origin, the Host is not ours.
    let port = server.base.rsplit(':').next().unwrap();
    let rebound = http
        .get(url("/api/history"))
        .header("host", format!("evil.example:{}", port))
        .header("origin", format!("http://evil.example:{}", port))
        .send()
        .await
        .unwrap();
    assert_eq!(rebound.status(), 403);
    let localhost = http
        .get(url("/api/history"))
        .header("host", format!("localhost:{}", port))
        .send()
        .await
        .unwrap();
    assert_eq!(localhost.status(), 200);

    // A path on the server is not a scan target for API callers.
    let local = http
        .post(url("/api/scan"))
        .json(&serde_json::json!({ "repo_url": fixture("suspicious") }))
        .send()
        .await
        .unwrap();
    assert_eq!(local.status(), 400);

    // Upload the fixture as a .vsix-shaped zip; check_cve=false keeps it offline.
    let mut zip_bytes = std::io::Cursor::new(Vec::new());
    {
        use std::io::Write;
        let mut w = zip::ZipWriter::new(&mut zip_bytes);
        w.start_file(
            "extension/loader.js",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        w.write_all(&std::fs::read(Path::new(&fixture("suspicious")).join("loader.js")).unwrap())
            .unwrap();
        w.finish().unwrap();
    }
    let mut body = Vec::new();
    body.extend_from_slice(
        b"--kalascan-test\r\nContent-Disposition: form-data; name=\"check_cve\"\r\n\r\nfalse\r\n\
          --kalascan-test\r\nContent-Disposition: form-data; name=\"file\"; filename=\"loader.vsix\"\r\n\
          Content-Type: application/zip\r\n\r\n",
    );
    body.extend_from_slice(zip_bytes.get_ref());
    body.extend_from_slice(b"\r\n--kalascan-test--\r\n");
    let accepted: serde_json::Value = http
        .post(url("/api/scan/upload"))
        .header(
            "content-type",
            "multipart/form-data; boundary=kalascan-test",
        )
        .body(body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(accepted["status"], "queued", "{}", accepted);
    let id = accepted["result_id"].as_str().unwrap();

    let mut status = serde_json::Value::Null;
    for _ in 0..300 {
        status = http
            .get(url(&format!("/api/scan/{}/status", id)))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if status["done"] == true {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(status["status"], "completed", "{}", status);
    assert!(
        rule_names(&status["result"])
            .iter()
            .any(|r| r == "eval() Usage"),
        "{}",
        status["result"]["rule_matches"]
    );

    let missing = http
        .get(url("/api/scan/no-such-id/status"))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
}
