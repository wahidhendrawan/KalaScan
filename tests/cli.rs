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
    // The score is the sum of its listed parts, under either model.
    for (model, flags) in [("v1", &[][..]), ("v2", &["--score-model", "v2"][..])] {
        let mut args = vec![fixture("suspicious"), "--format".into(), "json".into()];
        args.extend(flags.iter().map(|f| f.to_string()));
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let v = scan_json(cwd.path(), &args);
        assert_eq!(v["score_breakdown"]["model"], model);
        let parts: u64 = v["score_breakdown"]["parts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["points"].as_u64().unwrap())
            .sum();
        assert_eq!(parts.min(100), v["risk_score"].as_u64().unwrap(), "{model}");
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
fn stix_bundle_describes_the_scan() {
    let cwd = tempfile::tempdir().unwrap();
    let v = scan_json(cwd.path(), &[&fixture("suspicious"), "--format", "stix"]);
    assert_eq!(v["type"], "bundle");
    let objects = v["objects"].as_array().unwrap();
    for o in objects {
        assert_eq!(o["spec_version"], "2.1", "{}", o);
    }
    let types: Vec<&str> = objects
        .iter()
        .map(|o| o["type"].as_str().unwrap())
        .collect();
    assert_eq!(types.first(), Some(&"identity"));
    assert_eq!(types.last(), Some(&"report"));
    assert!(types.contains(&"attack-pattern"), "{:?}", types);
}

#[test]
fn osv_refuses_a_directory() {
    // A directory has no registry identity; the registry targets are
    // covered offline by the unit tests in src/export/osv.rs.
    let cwd = tempfile::tempdir().unwrap();
    let run = scan(cwd.path(), &[&fixture("suspicious"), "--format", "osv"]).failure();
    assert!(stderr(&run).contains("exact version"), "{}", stderr(&run));
    assert!(run.get_output().stdout.is_empty());
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
    cwd: tempfile::TempDir,
}

impl Server {
    async fn start() -> Server {
        Server::start_with(&[]).await
    }

    /// `envs` on top of a clean environment, e.g. a KALASCAN_HOME that
    /// outlives this server so a second one can resume its queue.
    async fn start_with(envs: &[(&str, &str)]) -> Server {
        Server::start_in(tempfile::tempdir().unwrap(), envs).await
    }

    /// `cwd` may already hold a kalascan.db with users; the server's log
    /// goes to `server.log` in it.
    async fn start_in(cwd: tempfile::TempDir, envs: &[(&str, &str)]) -> Server {
        // Free port: bind to 0, read it back, release it for the server.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        // Own cwd: kalascan.db is created there.
        let child = std::process::Command::new(env!("CARGO_BIN_EXE_kalascan"))
            .current_dir(cwd.path())
            .env_remove("KALASCAN_TOKEN")
            .env_remove("KALASCAN_ALLOW_PRIVATE_TARGETS")
            .env("RUST_LOG", "off")
            .envs(envs.iter().copied())
            .stderr(std::fs::File::create(cwd.path().join("server.log")).unwrap())
            .args(["serve", "--addr", &format!("127.0.0.1:{}", port)])
            .spawn()
            .unwrap();
        let server = Server {
            child,
            base: format!("http://127.0.0.1:{}", port),
            cwd,
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

    fn log(&self) -> String {
        std::fs::read_to_string(self.cwd.path().join("server.log")).unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A one-file .vsix as the body of a `multipart/form-data; boundary=kalascan-test` upload.
fn upload_body() -> Vec<u8> {
    use std::io::Write;
    let mut zip_bytes = std::io::Cursor::new(Vec::new());
    let mut w = zip::ZipWriter::new(&mut zip_bytes);
    w.start_file("extension/a.js", zip::write::SimpleFileOptions::default())
        .unwrap();
    w.write_all(b"console.log(1);\n").unwrap();
    w.finish().unwrap();
    let mut body = b"--kalascan-test\r\nContent-Disposition: form-data; name=\"file\"; \
        filename=\"a.vsix\"\r\nContent-Type: application/zip\r\n\r\n"
        .to_vec();
    body.extend_from_slice(zip_bytes.get_ref());
    body.extend_from_slice(b"\r\n--kalascan-test--\r\n");
    body
}

async fn upload(http: &reqwest::Client, base: &str) -> reqwest::Response {
    http.post(format!("{}/api/scan/upload", base))
        .header(
            "content-type",
            "multipart/form-data; boundary=kalascan-test",
        )
        .body(upload_body())
        .send()
        .await
        .unwrap()
}

fn entries(dir: &Path) -> usize {
    std::fs::read_dir(dir).unwrap().count()
}

#[tokio::test]
async fn a_full_queue_refuses_new_scans() {
    let tmp = tempfile::tempdir().unwrap();
    // No slots: every accepted scan stays queued, so nothing is downloaded.
    let server = Server::start_with(&[
        ("KALASCAN_MAX_CONCURRENT_SCANS", "0"),
        ("KALASCAN_SCAN_RATE_LIMIT", "1000"),
        ("TMPDIR", tmp.path().to_str().unwrap()),
    ])
    .await;
    let http = reqwest::Client::new();
    let submit = || {
        http.post(format!("{}/api/scan", server.base))
            .json(&serde_json::json!({ "repo_url": "npm:left-pad" }))
            .send()
    };
    // MAX_PENDING_SCANS in src/server.rs.
    for i in 0..64 {
        assert_eq!(submit().await.unwrap().status(), 200, "scan {}", i);
    }
    let full = submit().await.unwrap();
    assert_eq!(full.status(), 429);
    let error: serde_json::Value = full.json().await.unwrap();
    assert!(
        error["error"].as_str().unwrap().contains("queue is full"),
        "{}",
        error
    );
    // A refused upload does not leave its extracted tree behind.
    assert_eq!(upload(&http, &server.base).await.status(), 429);
    assert_eq!(entries(tmp.path()), 0);
}

#[cfg(unix)]
#[tokio::test]
async fn a_stopped_server_drops_its_trees_and_resumes_under_the_current_policy() {
    let home = tempfile::tempdir().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let envs = [
        ("KALASCAN_HOME", home.path().to_str().unwrap()),
        ("TMPDIR", tmp.path().to_str().unwrap()),
    ];
    // Stands in for an internal service: a connection means it was fetched.
    let internal = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    internal.set_nonblocking(true).unwrap();
    let target = format!(
        "http://127.0.0.1:{}/queued.vsix",
        internal.local_addr().unwrap().port()
    );
    let http = reqwest::Client::new();

    // Boot 1 allows internal targets and has no slots, so both scans queue.
    let mut first = Server::start_with(
        &[
            &envs[..],
            &[
                ("KALASCAN_ALLOW_PRIVATE_TARGETS", "1"),
                ("KALASCAN_MAX_CONCURRENT_SCANS", "0"),
            ],
        ]
        .concat(),
    )
    .await;
    let queued: serde_json::Value = http
        .post(format!("{}/api/scan", first.base))
        .json(&serde_json::json!({ "repo_url": target }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(queued["status"], "queued", "{}", queued);
    let uploaded: serde_json::Value = upload(&http, &first.base).await.json().await.unwrap();
    assert_eq!(uploaded["status"], "queued", "{}", uploaded);
    assert_eq!(entries(tmp.path()), 1, "the queued upload's tree");

    // `docker stop`: the queued upload's tree goes with the server.
    let term = std::process::Command::new("kill")
        .args(["-TERM", &first.child.id().to_string()])
        .status()
        .unwrap();
    assert!(term.success());
    for _ in 0..100 {
        if first.child.try_wait().unwrap().is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        first.child.try_wait().unwrap().is_some(),
        "server ignored SIGTERM"
    );
    assert_eq!(entries(tmp.path()), 0, "trees left behind by the stop");

    // Boot 2 no longer allows internal targets: neither scan is run.
    let second = Server::start_with(&envs).await;
    for id in [&queued["result_id"], &uploaded["result_id"]] {
        let status: serde_json::Value = http
            .get(format!(
                "{}/api/scan/{}/status",
                second.base,
                id.as_str().unwrap()
            ))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(
            status["status"]
                .as_str()
                .unwrap()
                .starts_with("failed: not resumed: "),
            "{}",
            status["status"]
        );
    }
    assert!(
        internal.accept().is_err(),
        "the internal target was fetched"
    );
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

    let report = |format: &str| http.get(url(&format!("/api/report/{}/{}", id, format)));
    let stix = report("stix").send().await.unwrap();
    assert_eq!(stix.status(), 200);
    assert_eq!(
        stix.headers()["content-type"],
        "application/stix+json;version=2.1"
    );
    let bundle: serde_json::Value = stix.json().await.unwrap();
    assert_eq!(bundle["type"], "bundle");
    // An uploaded archive is not a registry package: no OSV record.
    assert_eq!(report("osv").send().await.unwrap().status(), 422);

    let missing = http
        .get(url("/api/scan/no-such-id/status"))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
}

#[tokio::test]
async fn rebinding_host_is_refused_on_the_dashboard_page_too() {
    let server = Server::start().await;
    let port = server.base.rsplit(':').next().unwrap();
    let page = |host: String| {
        reqwest::Client::new()
            .get(format!("{}/", server.base))
            .header("host", host)
            .send()
    };
    // Without auth `/` embeds the scan history.
    let rebound = page(format!("evil.example:{}", port)).await.unwrap();
    assert_eq!(rebound.status(), 403);
    let local = page(format!("127.0.0.1:{}", port)).await.unwrap();
    assert_eq!(local.status(), 200);
}

#[tokio::test]
async fn removing_the_last_user_does_not_open_the_server() {
    let cwd = tempfile::tempdir().unwrap();
    let dir = cwd.path().to_path_buf();
    let user = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_kalascan"))
            .current_dir(&dir)
            .arg("user")
            .args(args)
            .assert()
            .success();
    };
    user(&["add", "dummy-op", "--role", "operator"]);
    let server = Server::start_in(cwd, &[("RUST_LOG", "off")]).await;
    let audit = || reqwest::get(format!("{}/api/audit", server.base));
    assert_eq!(audit().await.unwrap().status(), 401);
    // Revoking the only token: no credentials used to mean anonymous admin.
    user(&["remove", "dummy-op"]);
    assert_eq!(audit().await.unwrap().status(), 401);
}

#[tokio::test]
async fn unauthenticated_requests_cannot_flood_the_audit_log() {
    let env = [("RUST_LOG", "off"), ("KALASCAN_TOKEN", "dummy-token")];
    let server = Server::start_in(tempfile::tempdir().unwrap(), &env).await;
    let http = reqwest::Client::new();
    let long_path = format!("{}/api/results/{}", server.base, "A".repeat(2000));
    for _ in 0..40 {
        assert_eq!(http.get(&long_path).send().await.unwrap().status(), 401);
    }
    let audit: serde_json::Value = http
        .get(format!("{}/api/audit", server.base))
        .bearer_auth("dummy-token")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let denied: Vec<&str> = audit["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "auth.denied")
        .map(|e| e["detail"].as_str().unwrap())
        .collect();
    // 30 rows a minute, 512 characters each.
    assert_eq!(denied.len(), 30);
    assert!(denied.iter().all(|d| d.len() == 512), "{:?}", denied);
}

#[tokio::test]
async fn failed_download_does_not_show_the_credentials_in_its_url() {
    let env = [
        ("RUST_LOG", "kalascan=info"),
        ("KALASCAN_ALLOW_PRIVATE_TARGETS", "1"),
    ];
    let server = Server::start_in(tempfile::tempdir().unwrap(), &env).await;
    let http = reqwest::Client::new();
    // The server's own 404 stands in for the artifact host.
    let target = server.base.replace("://", "://dummy-bot:DUMMY-SECRET@") + "/dl/pkg.vsix";
    let accepted: serde_json::Value = http
        .post(format!("{}/api/scan", server.base))
        .json(&serde_json::json!({ "repo_url": target, "check_cve": false }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = accepted["result_id"].as_str().unwrap();
    let mut status = serde_json::Value::Null;
    for _ in 0..300 {
        status = http
            .get(format!("{}/api/scan/{}/status", server.base, id))
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
    let shown = status["status"].as_str().unwrap();
    assert!(shown.starts_with("failed: Failed to download"), "{}", shown);
    assert!(shown.contains("HTTP 404"), "{}", shown);
    assert!(!status.to_string().contains("DUMMY-SECRET"), "{}", status);
    let log = server.log();
    assert!(log.contains("Failed to download"), "{}", log);
    assert!(!log.contains("DUMMY-SECRET"), "{}", log);
}

#[tokio::test]
async fn line_break_in_a_scan_id_stays_inside_one_log_record() {
    let env = [("RUST_LOG", "kalascan=info")];
    let server = Server::start_in(tempfile::tempdir().unwrap(), &env).await;
    let gone = reqwest::Client::new()
        .delete(format!("{}/api/scan/x%0D%0AFORGED%20record", server.base))
        .send()
        .await
        .unwrap();
    assert_eq!(gone.status(), 404);
    let log = server.log();
    assert!(log.contains("x\\r\\nFORGED record"), "{}", log);
    assert!(!log.lines().any(|l| l.starts_with("FORGED")), "{}", log);
}
