//! The detection fingerprint: one hash over the files that decide a verdict,
//! the rule files in `rules/` and the detection modules the CI `ruleset` job
//! watches (CONTRIBUTING.md, "Ruleset versions"). `kalascan rules` prints it
//! and `eval/run_eval.py --summary` records it, so a result file names the
//! code that produced it even where `RULESET_VERSION` was not raised.

const MODULES: &[&str] = &[
    "scanner",
    "correlate",
    "score",
    "obfuscator",
    "registry",
    "reputation",
    "agent",
    "dataflow",
    "deobfuscate",
    "entropy",
    "iocs",
    "triage",
    "cve",
    "yara_engine",
    "zipslip",
];

/// Every rule file under `dir`, sorted; the generator scripts are not rules.
fn rule_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            rule_files(&path, out);
        } else if path.extension().is_none_or(|e| e != "py") {
            out.push(path);
        }
    }
}

fn main() {
    let mut files: Vec<std::path::PathBuf> = MODULES
        .iter()
        .map(|m| format!("src/{m}.rs").into())
        .collect();
    rule_files(std::path::Path::new("rules"), &mut files);
    println!("cargo:rerun-if-changed=rules");
    // FNV-1a, 64 bit. `\r` is skipped so a CRLF checkout hashes the same.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for file in &files {
        println!("cargo:rerun-if-changed={}", file.display());
        for byte in std::fs::read(file).unwrap_or_default() {
            if byte != b'\r' {
                hash = (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
    }
    println!("cargo:rustc-env=KALASCAN_DETECTION={hash:016x}");
}
