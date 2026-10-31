//! Exact dependency versions from lockfiles, for `kalascan deps`.
//!
//! A manifest says `^4.17.0`; what CI installs is the version the lockfile
//! pins, and that is the code worth scanning. npm (`package-lock.json`
//! v1-v3), Poetry (`poetry.lock`), Pipenv (`Pipfile.lock`) and pinned
//! `requirements.txt` lines.

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Locked {
    pub ecosystem: &'static str,
    pub name: String,
    pub version: String,
    pub dev: bool,
    pub source: &'static str,
}

impl Locked {
    /// The scan target for this package (`npm:name@1.2.3`, `pypi:name==1.2.3`).
    pub fn target(&self) -> String {
        match self.ecosystem {
            "npm" => format!("npm:{}@{}", self.name, self.version),
            _ => format!("pypi:{}=={}", self.name, self.version),
        }
    }
}

/// Every locked package under `root`, deduplicated. Names that are not valid
/// registry names (the lockfile is someone else's input) are dropped.
pub fn read(root: &Path, include_dev: bool) -> Vec<Locked> {
    let mut found: Vec<Locked> = Vec::new();
    let text = |f: &str| std::fs::read_to_string(root.join(f)).ok();
    if let Some(t) = text("package-lock.json") {
        found.extend(package_lock(&t));
    }
    if let Some(t) = text("poetry.lock") {
        found.extend(poetry_lock(&t));
    }
    if let Some(t) = text("Pipfile.lock") {
        found.extend(pipfile_lock(&t));
    }
    if let Some(t) = text("requirements.txt") {
        found.extend(requirements(&t));
    }
    let mut seen = BTreeSet::new();
    found
        .into_iter()
        .filter(|p| include_dev || !p.dev)
        .filter(|p| crate::vsix::parse_package_target(&p.target()).is_some())
        .filter(|p| seen.insert((p.ecosystem, p.name.clone(), p.version.clone())))
        .collect()
}

fn package_lock(text: &str) -> Vec<Locked> {
    let Ok(doc) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let lock = |name: &str, entry: &Value| -> Option<Locked> {
        // Links and git/file dependencies are not registry packages.
        if entry["link"].as_bool() == Some(true) {
            return None;
        }
        if let Some(r) = entry["resolved"].as_str() {
            if !r.starts_with("https://registry.npmjs.org/") {
                return None;
            }
        }
        Some(Locked {
            ecosystem: "npm",
            name: name.to_string(),
            version: entry["version"].as_str()?.to_string(),
            dev: entry["dev"].as_bool().unwrap_or(false)
                || entry["devOptional"].as_bool().unwrap_or(false),
            source: "package-lock.json",
        })
    };
    // v2/v3: flat "packages" keyed by install path.
    if let Some(packages) = doc["packages"].as_object() {
        return packages
            .iter()
            .filter_map(|(path, entry)| {
                let name = path.rsplit_once("node_modules/")?.1;
                lock(name, entry)
            })
            .collect();
    }
    // v1: nested "dependencies".
    fn walk(deps: &Value, out: &mut Vec<(String, Value)>) {
        for (name, entry) in deps.as_object().into_iter().flatten() {
            out.push((name.clone(), entry.clone()));
            walk(&entry["dependencies"], out);
        }
    }
    let mut flat = Vec::new();
    walk(&doc["dependencies"], &mut flat);
    flat.iter().filter_map(|(n, e)| lock(n, e)).collect()
}

fn poetry_lock(text: &str) -> Vec<Locked> {
    let Ok(doc) = toml::from_str::<toml::Value>(text) else {
        return Vec::new();
    };
    doc.get("package")
        .and_then(|p| p.as_array())
        .into_iter()
        .flatten()
        .filter_map(|p| {
            // Only registry packages: git, file and url sources have a `source.type`.
            if p.get("source").and_then(|s| s.get("type")).is_some() {
                return None;
            }
            Some(Locked {
                ecosystem: "pypi",
                name: p.get("name")?.as_str()?.to_string(),
                version: p.get("version")?.as_str()?.to_string(),
                dev: p.get("category").and_then(|c| c.as_str()) == Some("dev"),
                source: "poetry.lock",
            })
        })
        .collect()
}

fn pipfile_lock(text: &str) -> Vec<Locked> {
    let Ok(doc) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    [("default", false), ("develop", true)]
        .iter()
        .flat_map(|(section, dev)| {
            doc[*section]
                .as_object()
                .into_iter()
                .flatten()
                .filter_map(move |(name, entry)| {
                    let version = entry["version"].as_str()?.strip_prefix("==")?;
                    Some(Locked {
                        ecosystem: "pypi",
                        name: name.clone(),
                        version: version.to_string(),
                        dev: *dev,
                        source: "Pipfile.lock",
                    })
                })
        })
        .collect()
}

/// Pinned `name==version` lines only; ranges have no single version to scan.
fn requirements(text: &str) -> Vec<Locked> {
    text.lines()
        .filter_map(|line| {
            let line = line.split('#').next()?.trim();
            let (name, rest) = line.split_once("==")?;
            let version = rest.split([';', ' ', '\\']).next()?.trim();
            let name = name.split('[').next()?.trim();
            (!name.is_empty() && !version.is_empty()).then(|| Locked {
                ecosystem: "pypi",
                name: name.to_string(),
                version: version.to_string(),
                dev: false,
                source: "requirements.txt",
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn targets(v: &[Locked]) -> Vec<String> {
        v.iter().map(Locked::target).collect()
    }

    #[test]
    fn package_lock_v3_and_v1() {
        let v3 = r#"{"lockfileVersion": 3, "packages": {
            "": {"name": "app"},
            "node_modules/lodash": {"version": "4.17.21", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"},
            "node_modules/@scope/x": {"version": "1.0.0"},
            "node_modules/a/node_modules/b": {"version": "2.0.0", "dev": true},
            "node_modules/local": {"version": "0.0.0", "link": true},
            "node_modules/fromgit": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/x/y.git"}
        }}"#;
        let got = package_lock(v3);
        assert_eq!(
            targets(&got),
            vec!["npm:lodash@4.17.21", "npm:@scope/x@1.0.0", "npm:b@2.0.0"]
        );
        assert!(got[2].dev);
        let v1 = r#"{"lockfileVersion": 1, "dependencies": {
            "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}}}"#;
        assert_eq!(
            targets(&package_lock(v1)),
            vec!["npm:a@1.0.0", "npm:b@2.0.0"]
        );
    }

    #[test]
    fn python_locks() {
        let poetry = "[[package]]\nname = \"requests\"\nversion = \"2.32.3\"\n\n\
                      [[package]]\nname = \"mine\"\nversion = \"0.1.0\"\n[package.source]\ntype = \"git\"\nurl = \"x\"\n";
        assert_eq!(targets(&poetry_lock(poetry)), vec!["pypi:requests==2.32.3"]);
        let pipfile = r#"{"default": {"flask": {"version": "==3.1.0"}}, "develop": {"pytest": {"version": "==8.0.0"}}}"#;
        let got = pipfile_lock(pipfile);
        assert_eq!(
            targets(&got),
            vec!["pypi:flask==3.1.0", "pypi:pytest==8.0.0"]
        );
        assert!(got[1].dev);
        let req = "requests==2.31.0 ; python_version >= '3.8'\nflask>=2\nuvicorn[standard]==0.30.0 \\\n  --hash=sha256:x\n# c==1\n";
        assert_eq!(
            targets(&requirements(req)),
            vec!["pypi:requests==2.31.0", "pypi:uvicorn==0.30.0"]
        );
    }

    #[test]
    fn read_dedups_skips_dev_and_bad_names() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package-lock.json"),
            r#"{"packages": {"node_modules/a": {"version": "1.0.0"}, "node_modules/x/node_modules/a": {"version": "1.0.0"},
                "node_modules/d": {"version": "1.0.0", "dev": true}, "node_modules/bad name": {"version": "1.0.0"}}}"#,
        )
        .unwrap();
        assert_eq!(targets(&read(dir.path(), false)), vec!["npm:a@1.0.0"]);
        assert_eq!(read(dir.path(), true).len(), 2);
    }
}
