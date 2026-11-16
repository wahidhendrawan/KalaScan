//! Exact dependency versions from lockfiles, for `kalascan deps`.
//!
//! A manifest says `^4.17.0`; what CI installs is the version the lockfile
//! pins, and that is the code worth scanning. npm (`package-lock.json`
//! v1-v3), Yarn (`yarn.lock`, classic and Berry), pnpm (`pnpm-lock.yaml`),
//! Poetry (`poetry.lock`), Pipenv (`Pipfile.lock`), uv (`uv.lock`), pinned
//! `requirements.txt` lines and Cargo (`Cargo.lock`).

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
    /// The scan target for this package (`npm:name@1.2.3`,
    /// `pypi:name==1.2.3`, `crates:name@1.2.3`).
    pub fn target(&self) -> String {
        match self.ecosystem {
            "npm" => format!("npm:{}@{}", self.name, self.version),
            "crates" => format!("crates:{}@{}", self.name, self.version),
            _ => format!("pypi:{}=={}", self.name, self.version),
        }
    }
}

/// The lockfiles `read` looks for.
pub const LOCKFILES: [&str; 8] = [
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
    "uv.lock",
    "requirements.txt",
    "Cargo.lock",
];

/// The packages one lockfile pins, by its file name. Unknown names and
/// unparsable text yield nothing.
pub fn parse(file_name: &str, text: &str) -> Vec<Locked> {
    match file_name {
        "package-lock.json" => package_lock(text),
        "yarn.lock" => yarn_lock(text),
        "pnpm-lock.yaml" => pnpm_lock(text),
        "poetry.lock" => poetry_lock(text),
        "Pipfile.lock" => pipfile_lock(text),
        "uv.lock" => registry_toml_lock(text, "pypi", "uv.lock"),
        "requirements.txt" => requirements(text),
        "Cargo.lock" => registry_toml_lock(text, "crates", "Cargo.lock"),
        _ => Vec::new(),
    }
}

/// Every locked package under `root`, deduplicated. Names that are not valid
/// registry names (the lockfile is someone else's input) are dropped.
pub fn read(root: &Path, include_dev: bool) -> Vec<Locked> {
    let found: Vec<Locked> = LOCKFILES
        .iter()
        .filter_map(|name| Some(parse(name, &std::fs::read_to_string(root.join(name)).ok()?)))
        .flatten()
        .collect();
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

/// `name@version` with the `@` that is not the scope's.
fn split_at_version(spec: &str) -> Option<(&str, &str)> {
    let i = spec.rfind('@').filter(|&i| i > 0)?;
    Some((&spec[..i], &spec[i + 1..]))
}

/// yarn.lock, classic (`version "1.0.0"`) and Berry (`version: 1.0.0`). Read
/// line by line: both are a flat list of `header:` blocks with indented
/// fields. The file does not say which packages are dev-only.
fn yarn_lock(text: &str) -> Vec<Locked> {
    let mut out = Vec::new();
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut registry = true;
    let mut flush = |name: &mut Option<String>, version: &mut Option<String>, registry: bool| {
        if let (Some(name), Some(version), true) = (name.take(), version.take(), registry) {
            out.push(Locked {
                ecosystem: "npm",
                name,
                version,
                dev: false,
                source: "yarn.lock",
            });
        }
    };
    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') {
            flush(&mut name, &mut version, registry);
            registry = true;
            // `"@scope/x@^1.0.0", "@scope/x@npm:^1.2.0":`: the name is the
            // same in every spec. `__metadata:` has no `@` and is skipped.
            let spec = line.split(',').next().unwrap_or_default();
            let spec = spec.trim_end_matches(':').trim_matches('"');
            name = split_at_version(spec).map(|(n, _)| n.to_string());
            continue;
        }
        // Fields sit at two spaces; deeper lines list dependencies, and one
        // of those may itself be called `version`.
        let Some(field) = line.strip_prefix("  ").filter(|f| !f.starts_with(' ')) else {
            continue;
        };
        let value = |key: &str| {
            let rest = field.strip_prefix(key)?;
            let rest = rest.strip_prefix(':').unwrap_or(rest);
            rest.starts_with(' ').then(|| rest.trim().trim_matches('"'))
        };
        if let Some(v) = value("version") {
            version = Some(v.to_string());
        } else if let Some(url) = value("resolved") {
            // Classic: git and tarball dependencies resolve elsewhere.
            registry = url.starts_with("https://registry.yarnpkg.com/")
                || url.starts_with("https://registry.npmjs.org/");
        } else if let Some(r) = value("resolution") {
            // Berry: `name@npm:1.0.0`; workspace:, patch:, git and file are not registry packages.
            registry = split_at_version(r).is_some_and(|(_, v)| v.starts_with("npm:"));
        }
    }
    flush(&mut name, &mut version, registry);
    out
}

/// pnpm-lock.yaml: the keys of the top-level `packages:` map, read line by
/// line (no YAML parser in the tree). v5 `/name/1.0.0_peers`, v6
/// `/name@1.0.0(peers)`, v9 `name@1.0.0`. Git and tarball keys carry a URL
/// where the version goes and are dropped by `read`'s name check.
fn pnpm_lock(text: &str) -> Vec<Locked> {
    let mut out: Vec<Locked> = Vec::new();
    let mut in_packages = false;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') {
            in_packages = line.trim_end() == "packages:";
            continue;
        }
        if !in_packages {
            continue;
        }
        if line.trim() == "dev: true" {
            if let Some(last) = out.last_mut() {
                last.dev = true;
            }
            continue;
        }
        // Package keys sit at exactly two spaces; their fields are deeper.
        let Some(key) = line.strip_prefix("  ").filter(|k| !k.starts_with(' ')) else {
            continue;
        };
        let Some(key) = key.trim_end().strip_suffix(':') else {
            continue;
        };
        let key = key.trim_matches(['\'', '"']);
        let key = key.split('(').next().unwrap_or_default();
        let key = key.strip_prefix('/').unwrap_or(key);
        // v5 ends in `/<version>[_peers]`; in v6 and v9 the version follows an `@`.
        let v5 = key.rsplit_once('/').and_then(|(name, rest)| {
            let version = rest.split('_').next()?;
            (version.starts_with(|c: char| c.is_ascii_digit()) && !version.contains('@'))
                .then_some((name, version))
        });
        let parsed = v5.or_else(|| split_at_version(key));
        // An unreadable key still starts a new entry: its `dev: true` must
        // not land on the package before it.
        let (name, version) = parsed.unwrap_or_default();
        out.push(Locked {
            ecosystem: "npm",
            name: name.to_string(),
            version: version.to_string(),
            dev: false,
            source: "pnpm-lock.yaml",
        });
    }
    out
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

/// uv.lock and Cargo.lock: `[[package]]` tables whose `source` names a
/// registry (`{ registry = "https://pypi.org/simple" }`,
/// `"registry+https://github.com/rust-lang/crates.io-index"`). Workspace
/// members, path, git and editable packages have another source or none.
/// Neither file marks dev-only packages.
fn registry_toml_lock(text: &str, ecosystem: &'static str, source: &'static str) -> Vec<Locked> {
    let Ok(doc) = toml::from_str::<toml::Value>(text) else {
        return Vec::new();
    };
    doc.get("package")
        .and_then(|p| p.as_array())
        .into_iter()
        .flatten()
        .filter_map(|p| {
            let from_registry = match p.get("source")? {
                toml::Value::String(s) => s.starts_with("registry+"),
                table => table.get("registry").is_some(),
            };
            from_registry.then_some(())?;
            Some(Locked {
                ecosystem,
                name: p.get("name")?.as_str()?.to_string(),
                version: p.get("version")?.as_str()?.to_string(),
                dev: false,
                source,
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
    fn yarn_lock_classic_and_berry() {
        let classic = r#"# yarn lockfile v1

"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.8.3":
  version "7.12.11"
  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.12.11.tgz#f4ad"
  dependencies:
    "@babel/highlight" "^7.10.4"

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#679591"

"fromgit@https://github.com/x/y.git":
  version "1.0.0"
  resolved "https://github.com/x/y.git#abc"
"#;
        assert_eq!(
            targets(&yarn_lock(classic)),
            vec!["npm:@babel/code-frame@7.12.11", "npm:lodash@4.17.21"]
        );
        let berry = r#"__metadata:
  version: 8
  cacheKey: 10

"@types/node@npm:^20.0.0":
  version: 20.11.5
  resolution: "@types/node@npm:20.11.5"
  dependencies:
    undici-types: "npm:~5.26.4"
  checksum: 10/abc
  languageName: node
  linkType: hard

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."

"left-pad@patch:left-pad@npm%3A1.3.0#./p.patch":
  version: 1.3.0
  resolution: "left-pad@patch:left-pad@npm%3A1.3.0#./p.patch::version=1.3.0"
"#;
        assert_eq!(targets(&yarn_lock(berry)), vec!["npm:@types/node@20.11.5"]);
    }

    #[test]
    fn pnpm_lock_v5_v6_v9() {
        let v9 = r#"lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21

packages:

  '@babel/core@7.24.0':
    resolution: {integrity: sha512-x}
    engines: {node: '>=6.9.0'}

  lodash@4.17.21:
    resolution: {integrity: sha512-y}

  fromgit@https://codeload.github.com/x/y/tar.gz/abc:
    resolution: {tarball: https://codeload.github.com/x/y/tar.gz/abc}

snapshots:

  '@babel/core@7.24.0(supports-color@8.1.1)':
    dependencies:
      debug: 4.3.4
"#;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pnpm-lock.yaml"), v9).unwrap();
        assert_eq!(
            targets(&read(dir.path(), false)),
            vec!["npm:@babel/core@7.24.0", "npm:lodash@4.17.21"]
        );
        let v6 = "packages:\n\n  /@babel/core@7.24.0(supports-color@8.1.1):\n    resolution: {integrity: x}\n    dev: false\n\n  /mocha@10.2.0:\n    resolution: {integrity: x}\n    dev: true\n";
        let got = pnpm_lock(v6);
        assert_eq!(
            targets(&got),
            vec!["npm:@babel/core@7.24.0", "npm:mocha@10.2.0"]
        );
        assert!(!got[0].dev && got[1].dev);
        let v5 = "packages:\n\n  /@scope/x/1.0.0:\n    dev: false\n\n  /react-dom/18.2.0_react@18.2.0:\n    dev: false\n";
        assert_eq!(
            targets(&pnpm_lock(v5)),
            vec!["npm:@scope/x@1.0.0", "npm:react-dom@18.2.0"]
        );
    }

    #[test]
    fn uv_and_cargo_locks_keep_registry_packages() {
        let uv = r#"version = 1

[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }

[[package]]
name = "requests"
version = "2.32.3"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "fromgit"
version = "1.0.0"
source = { git = "https://github.com/x/y?rev=abc#abc" }
"#;
        assert_eq!(
            targets(&registry_toml_lock(uv, "pypi", "uv.lock")),
            vec!["pypi:requests==2.32.3"]
        );
        let cargo = r#"version = 4

[[package]]
name = "app"
version = "0.1.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.203"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"

[[package]]
name = "fromgit"
version = "0.1.0"
source = "git+https://github.com/x/y#abc"
"#;
        assert_eq!(
            targets(&registry_toml_lock(cargo, "crates", "Cargo.lock")),
            vec!["crates:serde@1.0.203"]
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
