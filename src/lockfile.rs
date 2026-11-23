//! Exact dependency versions from lockfiles, for `kalascan deps`.
//!
//! A manifest says `^4.17.0`; what CI installs is the version the lockfile
//! pins, and that is the code worth scanning. npm (`package-lock.json`
//! v1-v3 and `npm-shrinkwrap.json`, the same format), Yarn (`yarn.lock`,
//! classic and Berry), pnpm (`pnpm-lock.yaml`),
//! Poetry (`poetry.lock`), Pipenv (`Pipfile.lock`), uv (`uv.lock`), pinned
//! `requirements.txt` lines and Cargo (`Cargo.lock`).
//!
//! Only the public registries are scanned. An entry that comes from somewhere
//! else is kept with the reason in `Locked::skipped`, so a caller can refuse
//! to call the lockfile clean.

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
    /// Why this entry is not scanned, `None` for a package that is. `lodash`
    /// resolved from an Artifactory mirror is not the npmjs package of that
    /// name: scanning that one would report on other code.
    pub skipped: Option<&'static str>,
}

/// A mirror (Artifactory, Verdaccio), a private index, git, a URL or a tarball.
const NOT_PUBLIC: &str = "not from the public registry";
/// `flask>=2`: a range has no single version to scan.
const NOT_PINNED: &str = "no pinned version";
/// `github:x/y#abc` where the version goes: names and versions go into
/// registry URLs.
const NOT_A_NAME: &str = "not a registry name or version";

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
pub const LOCKFILES: [&str; 9] = [
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
    "uv.lock",
    "requirements.txt",
    "Cargo.lock",
];

/// The entries of one lockfile, by its file name, those with a `skipped`
/// reason included. Unknown names and unparsable text yield nothing.
pub fn parse(file_name: &str, text: &str) -> Vec<Locked> {
    match file_name {
        "package-lock.json" => package_lock(text),
        // The same format, under the name npm also publishes.
        "npm-shrinkwrap.json" => package_lock(text)
            .into_iter()
            .map(|p| Locked {
                source: "npm-shrinkwrap.json",
                ..p
            })
            .collect(),
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

/// Every locked package under `root`, deduplicated, and the entries that are
/// not scanned (`Locked::skipped` says why). An entry whose name or version
/// is not a valid registry one (the lockfile is someone else's input) is
/// skipped too.
pub fn read(root: &Path, include_dev: bool) -> (Vec<Locked>, Vec<Locked>) {
    read_with(include_dev, |name| {
        std::fs::read_to_string(root.join(name)).ok()
    })
}

/// `read`, with `text_of` giving a lockfile's text by its name: a scan reads
/// the lockfiles of someone else's tree the way it reads the manifests
/// (`cve::read_manifest`).
pub fn read_with(
    include_dev: bool,
    text_of: impl Fn(&str) -> Option<String>,
) -> (Vec<Locked>, Vec<Locked>) {
    let found: Vec<Locked> = LOCKFILES
        .iter()
        .filter_map(|name| Some(parse(name, &text_of(name)?)))
        .flatten()
        .collect();
    let mut seen = BTreeSet::new();
    found
        .into_iter()
        .filter(|p| include_dev || !p.dev)
        .map(|mut p| {
            if p.skipped.is_none() && crate::vsix::parse_package_target(&p.target()).is_none() {
                p.skipped = Some(NOT_A_NAME);
            }
            p
        })
        .filter(|p| seen.insert((p.ecosystem, p.name.clone(), p.version.clone(), p.skipped)))
        .partition(|p| p.skipped.is_none())
}

/// The (ecosystem, name, version) triples the lockfiles under `root` pinned
/// at `git_ref`: what a pull request's base already installs. A lockfile the
/// ref does not have pins nothing; a ref git does not know is an error.
pub fn pinned_at(
    root: &Path,
    git_ref: &str,
) -> anyhow::Result<BTreeSet<(&'static str, String, String)>> {
    // `git show <ref>:…` would read a ref like `--output=x` as an option.
    if git_ref.starts_with('-') {
        anyhow::bail!("invalid git ref: {git_ref}");
    }
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
    };
    if !git(&[
        "rev-parse",
        "--verify",
        "--quiet",
        &format!("{git_ref}^{{commit}}"),
    ])?
    .status
    .success()
    {
        anyhow::bail!(
            "git ref {git_ref} not found in {} (fetch it, e.g. fetch-depth: 0)",
            root.display()
        );
    }
    let mut pinned = BTreeSet::new();
    for name in LOCKFILES {
        let out = git(&["show", &format!("{git_ref}:./{name}")])?;
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            pinned.extend(
                parse(name, &text)
                    .into_iter()
                    .map(|p| (p.ecosystem, p.name, p.version)),
            );
        }
    }
    Ok(pinned)
}

fn package_lock(text: &str) -> Vec<Locked> {
    let Ok(doc) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let lock = |name: &str, entry: &Value| -> Option<Locked> {
        // A link is a directory of the project itself, not a download.
        if entry["link"].as_bool() == Some(true) {
            return None;
        }
        let elsewhere = entry["resolved"]
            .as_str()
            .is_some_and(|r| !r.starts_with("https://registry.npmjs.org/"));
        Some(Locked {
            ecosystem: "npm",
            name: name.to_string(),
            version: entry["version"].as_str()?.to_string(),
            dev: entry["dev"].as_bool().unwrap_or(false)
                || entry["devOptional"].as_bool().unwrap_or(false),
            source: "package-lock.json",
            skipped: elsewhere.then_some(NOT_PUBLIC),
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
    let mut skipped = None;
    let mut local = false;
    let mut flush = |name: &mut Option<String>, version: &mut Option<String>, skipped, local| {
        if let (Some(name), Some(version), false) = (name.take(), version.take(), local) {
            out.push(Locked {
                ecosystem: "npm",
                name,
                version,
                dev: false,
                source: "yarn.lock",
                skipped,
            });
        }
    };
    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') {
            flush(&mut name, &mut version, skipped, local);
            (skipped, local) = (None, false);
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
            // Classic: a mirror, git and tarball dependencies resolve elsewhere.
            let registry = url.starts_with("https://registry.yarnpkg.com/")
                || url.starts_with("https://registry.npmjs.org/");
            skipped = (!registry).then_some(NOT_PUBLIC);
        } else if let Some(r) = value("resolution") {
            // Berry: `name@npm:1.0.0`. The protocol follows the first `@`
            // past a scope's: a patch repeats `left-pad@npm%3A1.3.0` after
            // its own. workspace:, link:, portal: and patch: are the
            // project's own files (the patched package has its own entry);
            // git, URLs and tarballs resolve elsewhere.
            let protocol = r.get(1..).and_then(|s| s.split_once('@'));
            let protocol = protocol.map_or("", |(_, p)| p);
            local = ["workspace:", "link:", "portal:", "patch:"]
                .iter()
                .any(|own| protocol.starts_with(own));
            skipped = (!protocol.starts_with("npm:")).then_some(NOT_PUBLIC);
        }
    }
    flush(&mut name, &mut version, skipped, local);
    out
}

/// pnpm-lock.yaml: the keys of the top-level `packages:` map, read line by
/// line (no YAML parser in the tree). v5 `/name/1.0.0_peers`, v6
/// `/name@1.0.0(peers)`, v9 `name@1.0.0`. Git and tarball keys carry a URL
/// where the version goes and are skipped by `read`'s name check.
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
        let (name, version) = parsed.unwrap_or((key, ""));
        out.push(Locked {
            ecosystem: "npm",
            name: name.to_string(),
            version: version.to_string(),
            dev: false,
            source: "pnpm-lock.yaml",
            skipped: None,
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
            // Only PyPI packages have no `source.type`: git, file, url and a
            // private index (`legacy`) are skipped, `directory` is the
            // project's own.
            let source = p.get("source").and_then(|s| s.get("type"));
            if source.and_then(|t| t.as_str()) == Some("directory") {
                return None;
            }
            Some(Locked {
                ecosystem: "pypi",
                name: p.get("name")?.as_str()?.to_string(),
                version: p.get("version")?.as_str()?.to_string(),
                dev: p.get("category").and_then(|c| c.as_str()) == Some("dev"),
                source: "poetry.lock",
                skipped: source.map(|_| NOT_PUBLIC),
            })
        })
        .collect()
}

/// uv.lock and Cargo.lock: `[[package]]` tables whose `source` names a
/// registry (`{ registry = "https://pypi.org/simple" }`,
/// `"registry+https://github.com/rust-lang/crates.io-index"`). Workspace
/// members and path packages have no source, or a `virtual`, `editable` or
/// `directory` one: the project's own. Git, URL and file sources are skipped.
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
                table => {
                    let own = ["virtual", "editable", "directory"];
                    if own.iter().any(|kind| table.get(kind).is_some()) {
                        return None;
                    }
                    table.get("registry").is_some()
                }
            };
            Some(Locked {
                ecosystem,
                name: p.get("name")?.as_str()?.to_string(),
                version: p.get("version")?.as_str()?.to_string(),
                dev: false,
                source,
                skipped: (!from_registry).then_some(NOT_PUBLIC),
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
                    // PyPI packages pin `==1.2.3`. A git or file entry has
                    // no such version; one with a `path` is the project's own.
                    let version = entry["version"].as_str().and_then(|v| v.strip_prefix("=="));
                    if version.is_none() && !entry["path"].is_null() {
                        return None;
                    }
                    Some(Locked {
                        ecosystem: "pypi",
                        name: name.clone(),
                        version: version.unwrap_or_default().to_string(),
                        dev: *dev,
                        source: "Pipfile.lock",
                        skipped: version.is_none().then_some(NOT_PUBLIC),
                    })
                })
        })
        .collect()
}

/// Pinned `name==version` lines; a range (`flask>=2`) has no single version
/// to scan and is skipped.
/// shortcut: option lines are not entries, so what `-r other.txt` includes
/// or `--index-url` redirects is not seen; read them when that matters.
fn requirements(text: &str) -> Vec<Locked> {
    text.lines()
        .filter_map(|line| {
            let line = line.split('#').next()?.trim();
            // `--hash=sha256:…` continues the line before it.
            if line.is_empty() || line.starts_with('-') {
                return None;
            }
            let pinned = line.split_once("==").and_then(|(name, rest)| {
                let version = rest.split([';', ' ', '\\']).next()?.trim();
                let name = name.split('[').next()?.trim();
                (!name.is_empty() && !version.is_empty()).then_some((name, version))
            });
            // `flask>=2`, `x @ https://…`: the name ends where the specifier starts.
            let name_only = || Some((line.split(|c| "=<>!~[;@ ".contains(c)).next()?, ""));
            let (name, version) = pinned.or_else(name_only)?;
            Some(Locked {
                ecosystem: "pypi",
                name: name.to_string(),
                version: version.to_string(),
                dev: false,
                source: "requirements.txt",
                skipped: pinned.is_none().then_some(NOT_PINNED),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_at_reads_the_lockfiles_of_a_ref() {
        let dir = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            let ok = std::process::Command::new("git")
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
                ok.status.success(),
                "{}",
                String::from_utf8_lossy(&ok.stderr)
            );
        };
        git(&["init", "-q"]);
        std::fs::write(dir.path().join("requirements.txt"), "requests==2.31.0\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-qm", "base"]);
        std::fs::write(
            dir.path().join("requirements.txt"),
            "requests==2.31.0\nflask==3.0.0\n",
        )
        .unwrap();
        let before = pinned_at(dir.path(), "HEAD").unwrap();
        let (now, _) = read(dir.path(), true);
        let new: Vec<_> = now
            .iter()
            .filter(|p| !before.contains(&(p.ecosystem, p.name.clone(), p.version.clone())))
            .map(|p| p.target())
            .collect();
        assert_eq!(new, ["pypi:flask==3.0.0"]);
        assert!(pinned_at(dir.path(), "no-such-ref").is_err());
        assert!(pinned_at(dir.path(), "--output=x").is_err());
    }

    /// The packages that are scanned.
    fn targets(v: &[Locked]) -> Vec<String> {
        let scanned = v.iter().filter(|p| p.skipped.is_none());
        scanned.map(Locked::target).collect()
    }

    /// The entries that are not, each with its reason.
    fn skipped(v: &[Locked]) -> Vec<(&str, &str)> {
        v.iter()
            .filter_map(|p| Some((p.name.as_str(), p.skipped?)))
            .collect()
    }

    #[test]
    fn read_reports_what_it_skips_and_why() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package-lock.json"),
            r#"{"lockfileVersion": 3, "packages": {
            "node_modules/lodash": {"version": "4.17.21", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"},
            "node_modules/internal": {"version": "1.0.0", "resolved": "https://artifactory.example.com/api/npm/npm/internal/-/internal-1.0.0.tgz"},
            "node_modules/tool": {"version": "2.0.0", "dev": true, "resolved": "https://verdaccio.example.com/tool/-/tool-2.0.0.tgz"}
        }}"#,
        )
        .unwrap();
        let (packages, not_scanned) = read(dir.path(), false);
        assert_eq!(targets(&packages), vec!["npm:lodash@4.17.21"]);
        assert_eq!(not_scanned.len(), 1);
        assert_eq!(not_scanned[0].target(), "npm:internal@1.0.0");
        assert_eq!(not_scanned[0].source, "package-lock.json");
        assert_eq!(not_scanned[0].skipped, Some(NOT_PUBLIC));
        // A skipped development dependency counts only with --include-dev.
        assert_eq!(read(dir.path(), true).1.len(), 2);
        // npm-shrinkwrap.json is the same format under another name.
        std::fs::rename(
            dir.path().join("package-lock.json"),
            dir.path().join("npm-shrinkwrap.json"),
        )
        .unwrap();
        let (packages, not_scanned) = read(dir.path(), false);
        assert_eq!(targets(&packages), vec!["npm:lodash@4.17.21"]);
        assert_eq!(not_scanned[0].source, "npm-shrinkwrap.json");
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
        // The workspace link is the project's own; the git dependency is not.
        assert_eq!(skipped(&got), vec![("fromgit", NOT_PUBLIC)]);
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
        assert_eq!(skipped(&yarn_lock(classic)), vec![("fromgit", NOT_PUBLIC)]);
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

"fromgit@https://github.com/x/y.git":
  version: 1.0.0
  resolution: "fromgit@https://github.com/x/y.git#commit=abc"
"#;
        assert_eq!(targets(&yarn_lock(berry)), vec!["npm:@types/node@20.11.5"]);
        // The workspace and the patch are the project's own files.
        assert_eq!(skipped(&yarn_lock(berry)), vec![("fromgit", NOT_PUBLIC)]);
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
        let (packages, not_scanned) = read(dir.path(), false);
        assert_eq!(
            targets(&packages),
            vec!["npm:@babel/core@7.24.0", "npm:lodash@4.17.21"]
        );
        assert_eq!(skipped(&not_scanned), vec![("fromgit", NOT_A_NAME)]);
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
        let got = registry_toml_lock(uv, "pypi", "uv.lock");
        assert_eq!(targets(&got), vec!["pypi:requests==2.32.3"]);
        assert_eq!(skipped(&got), vec![("fromgit", NOT_PUBLIC)]);
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
        let got = registry_toml_lock(cargo, "crates", "Cargo.lock");
        assert_eq!(targets(&got), vec!["crates:serde@1.0.203"]);
        assert_eq!(skipped(&got), vec![("fromgit", NOT_PUBLIC)]);
    }

    #[test]
    fn python_locks() {
        let poetry = "[[package]]\nname = \"requests\"\nversion = \"2.32.3\"\n\n\
                      [[package]]\nname = \"mine\"\nversion = \"0.1.0\"\n[package.source]\ntype = \"git\"\nurl = \"x\"\n";
        assert_eq!(targets(&poetry_lock(poetry)), vec!["pypi:requests==2.32.3"]);
        assert_eq!(skipped(&poetry_lock(poetry)), vec![("mine", NOT_PUBLIC)]);
        let pipfile = r#"{"default": {"flask": {"version": "==3.1.0"}, "app": {"editable": true, "path": "."},
            "fromgit": {"git": "https://github.com/x/y.git", "ref": "abc"}}, "develop": {"pytest": {"version": "==8.0.0"}}}"#;
        let got = pipfile_lock(pipfile);
        assert_eq!(
            targets(&got),
            vec!["pypi:flask==3.1.0", "pypi:pytest==8.0.0"]
        );
        assert!(got.last().unwrap().dev);
        assert_eq!(skipped(&got), vec![("fromgit", NOT_PUBLIC)]);
        let req = "requests==2.31.0 ; python_version >= '3.8'\nflask>=2\nuvicorn[standard]==0.30.0 \\\n  --hash=sha256:x\n# c==1\n";
        let got = requirements(req);
        assert_eq!(
            targets(&got),
            vec!["pypi:requests==2.31.0", "pypi:uvicorn==0.30.0"]
        );
        assert_eq!(skipped(&got), vec![("flask", NOT_PINNED)]);
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
        let (packages, not_scanned) = read(dir.path(), false);
        assert_eq!(targets(&packages), vec!["npm:a@1.0.0"]);
        assert_eq!(skipped(&not_scanned), vec![("bad name", NOT_A_NAME)]);
        assert_eq!(read(dir.path(), true).0.len(), 2);
    }
}
