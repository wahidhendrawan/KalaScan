//! Find IDE and browser extensions installed on this machine, so
//! `kalascan installed` can audit a developer laptop in one command.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub struct Installed {
    pub app: &'static str,
    pub name: String,
    pub path: PathBuf,
}

/// VS Code-family editors keep one folder per extension version.
const EDITORS: &[(&str, &str)] = &[
    ("VS Code", ".vscode/extensions"),
    ("VS Code Insiders", ".vscode-insiders/extensions"),
    ("VSCodium", ".vscode-oss/extensions"),
    ("Cursor", ".cursor/extensions"),
    ("Windsurf", ".windsurf/extensions"),
];

/// Chromium profiles: `<root>/<profile>/Extensions/<id>/<version>/`.
fn browser_roots(home: &Path) -> Vec<(&'static str, PathBuf)> {
    let (mac, linux) = (
        home.join("Library/Application Support"),
        home.join(".config"),
    );
    let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    let mut roots = vec![
        ("Chrome", mac.join("Google/Chrome")),
        ("Edge", mac.join("Microsoft Edge")),
        ("Brave", mac.join("BraveSoftware/Brave-Browser")),
        ("Chrome", linux.join("google-chrome")),
        ("Chromium", linux.join("chromium")),
        ("Edge", linux.join("microsoft-edge")),
        ("Brave", linux.join("BraveSoftware/Brave-Browser")),
    ];
    if let Some(local) = local {
        roots.push(("Chrome", local.join("Google/Chrome/User Data")));
        roots.push(("Edge", local.join("Microsoft/Edge/User Data")));
        roots.push(("Brave", local.join("BraveSoftware/Brave-Browser/User Data")));
    }
    roots
}

fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        // Never follow symlinks out of the extension folder.
        .filter(|p| p.symlink_metadata().is_ok_and(|m| m.is_dir()))
        .collect();
    dirs.sort();
    dirs
}

pub fn discover(home: &Path) -> Vec<Installed> {
    let mut found = Vec::new();
    for (app, rel) in EDITORS {
        for dir in subdirs(&home.join(rel)) {
            if dir.join("package.json").is_file() {
                found.push(Installed {
                    app,
                    name: dir.file_name().unwrap_or_default().to_string_lossy().into(),
                    path: dir,
                });
            }
        }
    }
    for (app, root) in browser_roots(home) {
        for profile in subdirs(&root) {
            for ext in subdirs(&profile.join("Extensions")) {
                // Several versions can linger; the newest is the one that runs.
                let Some(version) = subdirs(&ext).pop() else {
                    continue;
                };
                if version.join("manifest.json").is_file() {
                    found.push(Installed {
                        app,
                        name: format!(
                            "{} ({})",
                            ext.file_name().unwrap_or_default().to_string_lossy(),
                            profile.file_name().unwrap_or_default().to_string_lossy()
                        ),
                        path: version,
                    });
                }
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_editor_and_browser_extensions() {
        let home = tempfile::tempdir().unwrap();
        let h = home.path();
        let ext = h.join(".vscode/extensions/ms-python.python-2024.8.1");
        std::fs::create_dir_all(&ext).unwrap();
        std::fs::write(ext.join("package.json"), "{}").unwrap();
        // Not an extension folder: no package.json.
        std::fs::create_dir_all(h.join(".cursor/extensions/.obsolete-dir")).unwrap();
        let crx = h.join(".config/google-chrome/Default/Extensions/abcdef");
        for v in ["1.0.0_0", "1.2.0_0"] {
            std::fs::create_dir_all(crx.join(v)).unwrap();
            std::fs::write(crx.join(v).join("manifest.json"), "{}").unwrap();
        }

        let found = discover(h);
        assert_eq!(found.len(), 2, "{:?}", found);
        assert_eq!(found[0].app, "VS Code");
        assert_eq!(found[0].name, "ms-python.python-2024.8.1");
        assert_eq!(found[1].app, "Chrome");
        assert_eq!(found[1].name, "abcdef (Default)");
        assert!(found[1].path.ends_with("1.2.0_0"));
    }
}
