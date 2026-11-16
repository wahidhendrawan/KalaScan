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

/// An AI agent's MCP or hook configuration. It is one file, so it is scanned
/// in a folder of its own as `as_file`: the name tells the scanner what it is.
pub struct AgentConfig {
    pub app: &'static str,
    pub path: PathBuf,
    pub as_file: &'static str,
}

pub fn agent_configs(home: &Path) -> Vec<AgentConfig> {
    let (mac, linux) = (
        home.join("Library/Application Support"),
        home.join(".config"),
    );
    let mut found = vec![
        ("Cursor", home.join(".cursor/mcp.json"), ".cursor/mcp.json"),
        (
            "Windsurf",
            home.join(".codeium/windsurf/mcp_config.json"),
            "mcp_config.json",
        ),
        (
            "Claude Code",
            home.join(".claude/settings.json"),
            ".claude/settings.json",
        ),
        ("Claude Code", home.join(".claude.json"), ".mcp.json"),
        (
            "Gemini CLI",
            home.join(".gemini/settings.json"),
            ".gemini/settings.json",
        ),
        (
            "Claude Desktop",
            mac.join("Claude/claude_desktop_config.json"),
            "claude_desktop_config.json",
        ),
        (
            "Claude Desktop",
            linux.join("Claude/claude_desktop_config.json"),
            "claude_desktop_config.json",
        ),
        (
            "VS Code",
            mac.join("Code/User/mcp.json"),
            ".vscode/mcp.json",
        ),
        (
            "VS Code",
            linux.join("Code/User/mcp.json"),
            ".vscode/mcp.json",
        ),
    ];
    if let Some(appdata) = std::env::var_os("APPDATA").map(PathBuf::from) {
        found.push((
            "Claude Desktop",
            appdata.join("Claude/claude_desktop_config.json"),
            "claude_desktop_config.json",
        ));
        found.push((
            "VS Code",
            appdata.join("Code/User/mcp.json"),
            ".vscode/mcp.json",
        ));
    }
    found
        .into_iter()
        .filter(|(_, path, _)| path.is_file())
        .map(|(app, path, as_file)| AgentConfig { app, path, as_file })
        .collect()
}

/// The part of a config file worth scanning: all of it, except for
/// `~/.claude.json`, which is mostly Claude Code's own state. Its MCP servers
/// (user scope and per project) are what an attacker would add.
pub fn agent_config_text(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    if path.file_name() != Some(".claude.json".as_ref()) {
        return Some(text);
    }
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    let mut servers = serde_json::Map::new();
    let mut add = |section: &serde_json::Value, prefix: &str| {
        for (name, server) in section.as_object().into_iter().flatten() {
            servers.insert(format!("{prefix}{name}"), server.clone());
        }
    };
    add(&v["mcpServers"], "");
    for (project, cfg) in v["projects"].as_object().into_iter().flatten() {
        add(&cfg["mcpServers"], &format!("{project}: "));
    }
    serde_json::to_string_pretty(&serde_json::json!({ "mcpServers": servers })).ok()
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
    // Claude Code: `plugins/cache/<marketplace>/<plugin>/<version>/`, and
    // skills as `skills/<name>/SKILL.md`. Every cached version is listed: an
    // older one is a `/plugin` switch away from running. shortcut: MCP
    // configs (~/.cursor/mcp.json, Claude Desktop) are files, not folders, so
    // not listed here; scan their folder instead.
    for marketplace in subdirs(&home.join(".claude/plugins/cache")) {
        for plugin in subdirs(&marketplace) {
            for version in subdirs(&plugin) {
                found.push(Installed {
                    app: "Claude Code",
                    name: format!(
                        "{}@{} ({})",
                        plugin.file_name().unwrap_or_default().to_string_lossy(),
                        version.file_name().unwrap_or_default().to_string_lossy(),
                        marketplace
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                    ),
                    path: version,
                });
            }
        }
    }
    for skill in subdirs(&home.join(".claude/skills")) {
        if skill.join("SKILL.md").is_file() {
            found.push(Installed {
                app: "Claude Code",
                name: format!(
                    "skill {}",
                    skill.file_name().unwrap_or_default().to_string_lossy()
                ),
                path: skill,
            });
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

    #[test]
    fn finds_agent_configs_and_keeps_only_mcp_servers_of_claude_json() {
        let home = tempfile::tempdir().unwrap();
        let h = home.path();
        std::fs::create_dir_all(h.join(".cursor")).unwrap();
        std::fs::write(h.join(".cursor/mcp.json"), r#"{"mcpServers": {}}"#).unwrap();
        std::fs::write(
            h.join(".claude.json"),
            r#"{"cachedGrowthBookFeatures": {"x": "http://1.2.3.4"},
                "mcpServers": {"gh": {"command": "npx"}},
                "projects": {"/repo": {"mcpServers": {"evil": {"command": "bash"}}, "lastCost": 1}}}"#,
        )
        .unwrap();
        let found = agent_configs(h);
        let files: Vec<&str> = found.iter().map(|c| c.as_file).collect();
        assert_eq!(files, [".cursor/mcp.json", ".mcp.json"]);
        let text = agent_config_text(&h.join(".claude.json")).unwrap();
        assert!(
            text.contains("\"gh\"") && text.contains("/repo: evil"),
            "{text}"
        );
        assert!(!text.contains("1.2.3.4") && !text.contains("lastCost"));
    }

    #[test]
    fn finds_claude_code_plugins_and_skills() {
        let home = tempfile::tempdir().unwrap();
        let h = home.path();
        std::fs::create_dir_all(h.join(".claude/plugins/cache/acme/linter/1.2.0/hooks")).unwrap();
        let skill = h.join(".claude/skills/release-notes");
        std::fs::create_dir_all(&skill).unwrap();
        std::fs::write(skill.join("SKILL.md"), "# Release notes").unwrap();
        // Not a skill: no SKILL.md.
        std::fs::create_dir_all(h.join(".claude/skills/scratch")).unwrap();

        let names: Vec<String> = discover(h).into_iter().map(|e| e.name).collect();
        assert_eq!(names, ["linter@1.2.0 (acme)", "skill release-notes"]);
    }
}
