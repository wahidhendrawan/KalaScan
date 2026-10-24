use serde::Deserialize;
use std::fs::File;
use std::io::{Cursor, Read, Seek};
use std::path::{Path, PathBuf};
use zip::ZipArchive;

#[derive(Deserialize)]
struct OpenVsxMetadata {
    files: Option<OpenVsxFiles>,
}

#[derive(Deserialize)]
struct OpenVsxFiles {
    download: Option<String>,
}

#[derive(Deserialize)]
struct JetBrainsUpdate {
    file: String,
}

/// Detect if an input string is targeting a VS Code, Open VSX, JetBrains, or Chrome extension package
pub fn is_vsix_target(target: &str) -> bool {
    let t = target.trim();
    if t.ends_with(".vsix") || t.ends_with(".zip") || t.ends_with(".jar") || t.ends_with(".crx") {
        return true;
    }
    if t.contains("marketplace.visualstudio.com")
        || t.contains("open-vsx.org")
        || t.contains("plugins.jetbrains.com")
    {
        return true;
    }
    // Check if it's in `publisher.extension-name` format (e.g. `golang.go`, `ms-python.python`)
    // Must contain exactly one dot, no slashes, no spaces, not starting with http/git
    if !t.starts_with("http://") && !t.starts_with("https://") && !t.starts_with("git@") {
        let parts: Vec<&str> = t.split('.').collect();
        if parts.len() == 2
            && !parts[0].is_empty()
            && !parts[1].is_empty()
            && !t.contains('/')
            && !t.contains(' ')
            && !t.ends_with(".git")
        {
            return true;
        }
    }
    false
}

/// Download or extract a VSIX, Open VSX, JetBrains, CRX, or ZIP extension into destination directory
pub async fn unpack_extension(target: &str, dest_dir: &Path) -> anyhow::Result<PathBuf> {
    let t = target.trim();

    // Check if it is an existing local file
    let path = Path::new(t);
    if path.is_file() {
        let file = File::open(path)?;
        return extract_zip(file, dest_dir);
    }

    // Resolve download URL based on target type
    let download_url = if t.contains("marketplace.visualstudio.com") {
        parse_marketplace_url(t)?
    } else if t.contains("open-vsx.org") {
        resolve_openvsx_download(t).await?
    } else if t.contains("plugins.jetbrains.com") {
        resolve_jetbrains_download(t).await?
    } else if !t.starts_with("http://") && !t.starts_with("https://") {
        let parts: Vec<&str> = t.split('.').collect();
        if parts.len() == 2 {
            format!(
                "https://marketplace.visualstudio.com/_apis/public/gallery/publishers/{}/vsextensions/{}/latest/vspackage",
                parts[0], parts[1]
            )
        } else {
            return Err(anyhow::anyhow!(
                "Invalid extension identifier format. Expected publisher.name"
            ));
        }
    } else {
        t.to_string()
    };

    let client = reqwest::Client::builder()
        .user_agent("KalaScan-Security-Scanner/1.1")
        .build()?;

    let resp = client.get(&download_url).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to download extension package from {}: HTTP {}",
            download_url,
            resp.status()
        ));
    }

    let bytes = resp.bytes().await?;
    extract_zip(Cursor::new(bytes), dest_dir)
}

pub fn parse_marketplace_url(url_str: &str) -> anyhow::Result<String> {
    let parsed = url::Url::parse(url_str)?;
    for (k, v) in parsed.query_pairs() {
        if k == "itemName" {
            let parts: Vec<&str> = v.split('.').collect();
            if parts.len() == 2 {
                return Ok(format!(
                    "https://marketplace.visualstudio.com/_apis/public/gallery/publishers/{}/vsextensions/{}/latest/vspackage",
                    parts[0], parts[1]
                ));
            }
        }
    }
    Err(anyhow::anyhow!(
        "Could not find itemName=publisher.extension query param in marketplace URL"
    ))
}

pub fn parse_openvsx_target(url_str: &str) -> anyhow::Result<(String, String)> {
    let parsed = url::Url::parse(url_str)?;
    let segments: Vec<&str> = parsed
        .path_segments()
        .map(|s| s.collect())
        .unwrap_or_default();

    // Expected format: /extension/{namespace}/{name}
    if segments.len() >= 3 && segments[0] == "extension" {
        return Ok((segments[1].to_string(), segments[2].to_string()));
    }

    Err(anyhow::anyhow!(
        "Invalid Open VSX URL format. Expected https://open-vsx.org/extension/<namespace>/<name>"
    ))
}

async fn resolve_openvsx_download(url_str: &str) -> anyhow::Result<String> {
    let (namespace, name) = parse_openvsx_target(url_str)?;
    let metadata_url = format!(
        "https://open-vsx.org/api/{}/{}/latest",
        namespace, name
    );

    let client = reqwest::Client::builder()
        .user_agent("KalaScan-Security-Scanner/1.2.0")
        .build()?;

    let metadata: OpenVsxMetadata = client
        .get(&metadata_url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    metadata
        .files
        .and_then(|f| f.download)
        .ok_or_else(|| anyhow::anyhow!("Open VSX metadata did not contain a download URL"))
}

pub fn parse_jetbrains_plugin_id(url_str: &str) -> anyhow::Result<String> {
    let parsed = url::Url::parse(url_str)?;
    let segments: Vec<&str> = parsed
        .path_segments()
        .map(|s| s.collect())
        .unwrap_or_default();

    // Expected format: /plugin/{id}-{slug} or /plugin/{id}
    for window in segments.windows(2) {
        if window[0] == "plugin" {
            let id = window[1].split('-').next().unwrap_or_default();
            if !id.is_empty() && id.chars().all(|c| c.is_ascii_digit()) {
                return Ok(id.to_string());
            }
        }
    }

    Err(anyhow::anyhow!(
        "Invalid JetBrains Marketplace URL. Expected https://plugins.jetbrains.com/plugin/<id>-<name>"
    ))
}

async fn resolve_jetbrains_download(url_str: &str) -> anyhow::Result<String> {
    let plugin_id = parse_jetbrains_plugin_id(url_str)?;
    let updates_url = format!(
        "https://plugins.jetbrains.com/api/plugins/{}/updates?size=1",
        plugin_id
    );

    let client = reqwest::Client::builder()
        .user_agent("KalaScan-Security-Scanner/1.2.0")
        .build()?;

    let updates: Vec<JetBrainsUpdate> = client
        .get(&updates_url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let latest = updates
        .first()
        .ok_or_else(|| anyhow::anyhow!("No downloadable versions found for JetBrains plugin {}", plugin_id))?;

    Ok(format!("https://plugins.jetbrains.com/files/{}", latest.file))
}

pub fn extract_zip<R: Read + Seek>(mut reader: R, dest_dir: &Path) -> anyhow::Result<PathBuf> {
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?;

    // Check for Chrome CRX magic bytes (Cr24 = 0x43, 0x72, 0x32, 0x34)
    let is_crx = buffer.starts_with(b"Cr24");

    let zip_bytes = if is_crx {
        let zip_magic = b"PK\x03\x04";
        let zip_offset = buffer
            .windows(4)
            .position(|w| w == zip_magic)
            .ok_or_else(|| anyhow::anyhow!("Invalid CRX: embedded ZIP archive not found"))?;

        buffer[zip_offset..].to_vec()
    } else {
        buffer
    };

    let mut archive = ZipArchive::new(Cursor::new(zip_bytes))?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = match file.enclosed_name() {
            Some(path) => dest_dir.join(path),
            None => continue, // Prevent zip-slip
        };

        if file.name().ends_with('/') {
            std::fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    std::fs::create_dir_all(p)?;
                }
            }
            let mut outfile = File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
        }
    }

    // In VSIX packages, the extension source code is placed inside `extension/`
    let extension_subfolder = dest_dir.join("extension");
    if extension_subfolder.is_dir() {
        Ok(extension_subfolder)
    } else {
        Ok(dest_dir.to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_vsix_target() {
        assert!(is_vsix_target("test.vsix"));
        assert!(is_vsix_target("plugin.jar"));
        assert!(is_vsix_target("ext.crx"));
        assert!(is_vsix_target("bundle.zip"));
        assert!(is_vsix_target("https://example.com/ext.vsix"));
        assert!(is_vsix_target("https://marketplace.visualstudio.com/items?itemName=ms-python.python"));
        assert!(is_vsix_target("https://open-vsx.org/extension/redhat/java"));
        assert!(is_vsix_target("https://plugins.jetbrains.com/plugin/1234-myplugin"));
        assert!(is_vsix_target("ms-python.python"));
        assert!(is_vsix_target("golang.go"));
        assert!(!is_vsix_target("https://github.com/user/repo.git"));
        assert!(!is_vsix_target("https://github.com/user/repo"));
    }

    #[test]
    fn test_parse_marketplace_url() {
        let url = "https://marketplace.visualstudio.com/items?itemName=ms-python.python";
        let parsed = parse_marketplace_url(url).unwrap();
        assert_eq!(
            parsed,
            "https://marketplace.visualstudio.com/_apis/public/gallery/publishers/ms-python/vsextensions/python/latest/vspackage"
        );
    }

    #[test]
    fn test_parse_openvsx_target() {
        let url = "https://open-vsx.org/extension/redhat/java";
        let parsed = parse_openvsx_target(url).unwrap();
        assert_eq!(parsed, ("redhat".to_string(), "java".to_string()));
    }

    #[test]
    fn test_parse_jetbrains_plugin_id() {
        assert_eq!(
            parse_jetbrains_plugin_id("https://plugins.jetbrains.com/plugin/631-python").unwrap(),
            "631"
        );
        assert_eq!(
            parse_jetbrains_plugin_id("https://plugins.jetbrains.com/plugin/10044").unwrap(),
            "10044"
        );
        assert!(parse_jetbrains_plugin_id("https://plugins.jetbrains.com/").is_err());
    }

    fn build_test_zip() -> Vec<u8> {
        use std::io::Write;
        use zip::write::SimpleFileOptions;

        let mut buffer = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut buffer);
            writer
                .start_file("extension/extension.js", SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"console.log('hello');").unwrap();
            writer.finish().unwrap();
        }
        buffer.into_inner()
    }

    #[test]
    fn test_extract_zip() {
        let tmp = tempfile::tempdir().unwrap();
        let out = extract_zip(Cursor::new(build_test_zip()), tmp.path()).unwrap();
        assert!(out.join("extension.js").is_file());
    }

    #[test]
    fn test_extract_crx() {
        let mut crx = b"Cr24\x03\x00\x00\x00\x00\x00\x00\x00".to_vec();
        crx.extend(build_test_zip());

        let tmp = tempfile::tempdir().unwrap();
        let out = extract_zip(Cursor::new(crx), tmp.path()).unwrap();
        assert!(out.join("extension.js").is_file());
    }
}
