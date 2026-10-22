use std::fs::File;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use zip::ZipArchive;

/// Detect if an input string is targeting a VS Code extension
pub fn is_vsix_target(target: &str) -> bool {
    let t = target.trim();
    if t.ends_with(".vsix") || t.ends_with(".zip") {
        return true;
    }
    if t.contains("marketplace.visualstudio.com") {
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

/// Download or extract a VSIX / ZIP extension into destination directory
pub async fn unpack_extension(target: &str, dest_dir: &Path) -> anyhow::Result<PathBuf> {
    let t = target.trim();

    // Check if it is an existing local file
    let path = Path::new(t);
    if path.is_file() {
        let file = File::open(path)?;
        return extract_zip(file, dest_dir);
    }

    // Resolve download URL if marketplace or publisher.name
    let download_url = if t.contains("marketplace.visualstudio.com") {
        parse_marketplace_url(t)?
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

pub fn extract_zip<R: std::io::Read + std::io::Seek>(
    reader: R,
    dest_dir: &Path,
) -> anyhow::Result<PathBuf> {
    let mut archive = ZipArchive::new(reader)?;

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

    // In VSIX packages, the extension source code is placed inside the `extension/` subfolder
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
        assert!(is_vsix_target("https://example.com/ext.vsix"));
        assert!(is_vsix_target("https://marketplace.visualstudio.com/items?itemName=ms-python.python"));
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
}
