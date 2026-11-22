use serde::Deserialize;
use std::fs::File;
use std::io::{Cursor, Read};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
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

#[derive(Deserialize)]
struct NpmVersion {
    dist: NpmDist,
}

#[derive(Deserialize)]
struct NpmDist {
    tarball: String,
}

#[derive(Deserialize)]
struct PypiRelease {
    urls: Vec<PypiFile>,
}

#[derive(Deserialize)]
struct PypiFile {
    packagetype: String,
    url: String,
}

/// Registry package target: `npm:name[@version]`, `pypi:name[==version]` or
/// `crates:name[@version]`.
#[derive(Debug, PartialEq)]
pub struct PackageTarget {
    pub ecosystem: &'static str,
    pub name: String,
    pub version: Option<String>,
}

pub fn parse_package_target(target: &str) -> Option<PackageTarget> {
    let t = target.trim();
    let (ecosystem, name, version) = if let Some(spec) = t.strip_prefix("npm:") {
        // `@scope/name@1.0`: the version `@` is never the leading scope `@`.
        match spec.rfind('@').filter(|&i| i > 0) {
            Some(i) => ("npm", &spec[..i], Some(&spec[i + 1..])),
            None => ("npm", spec, None),
        }
    } else if let Some(spec) = t.strip_prefix("crates:") {
        match spec.split_once('@') {
            Some((n, v)) => ("crates", n, Some(v)),
            None => ("crates", spec, None),
        }
    } else {
        let spec = t.strip_prefix("pypi:")?;
        match spec.split_once("==") {
            Some((n, v)) => ("pypi", n, Some(v)),
            None => ("pypi", spec, None),
        }
    };
    // Names go into registry URLs: keep them to the registries' own charsets.
    let valid = |s: &str, extra: &[char]| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "-._".contains(c) || extra.contains(&c))
    };
    // `/` and `@` only in the npm `@scope/name` shape.
    let bare = match name.strip_prefix('@') {
        Some(scoped) if ecosystem == "npm" => match scoped.split_once('/') {
            Some((scope, pkg)) if valid(scope, &[]) && valid(pkg, &[]) => pkg,
            _ => return None,
        },
        _ => name,
    };
    if !valid(bare, &[]) || bare.starts_with('.') || version.is_some_and(|v| !valid(v, &['+'])) {
        return None;
    }
    Some(PackageTarget {
        ecosystem,
        name: name.to_string(),
        version: version.map(str::to_string),
    })
}

/// Loopback, private, link-local, CGNAT and unique-local addresses: hosts a
/// scan target must not make the server talk to (cloud metadata, admin ports).
pub fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || (a == 100 && (b & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| is_internal_ip(IpAddr::V4(v4)))
        }
    }
}

/// Whether `host` is, or resolves to, an internal address. Unresolvable is
/// not internal: the request fails on its own.
pub(crate) async fn resolves_internal(host: &str, port: u16) -> bool {
    match host.parse() {
        Ok(ip) => is_internal_ip(ip),
        Err(_) => tokio::net::lookup_host((host, port))
            .await
            .is_ok_and(|mut found| found.any(|a| is_internal_ip(a.ip()))),
    }
}

/// `KALASCAN_ALLOW_PRIVATE_TARGETS=1`: scan an internal Git server or mirror.
pub fn allow_private_targets() -> bool {
    std::env::var("KALASCAN_ALLOW_PRIVATE_TARGETS").is_ok_and(|v| v == "1")
}

/// Resolves only to public addresses. The address checked is the one the
/// connection then uses, for the first request and every redirect, so a
/// hostname that resolves (or re-resolves) to an internal address fails.
/// IP literals skip resolution: the redirect policy and the submit-time
/// check in `server.rs` handle those.
pub(crate) struct PublicOnly;

impl reqwest::dns::Resolve for PublicOnly {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let host = name.as_str();
            let public: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, 0))
                .await?
                .filter(|a| !is_internal_ip(a.ip()))
                .collect();
            if public.is_empty() {
                return Err(format!("{host} resolves to an internal address; refused").into());
            }
            Ok(Box::new(public.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// An API caller's request must not reach internal hosts; the operator's
/// own CLI scan may, and so may anyone with KALASCAN_ALLOW_PRIVATE_TARGETS=1.
pub(crate) fn public_only() -> bool {
    !crate::operator_scan() && !allow_private_targets()
}

/// One client for every registry and marketplace call. Bounded connect, idle
/// and total time: a host serving 1 KB/s used to hang the CLI forever.
pub(crate) fn http_client() -> anyhow::Result<reqwest::Client> {
    // A public URL that redirects to a literal internal address is refused;
    // a hostname is checked by `PublicOnly`.
    let policy = reqwest::redirect::Policy::custom(|attempt| {
        let internal = attempt
            .url()
            .host_str()
            .and_then(|h| h.trim_matches(['[', ']']).parse::<IpAddr>().ok())
            .is_some_and(is_internal_ip);
        if attempt.previous().len() >= 5 {
            attempt.error("too many redirects")
        } else if internal && !allow_private_targets() {
            attempt.error("redirect to an internal address refused")
        } else {
            attempt.follow()
        }
    });
    let builder = reqwest::Client::builder()
        .user_agent(concat!(
            "KalaScan-Security-Scanner/",
            env!("CARGO_PKG_VERSION")
        ))
        .connect_timeout(Duration::from_secs(30))
        .read_timeout(Duration::from_secs(60))
        .timeout(Duration::from_secs(900))
        .redirect(policy);
    Ok(if public_only() {
        builder.dns_resolver(std::sync::Arc::new(PublicOnly))
    } else {
        builder
    }
    .build()?)
}

/// Read a response body, refusing anything past `limit` before it is
/// buffered (`bytes()` used to read an unbounded body into memory).
pub(crate) async fn read_capped(
    mut resp: reqwest::Response,
    limit: u64,
) -> anyhow::Result<Vec<u8>> {
    let too_large =
        || anyhow::anyhow!("Response too large (> {} MiB limit)", limit / (1024 * 1024));
    if resp.content_length().is_some_and(|n| n > limit) {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if (body.len() + chunk.len()) as u64 > limit {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The archive to scan, and for a PyPI release scanned from its wheel, the
/// sdist beside it.
async fn resolve_package_download(pkg: &PackageTarget) -> anyhow::Result<(String, Option<String>)> {
    let client = http_client()?;
    if pkg.ecosystem == "npm" {
        let url = format!(
            "https://registry.npmjs.org/{}/{}",
            pkg.name.replace('/', "%2F"),
            pkg.version.as_deref().unwrap_or("latest")
        );
        let meta: NpmVersion = client
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        return Ok((meta.dist.tarball, None));
    }
    if pkg.ecosystem == "crates" {
        let version = match &pkg.version {
            Some(v) => v.clone(),
            None => {
                let meta: serde_json::Value = client
                    .get(format!("https://crates.io/api/v1/crates/{}", pkg.name))
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;
                meta["crate"]["max_stable_version"]
                    .as_str()
                    .or_else(|| meta["crate"]["max_version"].as_str())
                    .ok_or_else(|| anyhow::anyhow!("crates.io lists no version of {}", pkg.name))?
                    .to_string()
            }
        };
        return Ok((
            format!(
                "https://static.crates.io/crates/{0}/{0}-{1}.crate",
                pkg.name, version
            ),
            None,
        ));
    }
    let url = match &pkg.version {
        Some(v) => format!("https://pypi.org/pypi/{}/{}/json", pkg.name, v),
        None => format!("https://pypi.org/pypi/{}/json", pkg.name),
    };
    let meta: PypiRelease = client
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    // Wheels are what pip installs when one exists; the sdist is the fallback.
    let file = |kind: &str| {
        meta.urls
            .iter()
            .find(|f| f.packagetype == kind)
            .map(|f| f.url.clone())
    };
    match (file("bdist_wheel"), file("sdist")) {
        (Some(wheel), sdist) => Ok((wheel, sdist)),
        (None, Some(sdist)) => Ok((sdist, None)),
        (None, None) => Err(anyhow::anyhow!(
            "PyPI has no downloadable files for {}",
            pkg.name
        )),
    }
}

/// The sdist's `setup.py` beside the wheel, at `correlate::SDIST_SETUP`: it
/// still runs wherever no wheel fits, with `--no-binary`, or in a tool that
/// builds from source. Only that file: the rest of an sdist (tests, Makefiles,
/// release scripts) never runs at install and flagged clean packages.
/// Best effort: a release whose sdist cannot be read is scanned as before.
async fn add_sdist_setup(url: &str, root: &Path) {
    let dest = root.join(crate::correlate::SDIST_SETUP);
    if !url.ends_with(".tar.gz") || dest.exists() {
        return;
    }
    let got = async {
        let resp = http_client()?.get(url).send().await?.error_for_status()?;
        let bytes = read_capped(resp, MAX_ARCHIVE_BYTES).await?;
        let tmp = tempfile::tempdir()?;
        let top = extract_tar_gz(&bytes, tmp.path())?;
        let setup = top.join("setup.py");
        if setup.is_file() {
            std::fs::create_dir_all(dest.parent().unwrap_or(root))?;
            std::fs::copy(setup, &dest)?;
        }
        anyhow::Ok(())
    };
    if let Err(e) = got.await {
        tracing::warn!("sdist beside the wheel not read: {e}");
    }
}

/// Detect if an input string is targeting a VS Code, Open VSX, JetBrains, or Chrome extension package
pub fn is_vsix_target(target: &str) -> bool {
    let t = target.trim();
    if parse_package_target(t).is_some() {
        return true;
    }
    if t.ends_with(".vsix") || t.ends_with(".zip") || t.ends_with(".jar") || t.ends_with(".crx") {
        return true;
    }
    if t.contains("marketplace.visualstudio.com")
        || t.contains("open-vsx.org")
        || t.contains("plugins.jetbrains.com")
    {
        return true;
    }
    parse_marketplace_id(t).is_some()
}

/// `publisher.extension` or `publisher.extension@1.2.3` (VS Marketplace).
pub fn parse_marketplace_id(target: &str) -> Option<(&str, &str, Option<&str>)> {
    let (id, version) = match target.trim().rsplit_once('@') {
        Some((id, v)) => (id, Some(v)),
        None => (target.trim(), None),
    };
    let (publisher, name) = id.split_once('.')?;
    let ok = |s: &str, extra: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
    };
    let archive =
        ["vsix", "zip", "jar", "crx", "git"].contains(&name.to_ascii_lowercase().as_str());
    (ok(publisher, "-_") && ok(name, "-_") && !archive && version.is_none_or(|v| ok(v, ".-")))
        .then_some((publisher, name, version))
}

/// Download or extract a VSIX, Open VSX, JetBrains, CRX, or ZIP extension into destination directory.
/// `local`: the target may name a file on this machine. The CLI only: the API
/// admits `budget.xlsx` as a marketplace id, and it was read from the
/// server's working directory.
pub async fn unpack_extension(
    target: &str,
    dest_dir: &Path,
    local: bool,
) -> anyhow::Result<PathBuf> {
    let t = target.trim();

    // Check if it is an existing local file
    let path = Path::new(t);
    if local && path.is_file() {
        let mut bytes = Vec::new();
        File::open(path)?
            .take(MAX_ARCHIVE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        return extract_zip(&bytes, dest_dir);
    }

    // Resolve download URL based on target type
    let mut sdist = None;
    let download_url = if let Some(pkg) = parse_package_target(t) {
        let (url, beside) = resolve_package_download(&pkg).await?;
        sdist = beside;
        url
    } else if t.contains("marketplace.visualstudio.com") {
        parse_marketplace_url(t)?
    } else if t.contains("open-vsx.org") {
        resolve_openvsx_download(t).await?
    } else if t.contains("plugins.jetbrains.com") {
        resolve_jetbrains_download(t).await?
    } else if !t.starts_with("http://") && !t.starts_with("https://") {
        let (publisher, name, version) = parse_marketplace_id(t).ok_or_else(|| {
            anyhow::anyhow!(
                "Invalid extension identifier format. Expected publisher.name[@version]"
            )
        })?;
        format!(
            "https://marketplace.visualstudio.com/_apis/public/gallery/publishers/{}/vsextensions/{}/{}/vspackage",
            publisher,
            name,
            version.unwrap_or("latest")
        )
    } else {
        t.to_string()
    };

    let resp = http_client()?.get(&download_url).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to download extension package from {}: HTTP {}",
            crate::redact_credentials(&download_url),
            resp.status()
        ));
    }

    let bytes = read_capped(resp, MAX_ARCHIVE_BYTES).await?;
    // A .crate is a gzipped tarball too.
    if [".tgz", ".tar.gz", ".crate"]
        .iter()
        .any(|ext| download_url.ends_with(ext))
    {
        return extract_tar_gz(&bytes, dest_dir);
    }
    // The VS Marketplace serves .vsix with `Content-Encoding: gzip`, and
    // reqwest is built without decompression: every marketplace-id scan
    // failed with "Could not find EOCD".
    if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut vsix = Vec::new();
        flate2::read::GzDecoder::new(&bytes[..])
            .take(MAX_ARCHIVE_BYTES + 1)
            .read_to_end(&mut vsix)?;
        return extract_zip(&vsix, dest_dir);
    }
    let root = extract_zip(&bytes, dest_dir)?;
    if let Some(url) = sdist {
        add_sdist_setup(&url, &root).await;
    }
    Ok(root)
}

/// A tar stream with empty size fields filled in. GNU tar and npm read a
/// size field of NULs as 0; the `tar` crate refuses the whole archive. npm's
/// own `0.0.0-stage` placeholders have such a directory entry, and what npm
/// installs has to be scannable.
struct EmptySizes<R> {
    inner: R,
    /// A header block read ahead and not handed out yet.
    pending: Vec<u8>,
    /// Bytes of entry data (padded to a block) before the next header.
    data_left: u64,
}

impl<R: std::io::Read> std::io::Read for EmptySizes<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if !self.pending.is_empty() {
                let n = out.len().min(self.pending.len());
                out[..n].copy_from_slice(&self.pending[..n]);
                self.pending.drain(..n);
                return Ok(n);
            }
            if self.data_left > 0 {
                let want = out
                    .len()
                    .min(usize::try_from(self.data_left).unwrap_or(usize::MAX));
                let n = self.inner.read(&mut out[..want])?;
                self.data_left -= n as u64;
                return Ok(n);
            }
            let mut block = [0u8; 512];
            let mut got = 0;
            while got < block.len() {
                match self.inner.read(&mut block[got..])? {
                    0 => break,
                    n => got += n,
                }
            }
            if got == 0 {
                return Ok(0);
            }
            if got == block.len() && block.iter().any(|&b| b != 0) {
                if block[124..136].iter().all(|&b| b == 0 || b == b' ') {
                    block[124..136].copy_from_slice(b"00000000000\0");
                    // The checksum is over the header with its own field as spaces.
                    block[148..156].fill(b' ');
                    let sum: u32 = block.iter().map(|&b| u32::from(b)).sum();
                    block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
                }
                let size = std::str::from_utf8(&block[124..136])
                    .ok()
                    .map(|s| s.trim_matches(|c| c == '\0' || c == ' '))
                    .and_then(|s| u64::from_str_radix(s, 8).ok());
                // A size this cannot read (base-256): hand the rest through as it is.
                self.data_left = size.map_or(u64::MAX, |s| s.div_ceil(512) * 512);
            }
            self.pending = block[..got].to_vec();
        }
    }
}

/// npm tarballs and PyPI sdists, under the same zip-bomb limits as `extract_zip`.
pub fn extract_tar_gz(bytes: &[u8], dest_dir: &Path) -> anyhow::Result<PathBuf> {
    if bytes.len() as u64 > MAX_ARCHIVE_BYTES {
        anyhow::bail!("Archive too large ({} bytes)", bytes.len());
    }
    let mut archive = tar::Archive::new(EmptySizes {
        inner: flate2::read::GzDecoder::new(bytes),
        pending: Vec::new(),
        data_left: 0,
    });
    let mut total_uncompressed: u64 = 0;
    for (i, entry) in archive.entries()?.enumerate() {
        let mut entry = entry?;
        if i >= MAX_ENTRIES {
            anyhow::bail!("Archive contains too many files (> {} limit)", MAX_ENTRIES);
        }
        // tar reads exactly the header size, so header sizes bound the output.
        let size = entry.header().size()?;
        if size > MAX_SINGLE_UNCOMPRESSED {
            anyhow::bail!("Archive entry is too large ({} bytes)", size);
        }
        total_uncompressed = total_uncompressed.saturating_add(size);
        if total_uncompressed > MAX_TOTAL_UNCOMPRESSED {
            anyhow::bail!(
                "Archive expands beyond {} MiB limit",
                MAX_TOTAL_UNCOMPRESSED / (1024 * 1024)
            );
        }
        // Links could point outside dest_dir; scanning needs regular files only.
        if !matches!(
            entry.header().entry_type(),
            tar::EntryType::Regular | tar::EntryType::Directory
        ) {
            continue;
        }
        // unpack_in refuses `..` and absolute paths (returns false).
        entry.unpack_in(dest_dir)?;
    }

    // npm packs into `package/`, sdists into `name-version/`: scan from there
    // so the manifest sits at the root for the dependency checks.
    let mut top = std::fs::read_dir(dest_dir)?.flatten();
    match (top.next(), top.next()) {
        (Some(only), None) if only.path().is_dir() => Ok(only.path()),
        _ => Ok(dest_dir.to_path_buf()),
    }
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

/// `https://open-vsx.org/extension/<ns>/<name>/<version>`: the version page
/// pins a release (the clean corpus scans the one published before a cutoff).
fn openvsx_version(url_str: &str) -> Option<String> {
    let url = url::Url::parse(url_str).ok()?;
    let version = url.path_segments()?.nth(3)?;
    (!version.is_empty()
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-+_".contains(c)))
    .then(|| version.to_string())
}

async fn resolve_openvsx_download(url_str: &str) -> anyhow::Result<String> {
    let (namespace, name) = parse_openvsx_target(url_str)?;
    let metadata_url = format!(
        "https://open-vsx.org/api/{}/{}/{}",
        namespace,
        name,
        openvsx_version(url_str).unwrap_or_else(|| "latest".to_string())
    );

    let metadata: OpenVsxMetadata = http_client()?
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

    let updates: Vec<JetBrainsUpdate> = http_client()?
        .get(&updates_url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let latest = updates.first().ok_or_else(|| {
        anyhow::anyhow!(
            "No downloadable versions found for JetBrains plugin {}",
            plugin_id
        )
    })?;

    Ok(format!(
        "https://plugins.jetbrains.com/files/{}",
        latest.file
    ))
}

/// Zip-bomb guards: cap archive size, entry count, per-entry and total uncompressed bytes.
/// These are trust-boundary limits for untrusted packages (.vsix/.zip/.jar/.crx).
const MAX_ARCHIVE_BYTES: u64 = 1024 * 1024 * 1024; // 1 GiB compressed input
const MAX_ENTRIES: usize = 10_000;
const MAX_TOTAL_UNCOMPRESSED: u64 = 512 * 1024 * 1024; // 512 MiB
const MAX_SINGLE_UNCOMPRESSED: u64 = 128 * 1024 * 1024; // 128 MiB per entry

pub fn extract_zip(bytes: &[u8], dest_dir: &Path) -> anyhow::Result<PathBuf> {
    extract_zip_capped(bytes, dest_dir, MAX_TOTAL_UNCOMPRESSED)
}

fn extract_zip_capped(bytes: &[u8], dest_dir: &Path, max_total: u64) -> anyhow::Result<PathBuf> {
    if bytes.len() as u64 > MAX_ARCHIVE_BYTES {
        anyhow::bail!(
            "Archive too large ({} bytes > {} MiB limit)",
            bytes.len(),
            MAX_ARCHIVE_BYTES / (1024 * 1024)
        );
    }

    // Check for Chrome CRX magic bytes (Cr24 = 0x43, 0x72, 0x32, 0x34)
    let zip_bytes = if bytes.starts_with(b"Cr24") {
        let zip_offset = bytes
            .windows(4)
            .position(|w| w == b"PK\x03\x04")
            .ok_or_else(|| anyhow::anyhow!("Invalid CRX: embedded ZIP archive not found"))?;
        &bytes[zip_offset..]
    } else {
        bytes
    };

    let mut archive = ZipArchive::new(Cursor::new(zip_bytes))?;

    if archive.len() > MAX_ENTRIES {
        anyhow::bail!(
            "Archive contains too many files ({} > {} limit)",
            archive.len(),
            MAX_ENTRIES
        );
    }

    // Counted from the bytes actually written: headers are attacker-written,
    // and entries declaring 1 byte each used to inflate to 640 MB unchecked.
    let mut total_uncompressed: u64 = 0;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = match file.enclosed_name() {
            Some(path) => dest_dir.join(path),
            None => continue, // Prevent zip-slip
        };

        if file.is_dir() {
            std::fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    std::fs::create_dir_all(p)?;
                }
            }
            let mut outfile = File::create(&outpath)?;
            // A bigger entry is truncated, not fatal: the scanner reads only
            // part of a file over 4 MiB and flags it as oversized. Claude
            // Code ships a 270 MB binary that used to make the VSIX unscannable.
            // One byte past the remaining budget is enough to detect overflow.
            let budget = max_total - total_uncompressed;
            let cap = MAX_SINGLE_UNCOMPRESSED.min(budget + 1);
            let written = std::io::copy(&mut Read::by_ref(&mut file).take(cap), &mut outfile)?;
            total_uncompressed += written;
            if total_uncompressed > max_total {
                anyhow::bail!(
                    "Archive expands beyond {} MiB limit",
                    max_total / (1024 * 1024)
                );
            }
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

    /// A hostname that resolves to loopback is refused at connect time, where
    /// a literal-address check before the request would have let it through.
    #[tokio::test]
    async fn public_only_refuses_a_hostname_that_resolves_internal() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://localhost:{}/",
            listener.local_addr().unwrap().port()
        );
        let guarded = reqwest::Client::builder()
            .dns_resolver(std::sync::Arc::new(PublicOnly))
            .build()
            .unwrap();
        let err = guarded.get(&url).send().await.unwrap_err();
        assert!(format!("{err:?}").contains("internal address"), "{err:?}");
    }

    #[test]
    fn test_is_vsix_target() {
        assert!(is_vsix_target("test.vsix"));
        assert!(is_vsix_target("plugin.jar"));
        assert!(is_vsix_target("ext.crx"));
        assert!(is_vsix_target("bundle.zip"));
        assert!(is_vsix_target("https://example.com/ext.vsix"));
        assert!(is_vsix_target(
            "https://marketplace.visualstudio.com/items?itemName=ms-python.python"
        ));
        assert!(is_vsix_target("https://open-vsx.org/extension/redhat/java"));
        assert!(is_vsix_target(
            "https://plugins.jetbrains.com/plugin/1234-myplugin"
        ));
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
        assert_eq!(openvsx_version(url), None);
        assert_eq!(
            openvsx_version("https://open-vsx.org/extension/GitHub/github-vscode-theme/6.3.4")
                .as_deref(),
            Some("6.3.4")
        );
        assert_eq!(
            openvsx_version("https://open-vsx.org/extension/a/b/1.0%2F..%2Fx"),
            None
        );
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
        let out = extract_zip(&build_test_zip(), tmp.path()).unwrap();
        assert!(out.join("extension.js").is_file());
    }

    #[test]
    fn test_extract_crx() {
        let mut crx = b"Cr24\x03\x00\x00\x00\x00\x00\x00\x00".to_vec();
        crx.extend(build_test_zip());

        let tmp = tempfile::tempdir().unwrap();
        let out = extract_zip(&crx, tmp.path()).unwrap();
        assert!(out.join("extension.js").is_file());
    }

    #[tokio::test]
    async fn only_the_cli_reads_a_local_package_file() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("budget.xlsx");
        std::fs::write(&file, build_test_zip()).unwrap();
        let target = file.to_str().unwrap();
        let dest = tmp.path().join("out");
        std::fs::create_dir(&dest).unwrap();

        // The server: a path is not an id, so this fails before any network call.
        let err = unpack_extension(target, &dest, false).await.unwrap_err();
        assert!(err.to_string().contains("identifier format"), "{}", err);
        assert_eq!(std::fs::read_dir(&dest).unwrap().count(), 0);

        let out = unpack_extension(target, &dest, true).await.unwrap();
        assert!(out.join("extension.js").is_file());
    }

    #[test]
    fn zip_total_counts_bytes_written_not_headers() {
        use std::io::Write;
        use zip::write::SimpleFileOptions;
        let mut buf = Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut buf);
            for name in ["a.js", "b.js"] {
                w.start_file(name, SimpleFileOptions::default()).unwrap();
                w.write_all(&[b'a'; 65_536]).unwrap();
            }
            w.finish().unwrap();
        }
        let honest = buf.into_inner();
        let tmp = tempfile::tempdir().unwrap();
        assert!(extract_zip_capped(&honest, tmp.path(), 200_000).is_ok());
        assert!(extract_zip_capped(&honest, tempfile::tempdir().unwrap().path(), 100_000).is_err());

        // Same archive, every header now claiming 1 byte uncompressed.
        let mut lying = honest.clone();
        for (sig, field) in [(b"PK\x03\x04", 22), (b"PK\x01\x02", 24)] {
            let starts: Vec<usize> = lying
                .windows(4)
                .enumerate()
                .filter(|(_, w)| w == sig)
                .map(|(i, _)| i)
                .collect();
            for i in starts {
                lying[i + field..i + field + 4].copy_from_slice(&1u32.to_le_bytes());
            }
        }
        let dest = tempfile::tempdir().unwrap();
        let _ = extract_zip_capped(&lying, dest.path(), 100_000);
        let written: u64 = walkdir::WalkDir::new(dest.path())
            .into_iter()
            .flatten()
            .filter_map(|e| e.metadata().ok())
            .filter(|m| m.is_file())
            .map(|m| m.len())
            .sum();
        assert!(
            written <= 100_001,
            "wrote {} bytes past a 100 KB cap",
            written
        );
    }

    #[test]
    fn internal_addresses() {
        for ip in [
            "127.0.0.1",
            "10.0.0.5",
            "172.16.3.4",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
            "0.0.0.0",
        ] {
            assert!(is_internal_ip(ip.parse().unwrap()), "{}", ip);
        }
        for ip in ["140.82.112.3", "8.8.8.8", "2606:4700::1111"] {
            assert!(!is_internal_ip(ip.parse().unwrap()), "{}", ip);
        }
    }

    #[test]
    fn test_parse_marketplace_id() {
        assert_eq!(
            parse_marketplace_id("ms-python.python"),
            Some(("ms-python", "python", None))
        );
        assert_eq!(
            parse_marketplace_id("esbenp.prettier-vscode@10.4.0"),
            Some(("esbenp", "prettier-vscode", Some("10.4.0")))
        );
        for bad in [
            "evil.vsix",
            "a.b.c",
            "a/b.c",
            "x.y@1.0?x",
            ".x",
            "user.repo.git",
            "src",
        ] {
            assert_eq!(parse_marketplace_id(bad), None, "{}", bad);
        }
    }

    #[test]
    fn test_parse_package_target() {
        let p = |t| parse_package_target(t);
        let pkg = |eco, name: &str, ver: Option<&str>| {
            Some(PackageTarget {
                ecosystem: eco,
                name: name.to_string(),
                version: ver.map(str::to_string),
            })
        };
        assert_eq!(p("npm:express"), pkg("npm", "express", None));
        assert_eq!(
            p("npm:express@4.17.1"),
            pkg("npm", "express", Some("4.17.1"))
        );
        assert_eq!(p("npm:@types/node"), pkg("npm", "@types/node", None));
        assert_eq!(
            p("npm:@types/node@20.1.0"),
            pkg("npm", "@types/node", Some("20.1.0"))
        );
        assert_eq!(
            p("pypi:requests==2.31.0"),
            pkg("pypi", "requests", Some("2.31.0"))
        );
        assert_eq!(p("pypi:requests"), pkg("pypi", "requests", None));
        assert_eq!(p("crates:serde"), pkg("crates", "serde", None));
        assert_eq!(
            p("crates:tokio@1.38.0"),
            pkg("crates", "tokio", Some("1.38.0"))
        );
        assert!(p("crates:a/b").is_none());
        assert!(p("crates:x@1.0.0/../y").is_none());
        // Must not smuggle anything into the registry URL.
        assert!(p("npm:../../etc").is_none());
        assert!(p("npm:a/b").is_none());
        assert!(p("npm:@a/b/c").is_none());
        assert!(p("pypi:a/b").is_none());
        assert!(p("npm:a?b=c").is_none());
        assert!(p("pypi:x==1#frag").is_none());
        assert!(p("npm:").is_none());
        assert!(p("express").is_none());
        assert!(is_vsix_target("npm:express"));
    }

    fn tar_gz(entries: &[(&str, tar::EntryType, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let gz = flate2::write::GzEncoder::new(&mut out, flate2::Compression::fast());
            let mut builder = tar::Builder::new(gz);
            for (name, kind, data) in entries {
                let mut header = tar::Header::new_old();
                // Raw name bytes: set_path() would refuse the `..` we want to test.
                header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
                header.set_entry_type(*kind);
                header.set_size(data.len() as u64);
                if *kind == tar::EntryType::Symlink {
                    header.set_link_name("/etc/passwd").unwrap();
                }
                header.set_mode(0o644);
                header.set_cksum();
                builder.append(&header, *data).unwrap();
            }
            builder.into_inner().unwrap().finish().unwrap();
        }
        out
    }

    #[test]
    fn tar_entry_with_an_empty_size_field_is_read_as_empty() {
        // npm's `0.0.0-stage` placeholder: `package/` with the size field all
        // NULs and the checksum made over that.
        let mut dir = tar::Header::new_ustar();
        dir.set_path("package/").unwrap();
        dir.set_entry_type(tar::EntryType::Directory);
        dir.set_mode(0o755);
        dir.set_size(0);
        let mut raw = *dir.as_bytes();
        raw[124..136].fill(0);
        raw[148..156].fill(b' ');
        let sum: u32 = raw.iter().map(|&b| u32::from(b)).sum();
        raw[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        let rest = {
            let mut builder = tar::Builder::new(Vec::new());
            let mut file = tar::Header::new_ustar();
            file.set_path("package/package.json").unwrap();
            file.set_size(2);
            file.set_mode(0o644);
            file.set_cksum();
            builder.append(&file, &b"{}"[..]).unwrap();
            builder.into_inner().unwrap()
        };
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &raw).unwrap();
        std::io::Write::write_all(&mut gz, &rest).unwrap();
        let archive = gz.finish().unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let root = extract_tar_gz(&archive, tmp.path()).unwrap();
        assert_eq!(std::fs::read(root.join("package.json")).unwrap(), b"{}");
    }

    #[test]
    fn test_extract_tar_gz_is_contained() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("dest");
        std::fs::create_dir(&dest).unwrap();
        let archive = tar_gz(&[
            ("package/package.json", tar::EntryType::Regular, b"{}"),
            ("package/index.js", tar::EntryType::Regular, b"eval(x)"),
            ("package/link", tar::EntryType::Symlink, b""),
            ("../escape.txt", tar::EntryType::Regular, b"pwned"),
        ]);
        let root = extract_tar_gz(&archive, &dest).unwrap();
        assert_eq!(root, dest.join("package"));
        assert!(root.join("index.js").is_file());
        assert!(!root.join("link").exists());
        assert!(!tmp.path().join("escape.txt").exists());
    }
}
