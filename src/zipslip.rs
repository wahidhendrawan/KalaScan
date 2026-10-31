//! Zip slip by variable-level taint tracking (JS/TS and Python).
//!
//! Source: an archive entry name (loop variable over `zip.files`,
//! `namelist()`, … or anything read from `.entryName` / `.fileName`).
//! Propagation: assignments whose right side mentions a tainted name.
//! Sink: a file write whose arguments mention a tainted name.
//! Guard: a `..` / prefix check on a tainted name.
//!
//! shortcut: per file, no scopes or control flow; a guard anywhere on the
//! tainted name counts. Move to a real parser (tree-sitter) if this misses.

use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

static SOURCES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        // for (const f in zip.files) / for (const e of entries) / of zip.getEntries()
        r"for\s*\(\s*(?:const|let|var)?\s*([\w$]+)\s+(?:in|of)\s+[\w$.]*?(?:files|entries|getEntries\(\))\b",
        // zip.forEach((relativePath, file) => …) / entries.forEach(entry => …)
        r"(?:\b\w*[Zz]ip\w*|\bentries|\barchive)\.(?:forEach|map)\s*\(\s*(?:async\s*)?\(?\s*([\w$]+)",
        // for name in z.namelist() / infolist() / getmembers() / getnames()
        r"for\s+(\w+)\s+in\s+[\w.]+\.(?:namelist|infolist|getmembers|getnames)\s*\(",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

/// Entry-name properties: whatever is assigned from these is tainted.
static NAME_PROPERTY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.(?:entryName|fileName|filename)\b").unwrap());

static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\b(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)").unwrap()
});

static SINK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:writeFile(?:Sync)?|createWriteStream|outputFile(?:Sync)?|open)\s*\(([^\n]*)")
        .unwrap()
});

static GUARDS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"([\w$]+)\.(?:startsWith|startswith|is_relative_to)\s*\(",
        r#"([\w$]+)\.(?:includes|indexOf)\s*\(\s*['"`]\.\."#,
        r#"['"]\.\.['"]\s+in\s+([\w.]+)"#,
        r"path\.relative\s*\([^)]*?([\w$]+)\s*\)",
        r"isAbsolute\s*\(\s*([\w$]+)",
        r"commonpath\s*\(\s*\[[^\]]*?([\w$]+)\s*\]",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

/// Line of the first unguarded write of an archive entry name, if any.
pub fn find(content: &str) -> Option<usize> {
    // tarfile.extractall without `filter=` trusts member names (CVE-2007-4559).
    if content.contains("tarfile") {
        if let Some(i) = content.find(".extractall(") {
            let call = &content[i..content[i..].find(')').map_or(content.len(), |j| i + j)];
            if !call.contains("filter") && !call.contains("members") {
                return Some(line_of(content, i));
            }
        }
    }

    let mut tainted: HashSet<String> = SOURCES
        .iter()
        .flat_map(|re| re.captures_iter(content).map(|c| c[1].to_string()))
        .collect();
    let assignments: Vec<(String, String)> = ASSIGNMENT
        .captures_iter(content)
        .filter(|c| !c[2].starts_with('=') && !c[2].starts_with('>'))
        .map(|c| (c[1].to_string(), c[2].to_string()))
        .collect();
    for (lhs, rhs) in &assignments {
        if NAME_PROPERTY.is_match(rhs) {
            tainted.insert(lhs.clone());
        }
    }
    if tainted.is_empty() {
        return None;
    }
    // Propagate: an assignment whose right side names a tainted variable
    // taints its left side. Indexed by identifier, so this is linear in the
    // code size; rescanning every assignment per pass took 54 s on one
    // minified bundle, where single-letter names taint almost everything.
    let mut readers: HashMap<&str, Vec<&str>> = HashMap::new();
    for (lhs, rhs) in &assignments {
        for name in identifiers(rhs) {
            readers.entry(name).or_default().push(lhs);
        }
    }
    let mut queue: Vec<String> = tainted.iter().cloned().collect();
    while let Some(name) = queue.pop() {
        for lhs in readers.get(name.as_str()).into_iter().flatten() {
            if tainted.insert(lhs.to_string()) {
                queue.push(lhs.to_string());
            }
        }
    }

    let guarded = GUARDS.iter().any(|re| {
        re.captures_iter(content).any(|c| {
            let name = c[1].rsplit('.').next().unwrap_or_default();
            tainted.contains(name)
        })
    });
    if guarded {
        return None;
    }
    SINK.captures_iter(content).find_map(|c| {
        let args = c.get(1).unwrap();
        identifiers(args.as_str())
            .any(|name| tainted.contains(name))
            .then(|| line_of(content, args.start()))
    })
}

/// Whole identifiers in `text`, skipping properties: in `x.name`, `name` is
/// not the variable `name`.
fn identifiers(text: &str) -> impl Iterator<Item = &str> {
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'$';
    let bytes = text.as_bytes();
    let mut i = 0;
    std::iter::from_fn(move || {
        while i < bytes.len() {
            if !is_ident(bytes[i]) {
                i += 1;
                continue;
            }
            let start = i;
            while i < bytes.len() && is_ident(bytes[i]) {
                i += 1;
            }
            if start == 0 || bytes[start - 1] != b'.' {
                return Some(&text[start..i]);
            }
        }
        None
    })
}

fn line_of(content: &str, offset: usize) -> usize {
    content[..offset].matches('\n').count() + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minified_bundle_is_linear_and_still_found() {
        // One line, 30k chained assignments: the old fixpoint took ~54 s.
        let mut code = String::from("var e=zip.getEntry(x);var v0=e.entryName;");
        for i in 1..30_000 {
            code.push_str(&format!("var v{}=v{}+{};", i, i - 1, i));
        }
        code.push_str("fs.writeFileSync(v29999,data);");
        let started = std::time::Instant::now();
        assert_eq!(find(&code), Some(1));
        assert!(started.elapsed().as_secs() < 5, "{:?}", started.elapsed());
    }

    #[test]
    fn real_rainbow_fart_extractor_is_a_slip() {
        let js = "async function add(filepath) {\n\
                  var zip = await jszip.loadAsync(file);\n\
                  let basepath = path.resolve(share.PATH_VOICE_PACKAGES, manifest.name);\n\
                  for (let filename in zip.files) {\n\
                  if (zip.files[filename].dir) { continue; }\n\
                  await fs.writeFile(share.uri(path.resolve(basepath, filename)), await zip.file(filename).async('nodebuffer'));\n\
                  }\n}";
        assert_eq!(find(js), Some(6));
    }

    #[test]
    fn guard_must_be_on_the_tainted_path() {
        let guarded = "for (const f in zip.files) {\n\
                       const dest = path.join(base, f);\n\
                       if (!dest.startsWith(base)) throw new Error('slip');\n\
                       fs.writeFileSync(dest, data);\n}";
        assert_eq!(find(guarded), None);

        // The old file-wide check accepted any startsWith; this one is unrelated.
        let unrelated = "if (url.startsWith('https')) fetch(url);\n\
                         for (const f in zip.files) {\n\
                         fs.writeFileSync(path.join(base, f), data);\n}";
        assert_eq!(find(unrelated), Some(3));
    }

    #[test]
    fn taint_flows_through_entry_properties() {
        let adm = "zip.getEntries().forEach(function (e) {\n\
                   const name = e.entryName;\n\
                   const out = path.join(target, name);\n\
                   fs.writeFileSync(out, e.getData());\n});";
        assert_eq!(find(adm), Some(4));
    }

    #[test]
    fn python_extractors() {
        let tar = "import tarfile\nwith tarfile.open(p) as t:\n    t.extractall(dest)\n";
        assert_eq!(find(tar), Some(3));
        let tar_safe =
            "import tarfile\nwith tarfile.open(p) as t:\n    t.extractall(dest, filter='data')\n";
        assert_eq!(find(tar_safe), None);
        let zip_loop = "for name in z.namelist():\n    target = os.path.join(dest, name)\n    open(target, 'wb').write(z.read(name))\n";
        assert_eq!(find(zip_loop), Some(3));
        let zip_guarded = "for name in z.namelist():\n    if '..' in name: continue\n    open(os.path.join(dest, name), 'wb').write(z.read(name))\n";
        assert_eq!(find(zip_guarded), None);
        // zipfile.extractall sanitises member names itself.
        assert_eq!(
            find("import zipfile\nzipfile.ZipFile(p).extractall(dest)\n"),
            None
        );
    }

    #[test]
    fn writes_unrelated_to_entries_are_not_slips() {
        let js = "for (const f in zip.files) { names.push(f) }\nfs.writeFileSync(path.join(out, 'index.json'), JSON.stringify(names));";
        assert_eq!(find(js), None);
    }
}
