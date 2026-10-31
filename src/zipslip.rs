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
use std::collections::HashSet;
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
    // Propagate to a fixpoint (bounded: each pass adds at least one name).
    for _ in 0..assignments.len() {
        let before = tainted.len();
        for (lhs, rhs) in &assignments {
            if tainted.iter().any(|t| mentions(rhs, t)) {
                tainted.insert(lhs.clone());
            }
        }
        if tainted.len() == before {
            break;
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
        tainted
            .iter()
            .any(|t| mentions(args.as_str(), t))
            .then(|| line_of(content, args.start()))
    })
}

/// `name` as a whole identifier inside `text`.
fn mentions(text: &str, name: &str) -> bool {
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'$';
    let bytes = text.as_bytes();
    text.match_indices(name).any(|(i, _)| {
        let before = i.checked_sub(1).map(|j| bytes[j]);
        let after = bytes.get(i + name.len()).copied();
        // `x.name` is a property, not the variable `name`.
        !before.is_some_and(|b| is_ident(b) || b == b'.') && !after.is_some_and(is_ident)
    })
}

fn line_of(content: &str, offset: usize) -> usize {
    content[..offset].matches('\n').count() + 1
}

#[cfg(test)]
mod tests {
    use super::*;

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
