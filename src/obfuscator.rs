//! What a javascript-obfuscator file calls, from its string table.
//!
//! The obfuscator moves every string literal into one array
//! (`const _0x2e30=['readFileSync','post',…]`) and calls APIs through it
//! (`fs[_0x5d1b(0x1be)](p)`), so no rule sees `readFileSync(` or a URL.
//! The array itself still holds the names: decode it, then ask which kinds
//! of behaviour those names add up to. Options it may have used:
//! `stringArrayEncoding: base64` (custom alphabet, decoded here) and
//! `splitStrings` (literals cut into 10-char pieces and shuffled, so
//! `powershell` and `"irm https` arrive as separate entries).
//!
//! shortcut: the `rc4` encoding needs the per-call key and is not decoded;
//! such files keep only the plain Obfuscator.io finding.

use crate::RuleMatch;
use regex::Regex;
use std::sync::LazyLock;

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
        decoded
    } else {
        raw
    }
}

fn any_contains(table: &[String], needles: &[&str]) -> Option<String> {
    table.iter().find_map(|s| {
        let lower = s.to_ascii_lowercase();
        needles.iter().any(|n| lower.contains(n)).then(|| s.clone())
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
    fn obfuscated_loader_without_those_names_is_quiet() {
        // Live Share's obfuscated host check: no file read, secret or shell.
        let src = "const _0x1a2b=['platform','version','arch','toString','length','apply','constructor'];";
        assert!(chains("checkHostApp.js", &string_table(src)).is_empty());
        assert!(string_table("const x = ['a', 'b'];").is_empty());
    }
}
