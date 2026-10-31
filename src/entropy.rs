use crate::RuleMatch;

/// Calculate Shannon entropy for a slice of bytes.
/// Returns a value between 0.0 (uniform) and 8.0 (completely random / compressed).
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0usize; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Check if a character is an invisible zero-width character
pub fn is_zero_width_char(c: char) -> bool {
    matches!(
        c,
        '\u{200B}' // Zero Width Space
            | '\u{200C}' // Zero Width Non-Joiner
            | '\u{200D}' // Zero Width Joiner
            | '\u{2060}' // Word Joiner
            | '\u{FEFF}' // Zero Width No-Break Space (BOM)
    )
}

/// Check if a character is a BiDi Trojan Source control character (CVE-2021-42574)
pub fn is_bidi_trojan_char(c: char) -> bool {
    matches!(
        c,
        '\u{202A}' // Left-to-Right Embedding (LRE)
            | '\u{202B}' // Right-to-Left Embedding (RLE)
            | '\u{202C}' // Pop Directional Formatting (PDF)
            | '\u{202D}' // Left-to-Right Override (LRO)
            | '\u{202E}' // Right-to-Left Override (RLO)
            | '\u{2066}' // Left-to-Right Isolate (LRI)
            | '\u{2067}' // Right-to-Left Isolate (RLI)
            | '\u{2068}' // First Strong Isolate (FSI)
            | '\u{2069}' // Pop Directional Isolate (PDI)
    )
}

/// Check if a character is a common Cyrillic confusable homoglyph used in spoofing Latin code identifiers
pub fn is_confusable_homoglyph(c: char) -> bool {
    matches!(
        c,
        '\u{0430}' // Cyrillic small 'a'
            | '\u{0441}' // Cyrillic small 'c'
            | '\u{0435}' // Cyrillic small 'e'
            | '\u{043E}' // Cyrillic small 'o'
            | '\u{0440}' // Cyrillic small 'p'
            | '\u{0455}' // Cyrillic small 's'
            | '\u{0456}' // Cyrillic small 'i'
            | '\u{0458}' // Cyrillic small 'j'
            | '\u{0410}' // Cyrillic capital 'A'
            | '\u{0412}' // Cyrillic capital 'V' (looks like 'B')
            | '\u{0415}' // Cyrillic capital 'E'
            | '\u{041A}' // Cyrillic capital 'K'
            | '\u{041C}' // Cyrillic capital 'M'
            | '\u{041D}' // Cyrillic capital 'H'
            | '\u{041E}' // Cyrillic capital 'O'
            | '\u{0420}' // Cyrillic capital 'P'
            | '\u{0421}' // Cyrillic capital 'C'
            | '\u{0422}' // Cyrillic capital 'T'
            | '\u{0425}' // Cyrillic capital 'X'
    )
}

/// Scan file content for high-entropy blobs, invisible characters, Trojan Source, and homoglyphs.
/// A zero-width char with ASCII word chars on both sides hides inside a token
/// (`pass​word`). ZWJ in emoji, ZWNJ in Persian/Indic text and codepage
/// tables in iconv bundles are ordinary text.
fn has_hidden_zero_width(line: &str) -> bool {
    let chars: Vec<char> = line.chars().collect();
    let is_word = |c: Option<&char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_');
    chars.iter().enumerate().any(|(i, &c)| {
        is_zero_width_char(c)
            && is_word(i.checked_sub(1).and_then(|p| chars.get(p)))
            && is_word(chars.get(i + 1))
    })
}

pub fn scan_advanced_obfuscation(file_path: &str, content: &str) -> Vec<RuleMatch> {
    let mut matches = Vec::new();

    // Skip scanning markdown or text files for entropy/homoglyphs to reduce noise
    let is_doc =
        file_path.ends_with(".md") || file_path.ends_with(".txt") || file_path.ends_with(".rst");

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;

        // 1. Detect Trojan Source (CVE-2021-42574). It fools a human reading
        // the source, so minified lines (bundles carrying RTL tables) are out.
        if line.len() <= 1000 && line.chars().any(is_bidi_trojan_char) {
            matches.push(RuleMatch {
                file_path: file_path.to_string(),
                line_number: line_num,
                matched_pattern: "Trojan Source Bi-Directional Character (CVE-2021-42574)"
                    .to_string(),
                severity: "critical".to_string(),
                context: line.chars().take(120).collect(),
            });
        }

        // 2. Detect Invisible Zero-Width Characters (ignore BOM at line 1 col 1)
        let body = if line_num == 1 {
            line.strip_prefix('\u{FEFF}').unwrap_or(line)
        } else {
            line
        };

        if has_hidden_zero_width(body) {
            matches.push(RuleMatch {
                file_path: file_path.to_string(),
                line_number: line_num,
                matched_pattern: "Invisible Zero-Width Character (Steganography/Obfuscation)"
                    .to_string(),
                severity: "high".to_string(),
                context: line.chars().take(120).collect(),
            });
        }

        if is_doc {
            continue;
        }

        // 3. Detect Confusable Homoglyphs in Code: one word mixing ASCII letters
        // with Cyrillic lookalikes. Per word, not per line: a Russian UI string
        // next to Latin code is localisation, not spoofing.
        let spoofed_word = line
            .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$'))
            .any(|w| {
                w.chars().any(|c| c.is_ascii_alphabetic()) && w.chars().any(is_confusable_homoglyph)
            });

        if spoofed_word {
            matches.push(RuleMatch {
                file_path: file_path.to_string(),
                line_number: line_num,
                matched_pattern: "Confusable Homoglyph Character (Supply Chain Spoofing)"
                    .to_string(),
                severity: "high".to_string(),
                context: line.chars().take(120).collect(),
            });
        }

        // 4. Detect High-Entropy String Literals (e.g. encrypted payloads, packed strings)
        // Extract continuous tokens of length >= 60 containing no whitespace
        for token in line.split_whitespace() {
            // Strip quotes and delimiters
            let clean_token = token.trim_matches(|c: char| {
                c == '"'
                    || c == '\''
                    || c == '`'
                    || c == ';'
                    || c == ','
                    || c == '('
                    || c == ')'
                    || c == '['
                    || c == ']'
            });

            if clean_token.len() >= 60 {
                let ent = calculate_entropy(clean_token.as_bytes());
                if ent >= 5.2 {
                    matches.push(RuleMatch {
                        file_path: file_path.to_string(),
                        line_number: line_num,
                        matched_pattern: format!(
                            "High-Entropy Suspicious Blob (Entropy: {:.2})",
                            ent
                        ),
                        severity: "medium".to_string(),
                        context: format!("{}...", clean_token.chars().take(80).collect::<String>()),
                    });
                    break; // Max one entropy match per line
                }
            }
        }
    }

    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multibyte_high_entropy_token_no_panic() {
        // A long high-entropy token containing a multi-byte char right at the
        // old 80-byte slice boundary must not panic (regression).
        let mut token = "A".repeat(78);
        token.push('产'); // 3 bytes, straddles byte index 78..81
        token.push_str(&"B".repeat(30));
        let content = format!("const x = \"{}\";", token);
        let _ = scan_advanced_obfuscation("app.js", &content);
    }

    #[test]
    fn test_calculate_entropy() {
        // Uniform string has 0 entropy
        assert_eq!(calculate_entropy(b"AAAA"), 0.0);
        // Random base64 has high entropy
        let data = b"4A9kLm3ZpQ1xW8vB7cE0yT6uR5oI2sN4gH9fD8aS3jK1lP0oI9uY8t";
        assert!(calculate_entropy(data) > 4.5);
    }

    #[test]
    fn test_zero_width_detection() {
        let content = "const secret = \"test\u{200B}hidden\";";
        let matches = scan_advanced_obfuscation("app.js", content);
        assert!(matches
            .iter()
            .any(|m| m.matched_pattern.contains("Zero-Width")));
    }

    #[test]
    fn test_trojan_source_detection() {
        let content = "/* \u{202E} } \u{2066} if (isAdmin) { */";
        let matches = scan_advanced_obfuscation("auth.py", content);
        assert!(matches
            .iter()
            .any(|m| m.matched_pattern.contains("Trojan Source")));
    }

    #[test]
    fn test_homoglyph_detection() {
        // Contains Cyrillic 'а' (\u{0430}) instead of Latin 'a'
        let content = "const p\u{0430}ssword = 'admin';";
        let matches = scan_advanced_obfuscation("index.js", content);
        assert!(matches
            .iter()
            .any(|m| m.matched_pattern.contains("Homoglyph")));
    }

    #[test]
    fn test_ordinary_unicode_text_is_not_flagged() {
        // Emoji ZWJ sequence, Persian ZWNJ, and a Russian UI string beside Latin code.
        let content = "const fam = \"👨\u{200D}👩\u{200D}👧\";\n\
                       const fa = \"می\u{200C}خواهم\";\n\
                       const msg = t(\"Сохранить файл\");";
        let matches = scan_advanced_obfuscation("i18n.js", content);
        assert!(
            !matches
                .iter()
                .any(|m| m.matched_pattern.contains("Zero-Width")
                    || m.matched_pattern.contains("Homoglyph")),
            "{:?}",
            matches
        );
    }

    #[test]
    fn test_high_entropy_detection() {
        // High entropy string with varied alphanumeric characters
        let content = "const payload = '4A9kLm3ZpQ1xW8vB7cE0yT6uR5oI2sN4gH9fD8aS3jK1lP0oI9uY8t7r6e5w4q3z2x1c';";
        let matches = scan_advanced_obfuscation("exploit.js", content);
        assert!(matches
            .iter()
            .any(|m| m.matched_pattern.contains("High-Entropy")));
    }
}
