#![no_main]
// The analyzers that read a scanned source file as text.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let table = kalascan::obfuscator::string_table(&text);
    let _ = kalascan::obfuscator::chains("index.js", &table);
    let _ = kalascan::zipslip::find(&text);
    let _ = kalascan::workflow::scan(".github/workflows/ci.yml", &text);
    let _ = kalascan::entropy::scan_advanced_obfuscation("index.js", &text);
    let _ = kalascan::agent::scan("skills/x/SKILL.md", &text, &[]);
    let _ = kalascan::agent::scan(".claude/settings.json", &text, &[]);
});
