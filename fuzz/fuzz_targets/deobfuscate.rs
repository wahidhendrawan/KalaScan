#![no_main]
// Recursive decoding (base64, hex, XOR, gzip, zlib, ...) of a scanned script.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("payload.js"), data).unwrap();
    let _ = kalascan::deobfuscate::analyze_directory(dir.path(), kalascan::scanner::Tree::Package);
});
