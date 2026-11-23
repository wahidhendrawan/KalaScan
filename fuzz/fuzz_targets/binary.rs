#![no_main]
// PE / ELF / Mach-O triage and the bounded x86 emulator, on arbitrary bytes.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("sample.bin"), data).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
    let tree = kalascan::scanner::Tree::Package;
    let triage = kalascan::triage::analyze_directory(dir.path(), tree, &[], false);
    let report = runtime.block_on(triage);
    let _ = kalascan::emulate::analyze_triage(dir.path(), &report);
});
