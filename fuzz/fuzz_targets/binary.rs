#![no_main]
// PE / ELF / Mach-O triage and the bounded x86 emulator, on arbitrary bytes.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("sample.bin"), data).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
    let report = runtime.block_on(kalascan::triage::analyze_directory(dir.path(), &[], false));
    let _ = kalascan::emulate::analyze_triage(dir.path(), &report);
});
