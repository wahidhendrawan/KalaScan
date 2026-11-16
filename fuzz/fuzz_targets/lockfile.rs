#![no_main]
// Lockfiles of a scanned project: the first byte picks the format.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((pick, rest)) = data.split_first() else {
        return;
    };
    let names = kalascan::lockfile::LOCKFILES;
    let name = names[*pick as usize % names.len()];
    for locked in kalascan::lockfile::parse(name, &String::from_utf8_lossy(rest)) {
        let _ = locked.target();
    }
});
