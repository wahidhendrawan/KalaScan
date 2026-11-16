#![no_main]
// Sandbox output: the traced sample influences what strace prints.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = kalascan::sandbox::parse_strace(&String::from_utf8_lossy(data));
});
