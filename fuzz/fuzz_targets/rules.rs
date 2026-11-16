#![no_main]
// `--rules FILE`: a rule file may be handed over by someone else.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = kalascan::scanner::parse_rules(&String::from_utf8_lossy(data));
});
