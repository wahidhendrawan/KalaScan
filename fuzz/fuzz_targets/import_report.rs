#![no_main]
// Scanner reports (Nessus, Nmap, Burp, ZAP, Nuclei, Qualys, CSV) come from other tools' output files.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = kalascan::import::parse(&String::from_utf8_lossy(data));
});
