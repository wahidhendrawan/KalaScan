#![no_main]
// Extension and package archives: zip (.vsix, .crx, .jar) and tar.gz (npm, sdist, .crate).
// Whatever the archive says, nothing may be written outside the destination.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let outer = tempfile::tempdir().unwrap();
    let dest = outer.path().join("dest");
    std::fs::create_dir(&dest).unwrap();
    let _ = kalascan::vsix::extract_zip(data, &dest);
    let _ = kalascan::vsix::extract_tar_gz(data, &dest);
    let escaped: Vec<_> = std::fs::read_dir(outer.path())
        .unwrap()
        .flatten()
        .map(|e| e.file_name())
        .filter(|n| n != "dest")
        .collect();
    assert!(escaped.is_empty(), "extraction escaped the destination: {:?}", escaped);
});
