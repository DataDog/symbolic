use std::str;
use std::sync::mpsc;
use std::time::Duration;

use symbolic_cfi::{AsciiCfiWriter, CfiCache, CfiErrorKind};
use symbolic_common::ByteView;
use symbolic_debuginfo::Object;
use symbolic_testutils::fixture;

use similar_asserts::assert_eq;

type Error = Box<dyn std::error::Error>;

#[test]
fn generated_cfi_roundtrips_exported_bytes() -> Result<(), Error> {
    for path in [
        "windows/CrashWithException.exe",
        "windows/crash.pdb",
        "windows/crash.sym",
        "linux/crash",
        "macos/crash",
    ] {
        let buffer = ByteView::open(fixture(path))?;
        let object = Object::parse(&buffer)?;
        let generated = CfiCache::from_object(&object)?;
        let exported = generated.as_slice();
        if path.ends_with(".exe") {
            assert!(exported.starts_with(b"MODULE windows "));
        }
        let raw = CfiCache::from_bytes(ByteView::from_slice(exported))?;
        assert_eq!(raw.as_slice(), exported);
        assert_eq!(raw.version(), 1);

        let mut serialized = Vec::new();
        generated.write_to(&mut serialized)?;
        let versioned = CfiCache::from_bytes(ByteView::from_slice(&serialized))?;
        assert_eq!(versioned.version(), generated.version());
        assert_eq!(versioned.as_slice(), exported);
    }
    Ok(())
}

#[test]
fn invalid_cfi_magic_is_rejected() {
    for input in [
        b"not a cache".as_slice(),
        b"MODULEwindows x86_64",
        b"MODULE ",
    ] {
        assert!(CfiCache::from_bytes(ByteView::from_slice(input)).is_err());
    }
}

#[test]
fn load_empty_cfi_cache() -> Result<(), Error> {
    let buffer = ByteView::from_slice(&[]);
    let cache = CfiCache::from_bytes(buffer)?;
    assert_eq!(cache.version(), 1);
    Ok(())
}

#[test]
fn cfi_from_elf() -> Result<(), Error> {
    let buffer = ByteView::open(fixture("linux/crash"))?;
    let object = Object::parse(&buffer)?;

    let buf: Vec<u8> = AsciiCfiWriter::transform(&object)?;
    let cfi = str::from_utf8(&buf)?;
    // NOTE: Breakpad's CFI writer outputs registers in alphabetical order. We
    // write the CFA register first, and then order by register number. Thus,
    // the output is not identical to `cfi_sym_linux`.
    insta::assert_snapshot!("cfi_elf", cfi);

    Ok(())
}

#[test]
fn cfi_from_macho() -> Result<(), Error> {
    let buffer = ByteView::open(fixture("macos/crash"))?;
    let object = Object::parse(&buffer)?;

    let buf: Vec<u8> = AsciiCfiWriter::transform(&object)?;
    let cfi = str::from_utf8(&buf)?;
    // NOTE: Breakpad's CFI writer outputs registers in alphabetical order. We
    // write the CFA register first, and then order by register number. Thus,
    // the output is not identical to `cfi_sym_macos`.
    insta::assert_snapshot!("cfi_macho", cfi);

    Ok(())
}

#[test]
fn cfi_from_sym_linux() -> Result<(), Error> {
    let buffer = ByteView::open(fixture("linux/crash.sym"))?;
    let object = Object::parse(&buffer)?;

    let buf: Vec<u8> = AsciiCfiWriter::transform(&object)?;
    let cfi = str::from_utf8(&buf)?;
    insta::assert_snapshot!("cfi_sym_linux", cfi);

    Ok(())
}

#[test]
fn cfi_from_sym_macos() -> Result<(), Error> {
    let buffer = ByteView::open(fixture("macos/crash.sym"))?;
    let object = Object::parse(&buffer)?;

    let buf: Vec<u8> = AsciiCfiWriter::transform(&object)?;
    let cfi = str::from_utf8(&buf)?;
    insta::assert_snapshot!("cfi_sym_macos", cfi);

    Ok(())
}

#[test]
fn cfi_from_sym_windows() -> Result<(), Error> {
    let buffer = ByteView::open(fixture("windows/crash.sym"))?;
    let object = Object::parse(&buffer)?;

    let buf: Vec<u8> = AsciiCfiWriter::transform(&object)?;
    let cfi = str::from_utf8(&buf)?;
    insta::assert_snapshot!("cfi_sym_windows", cfi);

    Ok(())
}

#[test]
fn cfi_from_pdb_windows() -> Result<(), Error> {
    let buffer = ByteView::open(fixture("windows/crash.pdb"))?;
    let object = Object::parse(&buffer)?;

    let buf: Vec<u8> = AsciiCfiWriter::transform(&object)?;
    let cfi = str::from_utf8(&buf)?;
    insta::assert_snapshot!("cfi_pdb_windows", cfi);

    Ok(())
}

#[test]
fn cfi_from_pe_windows() -> Result<(), Error> {
    let buffer = ByteView::open(fixture("windows/CrashWithException.exe"))?;
    let object = Object::parse(&buffer)?;

    let buf: Vec<u8> = AsciiCfiWriter::transform(&object)?;
    let cfi = str::from_utf8(&buf)?;
    insta::assert_snapshot!("cfi_pe_windows", cfi);

    Ok(())
}

#[test]
fn cfi_from_elf_arm64() -> Result<(), Error> {
    let buffer = ByteView::open(fixture("linux/arm64/cfi_test"))?;
    let object = Object::parse(&buffer)?;

    let buf: Vec<u8> = AsciiCfiWriter::transform(&object)?;
    let cfi = str::from_utf8(&buf)?;
    // Verify that .ra: x30 appears in INIT rows
    insta::assert_snapshot!("cfi_elf_arm64", cfi);

    Ok(())
}

#[test]
fn cfi_from_pe_arm64() -> Result<(), Error> {
    let buffer = ByteView::open(fixture("windows/arm64/test.exe"))?;
    let object = Object::parse(&buffer)?;

    let buf: Vec<u8> = AsciiCfiWriter::transform(&object)?;
    let cfi = str::from_utf8(&buf)?;
    // Verify that .ra: x30 appears in INIT rows
    insta::assert_snapshot!("cfi_pe_arm64", cfi);

    Ok(())
}

#[test]
fn cfi_process_pe_self_loop_terminates() {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let buffer = ByteView::open(fixture("windows/cfi_chained_loop.exe"))
            .expect("failed to open fixture");
        let object = Object::parse(&buffer).expect("failed to parse PE");

        let mut buf = Vec::new();
        let result = AsciiCfiWriter::new(&mut buf)
            .max_unwind_chain_len(Some(8))
            .process(&object)
            .map_err(|e| e.kind());
        let _ = tx.send(result);
    });

    match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(result) => assert_eq!(
            result,
            Err(CfiErrorKind::ExceededUnwindChainLength),
            "should be rejected once the limit is reached"
        ),
        Err(_) => panic!("process_pe did not terminate: loop is unbounded"),
    }
}
