use std::ffi::CStr;
use std::os::raw::c_char;

use symbolic::cfi::{CfiCache, CFICACHE_LATEST_VERSION};
use symbolic::common::ByteView;

use crate::debuginfo::SymbolicObject;
use crate::utils::ForeignObject;

/// Contains stack frame information (CFI) for an image.
pub struct SymbolicCfiCache;

#[cfg(test)]
mod tests {
    use super::*;
    use minidump_unwind::SymbolFile;
    use std::io::Cursor;
    use symbolic::debuginfo::Object;

    #[test]
    fn exported_native_pe_cfi_can_be_loaded_by_minidump_reader() {
        let object = Object::parse(include_bytes!(
            "../../symbolic-testutils/fixtures/windows/CrashWithException.exe"
        ))
        .unwrap();
        let generated = CfiCache::from_object(&object).unwrap();
        unsafe {
            let cache = SymbolicCfiCache::from_rust(generated);
            let bytes = std::slice::from_raw_parts(
                symbolic_cficache_get_bytes(cache),
                symbolic_cficache_get_size(cache),
            );
            assert!(bytes.starts_with(b"MODULE windows "));
            let loaded = CfiCache::from_bytes(ByteView::from_slice(bytes)).unwrap();
            SymbolFile::parse(Cursor::new(loaded.as_slice()), |_| ()).unwrap();
            symbolic_cficache_free(cache);
        }
    }

    #[test]
    fn malformed_module_record_is_rejected_by_symbol_parser() {
        let cache = CfiCache::from_bytes(ByteView::from_slice(b"MODULE windows broken\n"))
            .expect("recognized raw format");
        assert!(SymbolFile::parse(Cursor::new(cache.as_slice()), |_| ()).is_err());
    }
}

impl ForeignObject for SymbolicCfiCache {
    type RustObject = CfiCache<'static>;
}

ffi_fn! {
    /// Extracts call frame information (CFI) from an Object.
    unsafe fn symbolic_cficache_from_object(
        object: *const SymbolicObject,
    ) -> Result<*mut SymbolicCfiCache> {
        let object = SymbolicObject::as_rust(object).get();
        let cache = CfiCache::from_object(object)?;
        Ok(SymbolicCfiCache::from_rust(cache))
    }
}

ffi_fn! {
    /// Loads a CFI cache from the given path.
    unsafe fn symbolic_cficache_open(path: *const c_char) -> Result<*mut SymbolicCfiCache> {
        let byteview = ByteView::open(CStr::from_ptr(path).to_str()?)?;
        let cache = CfiCache::from_bytes(byteview)?;
        Ok(SymbolicCfiCache::from_rust(cache))
    }
}

ffi_fn! {
    /// Returns the file format version of the CFI cache.
    unsafe fn symbolic_cficache_get_version(cache: *const SymbolicCfiCache) -> Result<u32> {
        Ok(SymbolicCfiCache::as_rust(cache).version())
    }
}

ffi_fn! {
    /// Returns a pointer to the raw buffer of the CFI cache.
    unsafe fn symbolic_cficache_get_bytes(cache: *const SymbolicCfiCache) -> Result<*const u8> {
        Ok(SymbolicCfiCache::as_rust(cache).as_slice().as_ptr())
    }
}

ffi_fn! {
    /// Returns the size of the raw buffer of the CFI cache.
    unsafe fn symbolic_cficache_get_size(cache: *const SymbolicCfiCache) -> Result<usize> {
        Ok(SymbolicCfiCache::as_rust(cache).as_slice().len())
    }
}

ffi_fn! {
    /// Releases memory held by an unmanaged `SymbolicCfiCache` instance.
    unsafe fn symbolic_cficache_free(cache: *mut SymbolicCfiCache) {
        SymbolicCfiCache::drop(cache);
    }
}

ffi_fn! {
    /// Returns the latest CFI cache version.
    unsafe fn symbolic_cficache_latest_version() -> Result<u32> {
        Ok(CFICACHE_LATEST_VERSION)
    }
}
