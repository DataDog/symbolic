use symbolic::common::{AsSelf, ByteView, SelfCell};
use symbolic::ppdb::{LineInfo, PortablePdb, PortablePdbCache, PortablePdbCacheConverter};

use crate::core::SymbolicStr;
use crate::utils::ForeignObject;

/// Line information for a single lookup result.
#[repr(C)]
pub struct SymbolicPortablePdbLineInfo {
    pub line: u32,
    pub file_name: SymbolicStr,
    pub file_lang: SymbolicStr,
}

/// The result of a PortablePdbCache lookup.
///
/// `len` is `0` if the lookup found no matching line information, and `1` otherwise. This
/// mirrors `SymbolicProguardRemapResult`'s array convention rather than using a separate
/// found/not-found flag.
#[repr(C)]
pub struct SymbolicPortablePdbLookupResult {
    pub items: *mut SymbolicPortablePdbLineInfo,
    pub len: usize,
}

fn lookup_result_of(line_info: Option<LineInfo<'_>>) -> SymbolicPortablePdbLookupResult {
    let mut items: Vec<_> = line_info
        .into_iter()
        .map(|line_info| SymbolicPortablePdbLineInfo {
            line: line_info.line,
            file_name: line_info.file_name.to_owned().into(),
            file_lang: line_info.file_lang.name().to_owned().into(),
        })
        .collect();

    items.shrink_to_fit();
    let rv = SymbolicPortablePdbLookupResult {
        items: items.as_mut_ptr(),
        len: items.len(),
    };
    std::mem::forget(items);
    rv
}

struct CacheInner<'a> {
    cache: PortablePdbCache<'a>,
}

impl<'slf, 'a: 'slf> AsSelf<'slf> for CacheInner<'a> {
    type Ref = CacheInner<'slf>;

    fn as_self(&'slf self) -> &'slf Self::Ref {
        self
    }
}

pub struct OwnedPortablePdbCache<'a> {
    inner: SelfCell<ByteView<'a>, CacheInner<'a>>,
}

/// Represents a PortablePdbCache.
pub struct SymbolicPortablePdbCache;

impl ForeignObject for SymbolicPortablePdbCache {
    type RustObject = OwnedPortablePdbCache<'static>;
}

ffi_fn! {
    /// Builds a PortablePdbCache from the bytes of a raw Portable PDB file.
    ///
    /// The resulting object holds the compiled binary representation in memory. Use
    /// `symbolic_portablepdbcache_get_bytes` / `symbolic_portablepdbcache_get_size` to retrieve
    /// those bytes for upload to blob storage, then free the object with
    /// `symbolic_portablepdbcache_free`. To load a previously-compiled cache use
    /// `symbolic_portablepdbcache_open` instead.
    unsafe fn symbolic_portablepdbcache_from_portable_pdb(
        bytes: *const u8,
        len: usize,
    ) -> Result<*mut SymbolicPortablePdbCache> {
        let data = std::slice::from_raw_parts(bytes, len);
        let pdb = PortablePdb::parse(data)?;

        let mut converter = PortablePdbCacheConverter::new();
        converter.process_portable_pdb(&pdb)?;
        let mut buf: Vec<u8> = Vec::new();
        converter.serialize(&mut buf)?;

        let byteview = ByteView::from_vec(buf);
        let inner = SelfCell::try_new(byteview, |data| {
            PortablePdbCache::parse(unsafe { &*data })
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + 'static>)
                .map(|cache| CacheInner { cache })
        })?;
        Ok(SymbolicPortablePdbCache::from_rust(OwnedPortablePdbCache { inner }))
    }
}

ffi_fn! {
    /// Parses a PortablePdbCache from its binary representation without taking ownership of the
    /// pointer.
    ///
    /// The cache borrows `bytes` for its entire lifetime; it is not copied. The caller must keep
    /// the buffer alive and at a fixed address until the cache is released with
    /// `symbolic_portablepdbcache_free`.
    unsafe fn symbolic_portablepdbcache_open(
        bytes: *const u8,
        len: usize,
    ) -> Result<*mut SymbolicPortablePdbCache> {
        let byteview = ByteView::from_slice(std::slice::from_raw_parts(bytes, len));
        let inner = SelfCell::try_new(byteview, |data| {
            // SAFETY: data points into the ByteView we just created, which borrows the
            // caller's buffer.
            PortablePdbCache::parse(unsafe { &*data })
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + 'static>)
                .map(|cache| CacheInner { cache })
        })?;
        Ok(SymbolicPortablePdbCache::from_rust(OwnedPortablePdbCache { inner }))
    }
}

ffi_fn! {
    /// Returns a pointer to the raw bytes of the PortablePdbCache binary.
    ///
    /// The pointer is valid for the lifetime of the cache object. Use
    /// `symbolic_portablepdbcache_get_size` for the byte count.
    unsafe fn symbolic_portablepdbcache_get_bytes(
        cache: *const SymbolicPortablePdbCache,
    ) -> Result<*const u8> {
        Ok(SymbolicPortablePdbCache::as_rust(cache).inner.owner().as_slice().as_ptr())
    }
}

ffi_fn! {
    /// Returns the size in bytes of the PortablePdbCache binary.
    unsafe fn symbolic_portablepdbcache_get_size(
        cache: *const SymbolicPortablePdbCache,
    ) -> Result<usize> {
        Ok(SymbolicPortablePdbCache::as_rust(cache).inner.owner().len())
    }
}

ffi_fn! {
    /// Frees a PortablePdbCache.
    unsafe fn symbolic_portablepdbcache_free(cache: *mut SymbolicPortablePdbCache) {
        SymbolicPortablePdbCache::drop(cache);
    }
}

ffi_fn! {
    /// Looks up line information for a (method token, IL offset) coordinate.
    ///
    /// `func_idx` is the (1-based) index of the function in the ECMA-335 `MethodDef` table, as
    /// encoded in .NET's `MemberInfo.MetadataToken`. `il_offset` is the offset from the start of
    /// the method's Intermediate Language code, as obtained via `StackFrame.GetILOffset`.
    ///
    /// Returns a result with `len == 0` if no line information is found for this coordinate. Use
    /// `symbolic_portablepdbcache_lookup_first` when no IL offset is available at all. Free the
    /// result with `symbolic_portablepdbcache_lookup_result_free`.
    unsafe fn symbolic_portablepdbcache_lookup(
        cache: *const SymbolicPortablePdbCache,
        func_idx: u32,
        il_offset: u32,
    ) -> Result<SymbolicPortablePdbLookupResult> {
        let cache = &SymbolicPortablePdbCache::as_rust(cache).inner.get().cache;
        Ok(lookup_result_of(cache.lookup(func_idx, il_offset)))
    }
}

ffi_fn! {
    /// Looks up line information for the first sequence point of a function, without an IL
    /// offset.
    ///
    /// Intended for frames that carry a method token but no meaningful IL offset (e.g. frames
    /// captured from ahead-of-time compiled code). Returns a result with `len == 0` if the
    /// function has no sequence points in the cache. Free the result with
    /// `symbolic_portablepdbcache_lookup_result_free`.
    unsafe fn symbolic_portablepdbcache_lookup_first(
        cache: *const SymbolicPortablePdbCache,
        func_idx: u32,
    ) -> Result<SymbolicPortablePdbLookupResult> {
        let cache = &SymbolicPortablePdbCache::as_rust(cache).inner.get().cache;
        Ok(lookup_result_of(cache.lookup_first(func_idx)))
    }
}

ffi_fn! {
    /// Frees a lookup result produced by `symbolic_portablepdbcache_lookup` or
    /// `symbolic_portablepdbcache_lookup_first`.
    unsafe fn symbolic_portablepdbcache_lookup_result_free(result: *mut SymbolicPortablePdbLookupResult) {
        if !result.is_null() {
            let result = &*result;
            if !result.items.is_null() {
                Vec::from_raw_parts(result.items, result.len, result.len);
            }
        }
    }
}
