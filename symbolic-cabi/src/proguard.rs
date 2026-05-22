use std::ffi::CStr;
use std::os::raw::c_char;

use symbolic::common::{AsSelf, ByteView, SelfCell};

use crate::core::{SymbolicStr, SymbolicUuid};
use crate::utils::ForeignObject;

use proguard::{ProguardCache, ProguardMapper, ProguardMapping, StackFrame};

/// Represents a Java Stack Frame.
#[repr(C)]
pub struct SymbolicJavaStackFrame {
    pub class_name: SymbolicStr,
    pub method: SymbolicStr,
    pub file: SymbolicStr,
    pub line: usize,
    pub parameters: SymbolicStr,
}

/// The result of remapping a Stack Frame.
#[repr(C)]
pub struct SymbolicProguardRemapResult {
    pub frames: *mut SymbolicJavaStackFrame,
    pub len: usize,
}

struct Inner<'a> {
    mapping: ProguardMapping<'a>,
    mapper: ProguardMapper<'a>,
}

impl<'slf, 'a: 'slf> AsSelf<'slf> for Inner<'a> {
    type Ref = Inner<'slf>;

    fn as_self(&'slf self) -> &'slf Self::Ref {
        self
    }
}

pub struct OwnedProguardMapper<'a> {
    inner: SelfCell<ByteView<'a>, Inner<'a>>,
}

/// Represents a proguard mapper.
pub struct SymbolicProguardMapper;

impl ForeignObject for SymbolicProguardMapper {
    type RustObject = OwnedProguardMapper<'static>;
}

ffi_fn! {
    /// Creates a proguard mapping view from a path.
    unsafe fn symbolic_proguardmapper_open(
        path: *const c_char,
        initialize_param_mapping: bool
    ) -> Result<*mut SymbolicProguardMapper> {
        let byteview = ByteView::open(CStr::from_ptr(path).to_str()?)?;

        let inner = SelfCell::new(byteview, |data| {
            let mapping = ProguardMapping::new(&*data);
            let mapper = if !initialize_param_mapping {
                ProguardMapper::new(mapping)
            } else {
                ProguardMapper::new_with_param_mapping(mapping, initialize_param_mapping)
            };
            Inner { mapping, mapper }
        });

        let proguard = OwnedProguardMapper { inner };
        Ok(SymbolicProguardMapper::from_rust(proguard))
    }
}

ffi_fn! {
    /// Frees a proguard mapping view.
    unsafe fn symbolic_proguardmapper_free(mapper: *mut SymbolicProguardMapper) {
        SymbolicProguardMapper::drop(mapper);
    }
}

ffi_fn! {
    /// Remaps a Stack Frame.
    unsafe fn symbolic_proguardmapper_remap_frame(
        mapper: *const SymbolicProguardMapper,
        class: *const SymbolicStr,
        method: *const SymbolicStr,
        line: usize,
        parameters: *const SymbolicStr,
        use_parameters: bool,
    ) -> Result<SymbolicProguardRemapResult> {
        let mapper = &SymbolicProguardMapper::as_rust(mapper).inner.get().mapper;
        let frame = if use_parameters {
            StackFrame::with_parameters((*class).as_str(), (*method).as_str(), (*parameters).as_str())
        } else {
            StackFrame::new((*class).as_str(), (*method).as_str(), line)
        };

        let mut frames: Vec<_> = mapper.remap_frame(&frame).map(|frame| {
            SymbolicJavaStackFrame {
                class_name: frame.class().to_owned().into(),
                method: frame.method().to_owned().into(),
                file: frame.file().unwrap_or("").to_owned().into(),
                line: frame.line().unwrap_or(0),
                parameters: frame.parameters().unwrap_or("").to_owned().into(),
            }
        }).collect();

        frames.shrink_to_fit();
        let rv = SymbolicProguardRemapResult {
            frames: frames.as_mut_ptr(),
            len: frames.len(),
        };
        std::mem::forget(frames);

        Ok(rv)
    }
}

ffi_fn! {
    /// Remaps a class name.
    unsafe fn symbolic_proguardmapper_remap_class(
        mapper: *const SymbolicProguardMapper,
        class: *const SymbolicStr,
    ) -> Result<SymbolicStr> {
        let mapper = &SymbolicProguardMapper::as_rust(mapper).inner.get().mapper;

        let class = (*class).as_str();
        Ok(mapper.remap_class(class).unwrap_or("").to_owned().into())
    }
}

ffi_fn! {
    /// Remaps a class name.
    unsafe fn symbolic_proguardmapper_remap_method(
        mapper: *const SymbolicProguardMapper,
        class: *const SymbolicStr,
        method: *const SymbolicStr,
    ) -> Result<SymbolicProguardRemapResult> {
        let mapper = &SymbolicProguardMapper::as_rust(mapper).inner.get().mapper;

        let class = (*class).as_str();
        let method = (*method).as_str();

        let (remapped_class, remapped_method) =
        mapper.remap_method(class, method).unwrap_or_default();

        let mut frames = vec![SymbolicJavaStackFrame {
            class_name: remapped_class.to_owned().into(),
            method: remapped_method.to_owned().into(),
            file: "".to_owned().into(),
            line: 0,
            parameters: "".to_owned().into(),
        }];

        frames.shrink_to_fit();
        let rv = SymbolicProguardRemapResult {
            frames: frames.as_mut_ptr(),
            len: frames.len(),
        };
        std::mem::forget(frames);

        Ok(rv)
    }
}

ffi_fn! {
    /// Returns the UUID of a proguard mapping file.
    unsafe fn symbolic_proguardmapper_get_uuid(
        mapper: *mut SymbolicProguardMapper,
    ) -> Result<SymbolicUuid> {
        Ok(SymbolicProguardMapper::as_rust(mapper).inner.get().mapping.uuid().into())
    }
}

ffi_fn! {
    /// Returns true if the mapping file has line infos.
    unsafe fn symbolic_proguardmapper_has_line_info(
        mapper: *const SymbolicProguardMapper,
    ) -> Result<bool> {
        Ok(SymbolicProguardMapper::as_rust(mapper).inner.get().mapping.has_line_info())
    }
}

ffi_fn! {
    /// Frees a remap result.
    unsafe fn symbolic_proguardmapper_result_free(result: *mut SymbolicProguardRemapResult) {
        if !result.is_null() {
            let result = &*result;
            Vec::from_raw_parts(result.frames, result.len, result.len);
        }
    }
}

// ── ProguardCache ─────────────────────────────────────────────────────────────

struct CacheInner<'a> {
    cache: ProguardCache<'a>,
}

impl<'slf, 'a: 'slf> AsSelf<'slf> for CacheInner<'a> {
    type Ref = CacheInner<'slf>;

    fn as_self(&'slf self) -> &'slf Self::Ref {
        self
    }
}

pub struct OwnedProguardCache<'a> {
    inner: SelfCell<ByteView<'a>, CacheInner<'a>>,
}

/// Represents a ProguardCache.
pub struct SymbolicProguardCache;

impl ForeignObject for SymbolicProguardCache {
    type RustObject = OwnedProguardCache<'static>;
}

ffi_fn! {
    /// Parses a ProguardCache from its binary representation.
    unsafe fn symbolic_proguardcache_open(
        bytes: *const u8,
        len: usize,
    ) -> Result<*mut SymbolicProguardCache> {
        let byteview = ByteView::from_vec(std::slice::from_raw_parts(bytes, len).to_vec());
        let inner = SelfCell::try_new(byteview, |data| {
            // SAFETY: data points into the ByteView we just created.
            ProguardCache::parse(unsafe { &*data })
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + 'static>)
                .map(|cache| CacheInner { cache })
        })?;
        Ok(SymbolicProguardCache::from_rust(OwnedProguardCache { inner }))
    }
}

ffi_fn! {
    /// Frees a ProguardCache.
    unsafe fn symbolic_proguardcache_free(cache: *mut SymbolicProguardCache) {
        SymbolicProguardCache::drop(cache);
    }
}

ffi_fn! {
    /// Runs the integrity check on a ProguardCache. Panics (caught by the FFI
    /// landing pad) if the cache is corrupt.
    unsafe fn symbolic_proguardcache_test(cache: *const SymbolicProguardCache) {
        SymbolicProguardCache::as_rust(cache).inner.get().cache.test();
    }
}

ffi_fn! {
    /// Remaps an obfuscated stacktrace using the ProguardCache.
    unsafe fn symbolic_proguardcache_remap_stacktrace(
        cache: *const SymbolicProguardCache,
        stacktrace: *const SymbolicStr,
    ) -> Result<SymbolicStr> {
        let cache = &SymbolicProguardCache::as_rust(cache).inner.get().cache;
        let result = cache.remap_stacktrace((*stacktrace).as_str())?;
        Ok(result.into())
    }
}
