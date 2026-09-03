use std::collections::HashMap;
use std::path::PathBuf;
use std::slice;

use futures_executor::block_on;
use minidump::{Minidump, MinidumpModuleList, MinidumpSystemInfo, Module};
use minidump_processor::process_minidump;
use minidump_unwind::symbols::{
    FileError, FileKind, FillSymbolError, FrameSymbolizer, FrameWalker, SymbolProvider, SymbolStats,
};
use serde::Serialize;
use symbolic::common::DebugId;
use symbolic::symcache::SymCache;

use crate::core::SymbolicStr;

/// One request-scoped symbolic symcache supplied by the caller.
#[repr(C)]
pub struct SymbolicMinidumpSymCache {
    /// Complete serialized symbolic symcache contents.
    pub contents: *const u8,
    /// Number of bytes in `contents`.
    pub contents_len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MinidumpErrorKind {
    InvalidArgument,
    InvalidMinidump,
    InvalidSymbols,
    Internal,
}

#[derive(Debug)]
pub(crate) struct MinidumpError {
    kind: MinidumpErrorKind,
    message: String,
}

impl MinidumpError {
    fn new(kind: MinidumpErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub(crate) fn kind(&self) -> MinidumpErrorKind {
        self.kind
    }
}

impl std::fmt::Display for MinidumpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for MinidumpError {}

#[derive(Debug, Serialize)]
struct Inspection {
    os: String,
    cpu: String,
    modules: Vec<ModuleInfo>,
}

#[derive(Debug, Serialize)]
struct ModuleInfo {
    code_file: String,
    code_id: Option<String>,
    debug_file: Option<String>,
    debug_id: Option<String>,
    breakpad_id: Option<String>,
    base_address: u64,
    size: u64,
}

struct SymCacheInput<'a> {
    contents: &'a [u8],
}

struct InMemorySymCacheProvider<'a> {
    caches: HashMap<DebugId, SymCache<'a>>,
    stats: HashMap<String, SymbolStats>,
}

#[async_trait::async_trait]
impl SymbolProvider for InMemorySymCacheProvider<'_> {
    async fn fill_symbol(
        &self,
        module: &(dyn Module + Sync),
        frame: &mut (dyn FrameSymbolizer + Send),
    ) -> Result<(), FillSymbolError> {
        let debug_id = module.debug_identifier().ok_or(FillSymbolError {})?;
        let cache = self.caches.get(&debug_id).ok_or(FillSymbolError {})?;
        let relative_address = frame
            .get_instruction()
            .checked_sub(module.base_address())
            .ok_or(FillSymbolError {})?;
        let locations = cache.lookup(relative_address).collect::<Vec<_>>();
        let outermost = locations.last().ok_or(FillSymbolError {})?;
        let outermost_function = outermost.function();
        let function_base = module.base_address() + u64::from(outermost_function.entry_pc());

        frame.set_function(outermost_function.name(), function_base, 0);
        if let Some(file) = outermost.file() {
            frame.set_source_file(&file.full_path(), outermost.line(), function_base);
        }

        for inline in locations[..locations.len() - 1].iter().rev() {
            let file = inline.file().map(|file| file.full_path());
            let line = (inline.line() != 0).then(|| inline.line());
            frame.add_inline_frame(inline.function().name(), file.as_deref(), line);
        }
        Ok(())
    }

    async fn walk_frame(
        &self,
        _module: &(dyn Module + Sync),
        _walker: &mut (dyn FrameWalker + Send),
    ) -> Option<()> {
        // Symcaches contain symbol and source mappings, but not unwind CFI.
        None
    }

    async fn get_file_path(
        &self,
        _module: &(dyn Module + Sync),
        _file_kind: FileKind,
    ) -> Result<PathBuf, FileError> {
        Err(FileError::NotFound)
    }

    fn stats(&self) -> HashMap<String, SymbolStats> {
        self.stats.clone()
    }
}

fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn inspect(dump: &[u8]) -> Result<String, MinidumpError> {
    let dump = Minidump::read(dump).map_err(|error| {
        MinidumpError::new(MinidumpErrorKind::InvalidMinidump, error.to_string())
    })?;
    let system_info = dump.get_stream::<MinidumpSystemInfo>().map_err(|error| {
        MinidumpError::new(MinidumpErrorKind::InvalidMinidump, error.to_string())
    })?;
    let module_list = dump.get_stream::<MinidumpModuleList>().map_err(|error| {
        MinidumpError::new(MinidumpErrorKind::InvalidMinidump, error.to_string())
    })?;

    let mut modules = module_list
        .iter()
        .map(|module| {
            let debug_id = module.debug_identifier();
            ModuleInfo {
                code_file: module.code_file().into_owned(),
                code_id: module
                    .code_identifier()
                    .map(|identifier| identifier.to_string()),
                debug_file: module.debug_file().map(|file| file.into_owned()),
                debug_id: debug_id.map(|identifier| identifier.to_string()),
                breakpad_id: debug_id.map(|identifier| identifier.breakpad().to_string()),
                base_address: module.base_address(),
                size: module.size(),
            }
        })
        .collect::<Vec<_>>();
    modules.sort_unstable_by_key(|module| module.base_address);

    serde_json::to_string(&Inspection {
        os: system_info.os.to_string(),
        cpu: system_info.cpu.to_string(),
        modules,
    })
    .map_err(|error| MinidumpError::new(MinidumpErrorKind::Internal, error.to_string()))
}

fn process(dump_bytes: &[u8], symcaches: &[SymCacheInput<'_>]) -> Result<String, MinidumpError> {
    let dump = Minidump::read(dump_bytes).map_err(|error| {
        MinidumpError::new(MinidumpErrorKind::InvalidMinidump, error.to_string())
    })?;
    let modules = dump.get_stream::<MinidumpModuleList>().map_err(|error| {
        MinidumpError::new(MinidumpErrorKind::InvalidMinidump, error.to_string())
    })?;

    let mut caches_by_debug_id = HashMap::with_capacity(symcaches.len());
    for supplied in symcaches {
        let cache = SymCache::parse(supplied.contents).map_err(|error| {
            MinidumpError::new(
                MinidumpErrorKind::InvalidSymbols,
                format!("invalid symcache: {error}"),
            )
        })?;
        let debug_id = cache.debug_id();

        let matches_module = modules
            .iter()
            .any(|module| module.debug_identifier() == Some(debug_id));
        if !matches_module {
            return Err(MinidumpError::new(
                MinidumpErrorKind::InvalidSymbols,
                format!("symcache debug ID {debug_id} did not match a minidump module"),
            ));
        }

        if caches_by_debug_id.insert(debug_id, cache).is_some() {
            return Err(MinidumpError::new(
                MinidumpErrorKind::InvalidSymbols,
                format!("duplicate symcache debug ID {debug_id}"),
            ));
        }
    }

    let stats = modules
        .iter()
        .map(|module| {
            let loaded_symbols = module
                .debug_identifier()
                .is_some_and(|debug_id| caches_by_debug_id.contains_key(&debug_id));
            (
                basename(&module.code_file()).to_owned(),
                SymbolStats {
                    loaded_symbols,
                    ..SymbolStats::default()
                },
            )
        })
        .collect();
    let provider = InMemorySymCacheProvider {
        caches: caches_by_debug_id,
        stats,
    };
    let state = block_on(process_minidump(&dump, &provider)).map_err(|error| {
        MinidumpError::new(MinidumpErrorKind::InvalidMinidump, error.to_string())
    })?;
    let mut json = Vec::new();
    state
        .print_json(&mut json, false)
        .map_err(|error| MinidumpError::new(MinidumpErrorKind::Internal, error.to_string()))?;
    String::from_utf8(json)
        .map_err(|error| MinidumpError::new(MinidumpErrorKind::Internal, error.to_string()))
}

unsafe fn borrowed_bytes<'a>(
    data: *const u8,
    len: usize,
    field: &str,
) -> Result<&'a [u8], MinidumpError> {
    if data.is_null() || len == 0 {
        return Err(MinidumpError::new(
            MinidumpErrorKind::InvalidSymbols,
            format!("{field} must not be empty"),
        ));
    }
    Ok(slice::from_raw_parts(data, len))
}

ffi_fn! {
    /// Inspects minidump bytes and returns system and loaded-module metadata as JSON.
    ///
    /// The input is borrowed for this synchronous call. The returned string is
    /// owned and must be released with `symbolic_str_free`.
    unsafe fn symbolic_minidump_inspect(
        dump: *const u8,
        dump_len: usize,
    ) -> Result<SymbolicStr> {
        if dump.is_null() || dump_len == 0 {
            return Err(MinidumpError::new(
                MinidumpErrorKind::InvalidArgument,
                "minidump input must not be empty",
            ).into());
        }

        let dump = slice::from_raw_parts(dump, dump_len);
        Ok(inspect(dump)?.into())
    }
}

ffi_fn! {
    /// Processes minidump bytes with request-scoped symbolic symcaches.
    ///
    /// Missing symcaches are allowed and produce a partial stackwalk. Every
    /// supplied symcache must match a loaded module by its embedded debug
    /// identifier. All input pointers are borrowed for this synchronous call.
    /// The returned JSON string is owned and must be released with
    /// `symbolic_str_free`.
    unsafe fn symbolic_minidump_process(
        dump: *const u8,
        dump_len: usize,
        symcaches: *const SymbolicMinidumpSymCache,
        symcaches_len: usize,
    ) -> Result<SymbolicStr> {
        if dump.is_null() || dump_len == 0 || (symcaches.is_null() && symcaches_len != 0) {
            return Err(MinidumpError::new(
                MinidumpErrorKind::InvalidArgument,
                "minidump input is empty or the symcache array is invalid",
            ).into());
        }

        let dump = slice::from_raw_parts(dump, dump_len);
        let native_symcaches = if symcaches_len == 0 {
            &[]
        } else {
            slice::from_raw_parts(symcaches, symcaches_len)
        };
        let symcaches = native_symcaches
            .iter()
            .map(|symcache| {
                Ok(SymCacheInput {
                    contents: borrowed_bytes(
                        symcache.contents,
                        symcache.contents_len,
                        "symcache contents",
                    )?,
                })
            })
            .collect::<Result<Vec<_>, MinidumpError>>()?;
        Ok(process(dump, &symcaches)?.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::io::Cursor;
    use std::ptr;
    use symbolic::debuginfo::Object;
    use symbolic::symcache::SymCacheConverter;

    const CRASH_LINUX: &[u8] = include_bytes!("../../py/tests/res/minidump/crash_linux.dmp");

    fn symcache_from_breakpad(contents: &[u8]) -> Vec<u8> {
        let object = Object::parse(contents).expect("Breakpad fixture must parse");
        let mut converter = SymCacheConverter::new();
        converter
            .process_object(&object)
            .expect("Breakpad fixture must convert");
        let mut symcache = Vec::new();
        converter
            .serialize(&mut Cursor::new(&mut symcache))
            .expect("symcache must serialize");
        symcache
    }

    #[test]
    fn inspect_rejects_invalid_bytes() {
        let error = inspect(b"not a minidump").unwrap_err();
        assert_eq!(error.kind(), MinidumpErrorKind::InvalidMinidump);
    }

    #[test]
    fn inspect_returns_system_and_modules() {
        let json = inspect(CRASH_LINUX).expect("fixture must be a valid minidump");
        let inspection: Value = serde_json::from_str(&json).expect("inspection must be JSON");

        assert!(inspection["os"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        assert!(inspection["cpu"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        assert!(inspection["modules"]
            .as_array()
            .is_some_and(|value| !value.is_empty()));
        assert!(inspection["modules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|module| module["breakpad_id"].as_str().is_some()));
    }

    #[test]
    fn process_returns_stable_json_without_symbols() {
        let json = process(CRASH_LINUX, &[]).expect("fixture must be stackwalkable");
        let report: Value = serde_json::from_str(&json).expect("stackwalk result must be JSON");

        assert_eq!(report["status"], "OK");
        assert!(report["threads"].is_array());
        assert!(report["modules"].is_array());
    }

    #[test]
    fn process_symbolicates_with_matching_in_memory_symbols() {
        let dump = Minidump::read(CRASH_LINUX).expect("fixture must be a valid minidump");
        let system_info = dump
            .get_stream::<MinidumpSystemInfo>()
            .expect("fixture must contain system info");
        let modules = dump
            .get_stream::<MinidumpModuleList>()
            .expect("fixture must contain modules");
        let module = modules
            .iter()
            .find(|module| basename(&module.code_file()) == "crash_linux")
            .expect("fixture must contain crash_linux");
        let debug_file = module.debug_file().unwrap().into_owned();

        let baseline = process(CRASH_LINUX, &[]).expect("fixture must be stackwalkable");
        let baseline: Value = serde_json::from_str(&baseline).expect("stackwalk must be JSON");
        let frame = &baseline["crashing_thread"]["frames"][0];
        assert_eq!(basename(frame["module"].as_str().unwrap()), "crash_linux");
        let module_offset = frame["module_offset"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x");
        let contents = format!(
            "MODULE {} {} {} {}\nFILE 0 crash_linux.cc\nFUNC {module_offset} 100 0 expected_crash_function\n{module_offset} 100 42 0\n",
            system_info.os,
            system_info.cpu,
            module.debug_identifier().unwrap().breakpad(),
            basename(&debug_file),
        );

        let symcache = symcache_from_breakpad(contents.as_bytes());
        let json = process(
            CRASH_LINUX,
            &[SymCacheInput {
                contents: &symcache,
            }],
        )
        .expect("matching in-memory symcache must be accepted");
        let report: Value = serde_json::from_str(&json).expect("stackwalk result must be JSON");
        assert_eq!(
            report["crashing_thread"]["frames"][0]["function"],
            "expected_crash_function"
        );
        assert_eq!(
            report["crashing_thread"]["frames"][0]["file"],
            "crash_linux.cc"
        );
        assert_eq!(report["crashing_thread"]["frames"][0]["line"], 42);
    }

    #[test]
    fn process_rejects_invalid_symbol_array() {
        let result = unsafe {
            symbolic_minidump_process(CRASH_LINUX.as_ptr(), CRASH_LINUX.len(), ptr::null(), 1)
        };
        assert!(result.data.is_null());
        assert!(matches!(
            unsafe { crate::core::symbolic_err_get_last_code() },
            crate::core::SymbolicErrorCode::MinidumpInvalidArgument
        ));
        unsafe { crate::core::symbolic_err_clear() };
    }

    #[test]
    fn process_classifies_invalid_symcache() {
        let invalid_contents = b"not a symcache";
        let symcache = SymbolicMinidumpSymCache {
            contents: invalid_contents.as_ptr(),
            contents_len: invalid_contents.len(),
        };
        let result = unsafe {
            symbolic_minidump_process(CRASH_LINUX.as_ptr(), CRASH_LINUX.len(), &symcache, 1)
        };
        assert!(result.data.is_null());
        assert!(matches!(
            unsafe { crate::core::symbolic_err_get_last_code() },
            crate::core::SymbolicErrorCode::MinidumpInvalidSymbols
        ));
        let message = unsafe {
            crate::core::symbolic_err_get_last_message()
                .as_str()
                .to_owned()
        };
        assert!(message.contains("invalid symcache"));
        unsafe { crate::core::symbolic_err_clear() };
    }
}
