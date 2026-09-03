use std::collections::HashMap;
use std::path::PathBuf;
use std::slice;
use std::str;

use breakpad_symbols::{
    FileError, FileKind, LocateSymbolsResult, SymbolError, SymbolFile, SymbolSupplier, Symbolizer,
};
use futures_executor::block_on;
use minidump::{Minidump, MinidumpModuleList, MinidumpSystemInfo, Module};
use minidump_processor::process_minidump;
use serde::Serialize;
use symbolic::common::DebugId;

use crate::core::SymbolicStr;

/// One request-scoped Breakpad symbol file supplied by the caller.
#[repr(C)]
pub struct SymbolicMinidumpSymbol {
    /// UTF-8 debug file name used to match a minidump module.
    pub debug_file: *const u8,
    /// Number of bytes in `debug_file`.
    pub debug_file_len: usize,
    /// UTF-8 Breakpad debug identifier used to match a minidump module.
    pub debug_id: *const u8,
    /// Number of bytes in `debug_id`.
    pub debug_id_len: usize,
    /// Complete UTF-8 Breakpad `.sym` contents.
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
    base_address: u64,
    size: u64,
}

struct SymbolInput<'a> {
    debug_file: &'a str,
    debug_id: &'a str,
    contents: &'a str,
}

#[derive(Eq, Hash, PartialEq)]
struct SymbolKey {
    debug_file: String,
    debug_id: String,
}

struct InMemorySymbolSupplier {
    symbols: HashMap<SymbolKey, String>,
}

#[async_trait::async_trait]
impl SymbolSupplier for InMemorySymbolSupplier {
    async fn locate_symbols(
        &self,
        module: &(dyn Module + Sync),
    ) -> Result<LocateSymbolsResult, SymbolError> {
        let debug_file = module.debug_file().ok_or(SymbolError::NotFound)?;
        let debug_id = module.debug_identifier().ok_or(SymbolError::NotFound)?;
        let key = SymbolKey {
            debug_file: normalize_debug_file(&debug_file),
            debug_id: debug_id.breakpad().to_string(),
        };
        let contents = self.symbols.get(&key).ok_or(SymbolError::NotFound)?;
        Ok(LocateSymbolsResult {
            symbols: SymbolFile::from_bytes(contents.as_bytes())?,
            extra_debug_info: None,
        })
    }

    async fn locate_file(
        &self,
        _module: &(dyn Module + Sync),
        _file_kind: FileKind,
    ) -> Result<PathBuf, FileError> {
        Err(FileError::NotFound)
    }
}

fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn normalize_debug_file(path: &str) -> String {
    basename(path).to_ascii_lowercase()
}

fn parse_debug_id(debug_id: &str) -> Result<DebugId, debugid::ParseDebugIdError> {
    DebugId::from_breakpad(debug_id).or_else(|_| debug_id.parse())
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
        .map(|module| ModuleInfo {
            code_file: module.code_file().into_owned(),
            code_id: module
                .code_identifier()
                .map(|identifier| identifier.to_string()),
            debug_file: module.debug_file().map(|file| file.into_owned()),
            debug_id: module
                .debug_identifier()
                .map(|identifier| identifier.to_string()),
            base_address: module.base_address(),
            size: module.size(),
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

fn process(dump_bytes: &[u8], symbols: &[SymbolInput<'_>]) -> Result<String, MinidumpError> {
    let dump = Minidump::read(dump_bytes).map_err(|error| {
        MinidumpError::new(MinidumpErrorKind::InvalidMinidump, error.to_string())
    })?;
    let modules = dump.get_stream::<MinidumpModuleList>().map_err(|error| {
        MinidumpError::new(MinidumpErrorKind::InvalidMinidump, error.to_string())
    })?;

    let mut symbols_by_identity = HashMap::with_capacity(symbols.len());
    for supplied in symbols {
        let parsed = SymbolFile::from_bytes(supplied.contents.as_bytes()).map_err(|error| {
            MinidumpError::new(
                MinidumpErrorKind::InvalidSymbols,
                format!("invalid symbol file {}: {error}", supplied.debug_file),
            )
        })?;
        let parsed_debug_id = parse_debug_id(&parsed.module_id).map_err(|error| {
            MinidumpError::new(
                MinidumpErrorKind::InvalidSymbols,
                format!("invalid MODULE debug ID {}: {error}", parsed.module_id),
            )
        })?;
        let supplied_debug_id = parse_debug_id(supplied.debug_id).map_err(|error| {
            MinidumpError::new(
                MinidumpErrorKind::InvalidSymbols,
                format!("invalid supplied debug ID {}: {error}", supplied.debug_id),
            )
        })?;
        if normalize_debug_file(&parsed.debug_file) != normalize_debug_file(supplied.debug_file)
            || parsed_debug_id != supplied_debug_id
        {
            return Err(MinidumpError::new(
                MinidumpErrorKind::InvalidSymbols,
                format!(
                    "symbol contents do not match supplied identity {} {}",
                    supplied.debug_file, supplied.debug_id
                ),
            ));
        }

        let matching_modules = modules
            .iter()
            .filter(|module| {
                module.debug_file().is_some_and(|file| {
                    normalize_debug_file(&file) == normalize_debug_file(supplied.debug_file)
                }) && module
                    .debug_identifier()
                    .is_some_and(|identifier| identifier == supplied_debug_id)
            })
            .collect::<Vec<_>>();
        if matching_modules.is_empty() {
            return Err(MinidumpError::new(
                MinidumpErrorKind::InvalidSymbols,
                format!(
                    "symbol identity {} {} did not match a minidump module",
                    supplied.debug_file, supplied.debug_id
                ),
            ));
        }

        let key = SymbolKey {
            debug_file: normalize_debug_file(supplied.debug_file),
            debug_id: supplied_debug_id.breakpad().to_string(),
        };
        if symbols_by_identity
            .insert(key, supplied.contents.to_owned())
            .is_some()
        {
            return Err(MinidumpError::new(
                MinidumpErrorKind::InvalidSymbols,
                format!(
                    "duplicate symbol identity {} {}",
                    supplied.debug_file, supplied.debug_id
                ),
            ));
        }
    }

    let provider = Symbolizer::new(InMemorySymbolSupplier {
        symbols: symbols_by_identity,
    });
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

unsafe fn borrowed_utf8<'a>(
    data: *const u8,
    len: usize,
    field: &str,
) -> Result<&'a str, MinidumpError> {
    if data.is_null() || len == 0 {
        return Err(MinidumpError::new(
            MinidumpErrorKind::InvalidSymbols,
            format!("{field} must not be empty"),
        ));
    }
    str::from_utf8(slice::from_raw_parts(data, len)).map_err(|error| {
        MinidumpError::new(
            MinidumpErrorKind::InvalidSymbols,
            format!("{field} must be UTF-8: {error}"),
        )
    })
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
    /// Processes minidump bytes with request-scoped Breakpad symbols.
    ///
    /// Missing symbol files are allowed and produce a partial stackwalk. Every
    /// supplied symbol file must match a loaded module by debug file and debug
    /// identifier. All input pointers are borrowed for this synchronous call.
    /// The returned JSON string is owned and must be released with
    /// `symbolic_str_free`.
    unsafe fn symbolic_minidump_process(
        dump: *const u8,
        dump_len: usize,
        symbols: *const SymbolicMinidumpSymbol,
        symbols_len: usize,
    ) -> Result<SymbolicStr> {
        if dump.is_null() || dump_len == 0 || (symbols.is_null() && symbols_len != 0) {
            return Err(MinidumpError::new(
                MinidumpErrorKind::InvalidArgument,
                "minidump input is empty or the symbol array is invalid",
            ).into());
        }

        let dump = slice::from_raw_parts(dump, dump_len);
        let native_symbols = if symbols_len == 0 {
            &[]
        } else {
            slice::from_raw_parts(symbols, symbols_len)
        };
        let symbols = native_symbols
            .iter()
            .map(|symbol| {
                Ok(SymbolInput {
                    debug_file: borrowed_utf8(
                        symbol.debug_file,
                        symbol.debug_file_len,
                        "debug_file",
                    )?,
                    debug_id: borrowed_utf8(symbol.debug_id, symbol.debug_id_len, "debug_id")?,
                    contents: borrowed_utf8(
                        symbol.contents,
                        symbol.contents_len,
                        "symbol contents",
                    )?,
                })
            })
            .collect::<Result<Vec<_>, MinidumpError>>()?;
        Ok(process(dump, &symbols)?.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::ptr;

    const CRASH_LINUX: &[u8] = include_bytes!("../../py/tests/res/minidump/crash_linux.dmp");

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
        let debug_id = module.debug_identifier().unwrap().to_string();

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

        let json = process(
            CRASH_LINUX,
            &[SymbolInput {
                debug_file: &debug_file,
                debug_id: &debug_id,
                contents: &contents,
            }],
        )
        .expect("matching in-memory symbols must be accepted");
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
        assert_eq!(
            unsafe { crate::core::symbolic_err_get_last_code() },
            crate::core::SymbolicErrorCode::MinidumpInvalidArgument
        );
        unsafe { crate::core::symbolic_err_clear() };
    }

    #[test]
    fn process_classifies_invalid_symbol_utf8() {
        let invalid_utf8 = [0xff];
        let valid_debug_file = b"crash_linux";
        let valid_debug_id = b"00112233445566778899AABBCCDDEEFF0";
        let valid_contents = b"MODULE Linux x86_64 00112233445566778899AABBCCDDEEFF0 crash_linux";
        struct Case<'a> {
            field: &'a str,
            debug_file: &'a [u8],
            debug_id: &'a [u8],
            contents: &'a [u8],
        }
        let cases = [
            Case {
                field: "debug_file",
                debug_file: &invalid_utf8,
                debug_id: valid_debug_id,
                contents: valid_contents,
            },
            Case {
                field: "debug_id",
                debug_file: valid_debug_file,
                debug_id: &invalid_utf8,
                contents: valid_contents,
            },
            Case {
                field: "symbol contents",
                debug_file: valid_debug_file,
                debug_id: valid_debug_id,
                contents: &invalid_utf8,
            },
        ];

        for case in cases {
            let symbol = SymbolicMinidumpSymbol {
                debug_file: case.debug_file.as_ptr(),
                debug_file_len: case.debug_file.len(),
                debug_id: case.debug_id.as_ptr(),
                debug_id_len: case.debug_id.len(),
                contents: case.contents.as_ptr(),
                contents_len: case.contents.len(),
            };
            let result = unsafe {
                symbolic_minidump_process(CRASH_LINUX.as_ptr(), CRASH_LINUX.len(), &symbol, 1)
            };
            assert!(result.data.is_null());
            assert_eq!(
                unsafe { crate::core::symbolic_err_get_last_code() },
                crate::core::SymbolicErrorCode::MinidumpInvalidSymbols,
                "invalid UTF-8 in {}",
                case.field
            );
            let message = unsafe {
                crate::core::symbolic_err_get_last_message()
                    .as_str()
                    .to_owned()
            };
            assert!(message.contains(case.field));
            unsafe { crate::core::symbolic_err_clear() };
        }
    }
}
