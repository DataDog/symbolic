use symbolic_common::Language;

use super::{raw, PortablePdbCache};

/// Line information for a given IL offset in a function.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct LineInfo<'data> {
    /// The line in the source file.
    pub line: u32,
    /// The source file's name.
    pub file_name: &'data str,
    /// The source language.
    pub file_lang: Language,
}

impl<'data> PortablePdbCache<'data> {
    /// Looks up line information for a function in the cache.
    ///
    /// `func_idx` is the (1-based) index of the function in the ECMA-335 `MethodDef` table
    /// (see the ECMA-335 spec, Section II.22.26). In C#, it is encoded in the
    /// [`MetadataToken`](https://docs.microsoft.com/en-us/dotnet/api/system.reflection.memberinfo.metadatatoken?view=net-6.0#system-reflection-memberinfo-metadatatoken)
    /// property on the [`MethodBase`](https://docs.microsoft.com/en-us/dotnet/api/system.reflection.methodbase?view=net-6.0) class.
    /// See [Metadata Tokens](https://docs.microsoft.com/en-us/previous-versions/dotnet/netframework-4.0/ms404456(v=vs.100)) for an
    /// explanation of the encoding.
    ///
    /// `il_offset` is the offset from the start of the method's Intermediate Language code.
    /// It can be obtained via the [`StackFrame.GetILOffset`](https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.stackframe.getiloffset?view=net-6.0#system-diagnostics-stackframe-getiloffset)
    /// method.
    pub fn lookup(&self, func_idx: u32, il_offset: u32) -> Option<LineInfo<'data>> {
        let range = raw::Range {
            func_idx,
            il_offset,
        };
        let sl = match self.ranges.binary_search(&range) {
            Ok(idx) => self.source_locations.get(idx)?,
            Err(idx) => {
                let idx = idx.checked_sub(1)?;
                let range = self.ranges.get(idx)?;
                if range.func_idx < func_idx {
                    return None;
                }

                self.source_locations.get(idx)?
            }
        };

        let (file_name, file_lang) = self.get_file(sl.file_idx)?;

        Some(LineInfo {
            line: sl.line,
            file_name,
            file_lang,
        })
    }

    /// Looks up line information for the first sequence point of a function in the cache.
    ///
    /// Unlike [`lookup`](Self::lookup), this does not require an IL offset. It is meant for
    /// callers that only have a function/method index available (e.g. `func_idx`, encoded as
    /// described on [`lookup`](Self::lookup)) and no meaningful IL offset to look up -- for
    /// instance, stack frames captured from ahead-of-time compiled code, where the IL offset is
    /// not available at capture time.
    ///
    /// This performs its own exact binary search for the function's first surviving range; it
    /// is not a fallback or a guess, and it does not simply delegate to `lookup(func_idx, 0)`.
    /// That delegation would be unsafe: hidden sequence points are stripped when the cache is
    /// built, so a function's first surviving sequence point is not guaranteed to start at IL
    /// offset 0. If it doesn't, a lookup for offset 0 would miss, and `lookup`'s "nearest
    /// preceding" fallback -- which searches backwards from an exact-offset miss -- would walk
    /// into the *previous* function's last range, silently returning wrong line information
    /// instead of this function's actual first range.
    pub fn lookup_first(&self, func_idx: u32) -> Option<LineInfo<'data>> {
        let start = self
            .ranges
            .partition_point(|range| range.func_idx < func_idx);
        let range = self.ranges.get(start)?;
        if range.func_idx != func_idx {
            return None;
        }

        let sl = self.source_locations.get(start)?;
        let (file_name, file_lang) = self.get_file(sl.file_idx)?;

        Some(LineInfo {
            line: sl.line,
            file_name,
            file_lang,
        })
    }

    fn get_file(&self, idx: u32) -> Option<(&'data str, Language)> {
        let raw = self.files.get(idx as usize)?;
        let name = self.get_string(raw.name_offset)?;

        Some((name, Language::from_u32(raw.lang)))
    }

    /// Resolves a string reference to the pointed-to `&str` data.
    fn get_string(&self, offset: u32) -> Option<&'data str> {
        watto::StringTable::read(self.string_bytes, offset as usize).ok()
    }
}
