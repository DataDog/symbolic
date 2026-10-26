//! Conversion of Windows ARM64 prolog unwind codes into Breakpad CFI rows.
//!
//! Reference: <https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling>.

use std::fmt::Write as _;
use std::io::{self, Write};

use symbolic_debuginfo::pe::{
    Arm64RuntimeFunction, Arm64UnwindCode, ARM64_PDATA_PACKED_UNWIND_FRAGMENT,
    ARM64_PDATA_PACKED_UNWIND_FUNCTION,
};

/// Size of one ARM64 instruction.
const INSTRUCTION_SIZE: u32 = 4;

/// One CFI row: the instruction offset from the function start and its rule changes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Row {
    pub offset: u32,
    pub rules: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RegisterKind {
    /// General-purpose register `x<n>`.
    X,
    /// 64-bit floating point register `d<n>`.
    D,
    /// 128-bit vector register `q<n>`.
    Q,
}

impl RegisterKind {
    fn slot_size(self) -> i64 {
        match self {
            RegisterKind::X | RegisterKind::D => 8,
            RegisterKind::Q => 16,
        }
    }
}

/// Where the canonical frame address is computed from.
#[derive(Clone, Copy)]
enum CfaBase {
    /// `cfa = sp + stack_size`.
    Sp,
    /// `cfa = x29 + offset`, once the frame pointer is established.
    Fp(i64),
}

struct State {
    /// Bytes allocated below the CFA so far.
    stack_size: i64,
    cfa: CfaBase,
    /// The last saved register pair: kind, second register and CFA offset of the first register.
    last_pair: Option<(RegisterKind, u8, i64)>,
}

impl State {
    fn new() -> Self {
        State {
            stack_size: 0,
            cfa: CfaBase::Sp,
            last_pair: None,
        }
    }

    fn cfa_rule(&self, out: &mut String) {
        match self.cfa {
            CfaBase::Sp => write!(out, " .cfa: sp {} +", self.stack_size),
            CfaBase::Fp(offset) => write!(out, " .cfa: x29 {offset} +"),
        }
        .ok();
    }

    fn alloc(&mut self, size: u32, out: &mut String) {
        self.stack_size += i64::from(size);
        if let CfaBase::Sp = self.cfa {
            self.cfa_rule(out);
        }
    }

    /// CFA-relative offset of `[sp + offset]`.
    fn sp_relative(&self, offset: u32) -> i64 {
        i64::from(offset) - self.stack_size
    }

    fn save(kind: RegisterKind, reg: u8, cfa_offset: i64, out: &mut String) {
        match (kind, reg) {
            (RegisterKind::X, 30) => write!(out, " .ra: .cfa {cfa_offset} + ^"),
            (RegisterKind::X, _) => write!(out, " x{reg}: .cfa {cfa_offset} + ^"),
            (RegisterKind::D, _) => write!(out, " d{reg}: .cfa {cfa_offset} + ^"),
            (RegisterKind::Q, _) => write!(out, " q{reg}: .cfa {cfa_offset} + ^"),
        }
        .ok();
    }

    fn save_pair(&mut self, kind: RegisterKind, first: u8, cfa_offset: i64, out: &mut String) {
        let second = first.wrapping_add(1);
        Self::save(kind, first, cfa_offset, out);
        Self::save(kind, second, cfa_offset + kind.slot_size(), out);
        self.last_pair = Some((kind, second, cfa_offset));
    }

    /// Applies one unwind code in execution order. Returns `None` for unsupported codes.
    fn apply(&mut self, code: &Arm64UnwindCode) -> Option<String> {
        use Arm64UnwindCode::*;
        use RegisterKind::*;

        let mut out = String::new();
        match *code {
            AllocSmall { size_bytes } | AllocMedium { size_bytes } | AllocLarge { size_bytes } => {
                self.alloc(size_bytes, &mut out)
            }

            // stp x19, x20, [sp, #-Z]!
            SaveR19R20Preindexed { offset_bytes } => {
                self.alloc(offset_bytes, &mut out);
                self.save_pair(X, 19, -self.stack_size, &mut out);
            }
            // stp x29, x30, [sp, #Z]
            SaveFpLr { offset_bytes } => {
                let at = self.sp_relative(offset_bytes);
                self.save_pair(X, 29, at, &mut out);
            }
            // stp x29, x30, [sp, #-Z]!
            SaveFpLrPreindexed { offset_bytes } => {
                self.alloc(offset_bytes, &mut out);
                self.save_pair(X, 29, -self.stack_size, &mut out);
            }
            SaveRegPair {
                first_reg,
                offset_bytes,
            } => {
                let at = self.sp_relative(offset_bytes);
                self.save_pair(X, first_reg, at, &mut out);
            }
            SaveRegPairPreindexed {
                first_reg,
                offset_bytes,
            } => {
                self.alloc(offset_bytes, &mut out);
                self.save_pair(X, first_reg, -self.stack_size, &mut out);
            }
            SaveReg { reg, offset_bytes } => {
                Self::save(X, reg, self.sp_relative(offset_bytes), &mut out);
            }
            SaveRegPreindexed { reg, offset_bytes } => {
                self.alloc(offset_bytes, &mut out);
                Self::save(X, reg, -self.stack_size, &mut out);
            }
            // stp x(19+2X), lr, [sp, #Z]
            SaveLrPair {
                first_reg,
                offset_bytes,
            } => {
                let at = self.sp_relative(offset_bytes);
                Self::save(X, first_reg, at, &mut out);
                Self::save(X, 30, at + 8, &mut out);
                self.last_pair = None;
            }
            SaveFRegPair {
                first_reg,
                offset_bytes,
            } => {
                let at = self.sp_relative(offset_bytes);
                self.save_pair(D, first_reg, at, &mut out);
            }
            SaveFRegPairPreindexed {
                first_reg,
                offset_bytes,
            } => {
                self.alloc(offset_bytes, &mut out);
                self.save_pair(D, first_reg, -self.stack_size, &mut out);
            }
            SaveFReg { reg, offset_bytes } => {
                Self::save(D, reg, self.sp_relative(offset_bytes), &mut out);
            }
            SaveFRegPreindexed { reg, offset_bytes } => {
                self.alloc(offset_bytes, &mut out);
                Self::save(D, reg, -self.stack_size, &mut out);
            }
            // Saves the next register pair after the previous pair save.
            SaveNext => {
                let (kind, second, at) = self.last_pair?;
                let next_at = at + 2 * kind.slot_size();
                self.save_pair(kind, second.wrapping_add(1), next_at, &mut out);
            }
            SaveAnyReg {
                kind,
                pair,
                preindexed,
                reg,
                offset_bytes,
            } => {
                let kind = match kind {
                    0 => X,
                    1 => D,
                    2 => Q,
                    _ => return None,
                };
                let at = if preindexed {
                    self.alloc(offset_bytes, &mut out);
                    -self.stack_size
                } else {
                    self.sp_relative(offset_bytes)
                };
                if pair {
                    self.save_pair(kind, reg, at, &mut out);
                } else {
                    Self::save(kind, reg, at, &mut out);
                }
            }
            // mov x29, sp
            SetFp => {
                self.cfa = CfaBase::Fp(self.stack_size);
                self.cfa_rule(&mut out);
            }
            // add x29, sp, #Z
            AddFp { offset_bytes, .. } => {
                self.cfa = CfaBase::Fp(self.stack_size - i64::from(offset_bytes));
                self.cfa_rule(&mut out);
            }
            // Instructions that do not affect unwinding.
            Nop | PacSignLr => {}
            _ => return None,
        }
        Some(out)
    }
}

/// Synthesizes the unwind codes (in `.xdata` order) of a packed `.pdata` entry.
///
/// Follows the canonical prolog of the "Packed unwind data" section of the Microsoft
/// documentation, in the same order as LLVM's `llvm-readobj --unwind` (`dumpPackedARM64Entry`).
/// A packed fragment has no prolog, so its codes are prefixed with `end_c`. Returns `None` for
/// entries that are not packed.
pub(crate) fn packed_codes(function: &Arm64RuntimeFunction) -> Option<Vec<Arm64UnwindCode>> {
    use Arm64UnwindCode::*;

    let fragment = match function.flag() {
        ARM64_PDATA_PACKED_UNWIND_FUNCTION => false,
        ARM64_PDATA_PACKED_UNWIND_FRAGMENT => true,
        _ => return None,
    };
    let (reg_i, reg_f, cr, h) = (
        function.reg_i(),
        function.reg_f(),
        function.cr(),
        function.h(),
    );

    let mut int_sz = 8 * reg_i;
    if cr == 1 {
        int_sz += 8;
    }
    let mut fp_sz = 8 * reg_f;
    if reg_f != 0 {
        fp_sz += 8;
    }
    let sav_sz = (int_sz + fp_sz + 8 * 8 * u32::from(h) + 0xf) & !0xf;
    let mut loc_sz = function.frame_size().checked_sub(sav_sz)?;
    let mut homing = h;
    if h && reg_i == 0 && reg_f == 0 && cr != 1 {
        loc_sz += sav_sz;
        homing = false;
    }

    // Codes are pushed in reverse execution order, as stored in `.xdata`.
    let mut codes = Vec::new();
    if cr == 2 || cr == 3 {
        codes.push(SetFp);
        if loc_sz <= 512 {
            codes.push(SaveFpLrPreindexed {
                offset_bytes: loc_sz,
            });
        } else {
            codes.push(SaveFpLr { offset_bytes: 0 });
        }
    }
    if loc_sz > 4080 {
        codes.push(AllocMedium {
            size_bytes: loc_sz - 4080,
        });
        codes.push(AllocMedium { size_bytes: 4080 });
    } else if (cr != 3 && cr != 2 && loc_sz > 0) || loc_sz > 512 {
        codes.push(AllocMedium { size_bytes: loc_sz });
    }
    if homing {
        codes.extend([Nop, Nop, Nop, Nop]);
    }

    let float_regs = if reg_f > 0 { reg_f + 1 } else { 0 };
    for i in (0..float_regs.div_ceil(2)).rev() {
        let first = (8 + 2 * i) as u8;
        if i == float_regs.div_ceil(2) - 1 && float_regs % 2 == 1 {
            codes.push(SaveFReg {
                reg: first,
                offset_bytes: int_sz + 16 * i,
            });
        } else if i == 0 && reg_i == 0 && cr != 1 {
            codes.push(SaveFRegPairPreindexed {
                first_reg: first,
                offset_bytes: sav_sz,
            });
        } else {
            codes.push(SaveFRegPair {
                first_reg: first,
                offset_bytes: int_sz + 16 * i,
            });
        }
    }

    if cr == 1 && reg_i % 2 == 0 {
        if reg_i == 0 {
            codes.push(SaveRegPreindexed {
                reg: 30,
                offset_bytes: sav_sz,
            });
        } else {
            codes.push(SaveReg {
                reg: 30,
                offset_bytes: int_sz - 8,
            });
        }
    }
    for i in (0..reg_i.div_ceil(2)).rev() {
        let first = (19 + 2 * i) as u8;
        if i == reg_i.div_ceil(2) - 1 && reg_i % 2 == 1 {
            // The last, unpaired register.
            if cr == 1 {
                if i == 0 {
                    // `sub sp, sp, #savsz` followed by `stp x19, lr, [sp]`.
                    codes.push(SaveLrPair {
                        first_reg: 19,
                        offset_bytes: 0,
                    });
                    codes.push(AllocMedium { size_bytes: sav_sz });
                } else {
                    codes.push(SaveLrPair {
                        first_reg: first,
                        offset_bytes: 16 * i,
                    });
                }
            } else if i == 0 {
                codes.push(SaveRegPreindexed {
                    reg: first,
                    offset_bytes: sav_sz,
                });
            } else {
                codes.push(SaveReg {
                    reg: first,
                    offset_bytes: 16 * i,
                });
            }
        } else if i == 0 {
            codes.push(SaveRegPairPreindexed {
                first_reg: 19,
                offset_bytes: sav_sz,
            });
        } else {
            codes.push(SaveRegPair {
                first_reg: first,
                offset_bytes: 16 * i,
            });
        }
    }
    if cr == 2 {
        codes.push(PacSignLr);
    }
    codes.push(End);

    if fragment {
        codes.insert(0, EndC);
    }
    Some(codes)
}

/// Builds the CFI rows of a function from its unwind codes (as stored in `.xdata`).
///
/// Returns `None` if the codes contain an operation this converter does not support.
pub(crate) fn prolog_rows(codes: &[Arm64UnwindCode]) -> Option<Vec<Row>> {
    let mut rows = vec![Row {
        offset: 0,
        rules: " .cfa: sp 0 + .ra: x30".to_owned(),
    }];
    let mut state = State::new();

    // A function fragment without a prolog starts with `end_c`; the codes that follow describe
    // the frame that is already established on entry to the fragment.
    if let Some(Arm64UnwindCode::EndC) = codes.first() {
        let established = codes[1..]
            .iter()
            .take_while(|c| !matches!(c, Arm64UnwindCode::End | Arm64UnwindCode::EndC))
            .collect::<Vec<_>>();
        let mut rules = String::new();
        for code in established.into_iter().rev() {
            rules.push_str(&state.apply(code)?);
        }
        let cfa = if rules.contains(".cfa:") {
            ""
        } else {
            " .cfa: sp 0 +"
        };
        let ra = if rules.contains(".ra:") {
            ""
        } else {
            " .ra: x30"
        };
        rows[0].rules = format!("{cfa}{ra}{rules}");
        return Some(rows);
    }

    let prolog = codes
        .iter()
        .take_while(|c| !matches!(c, Arm64UnwindCode::End | Arm64UnwindCode::EndC))
        .collect::<Vec<_>>();

    // Prolog codes are stored in reverse order; the n-th executed instruction takes effect at
    // the start of the next instruction.
    for (index, code) in prolog.into_iter().rev().enumerate() {
        let rules = state.apply(code)?;
        if !rules.is_empty() {
            let offset = u32::try_from(index + 1)
                .ok()?
                .checked_mul(INSTRUCTION_SIZE)?;
            rows.push(Row { offset, rules });
        }
    }
    Some(rows)
}

/// Writes the CFI rows of one function. Rows past the end of the function are dropped.
pub(crate) fn write_function<W: Write>(
    writer: &mut W,
    begin: u32,
    length: u32,
    rows: &[Row],
) -> io::Result<()> {
    for row in rows {
        if row.offset == 0 {
            writeln!(writer, "STACK CFI INIT {begin:x} {length:x}{}", row.rules)?;
        } else if row.offset < length {
            writeln!(writer, "STACK CFI {:x}{}", begin + row.offset, row.rules)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use Arm64UnwindCode::*;

    fn rules(codes: &[Arm64UnwindCode]) -> Vec<(u32, String)> {
        prolog_rows(codes)
            .unwrap()
            .into_iter()
            .map(|r| (r.offset, r.rules))
            .collect()
    }

    #[test]
    fn alloc_then_save_lr() {
        // sub sp, sp, #64 ; str x30, [sp, #48]   (stored in reverse order)
        let codes = [
            SaveAnyReg {
                kind: 0,
                pair: false,
                preindexed: false,
                reg: 30,
                offset_bytes: 48,
            },
            AllocSmall { size_bytes: 64 },
            End,
        ];
        assert_eq!(
            rules(&codes),
            vec![
                (0, " .cfa: sp 0 + .ra: x30".into()),
                (4, " .cfa: sp 64 +".into()),
                (8, " .ra: .cfa -16 + ^".into()),
            ]
        );
    }

    #[test]
    fn frame_record_and_frame_pointer() {
        // stp x29, x30, [sp, #-32]! ; stp x19, x20, [sp, #16] ; mov x29, sp
        let codes = [
            SetFp,
            SaveRegPair {
                first_reg: 19,
                offset_bytes: 16,
            },
            SaveFpLrPreindexed { offset_bytes: 32 },
            End,
        ];
        assert_eq!(
            rules(&codes),
            vec![
                (0, " .cfa: sp 0 + .ra: x30".into()),
                (
                    4,
                    " .cfa: sp 32 + x29: .cfa -32 + ^ .ra: .cfa -24 + ^".into()
                ),
                (8, " x19: .cfa -16 + ^ x20: .cfa -8 + ^".into()),
                (12, " .cfa: x29 32 +".into()),
            ]
        );
    }

    #[test]
    fn save_next_follows_previous_pair() {
        // stp x19, x20, [sp, #-48]! ; stp x21, x22, [sp, #16] ; stp x29, x30, [sp, #32]
        let codes = [
            SaveFpLr { offset_bytes: 32 },
            SaveNext,
            SaveR19R20Preindexed { offset_bytes: 48 },
            End,
        ];
        assert_eq!(
            rules(&codes),
            vec![
                (0, " .cfa: sp 0 + .ra: x30".into()),
                (
                    4,
                    " .cfa: sp 48 + x19: .cfa -48 + ^ x20: .cfa -40 + ^".into()
                ),
                (8, " x21: .cfa -32 + ^ x22: .cfa -24 + ^".into()),
                (12, " x29: .cfa -16 + ^ .ra: .cfa -8 + ^".into()),
            ]
        );
    }

    #[test]
    fn fragment_without_prolog_has_established_frame() {
        let codes = [EndC, SaveFpLrPreindexed { offset_bytes: 16 }, End];
        assert_eq!(
            rules(&codes),
            vec![(
                0,
                " .cfa: sp 16 + x29: .cfa -16 + ^ .ra: .cfa -8 + ^".into()
            )]
        );
    }

    #[test]
    fn unsupported_codes_skip_the_function() {
        assert!(prolog_rows(&[AllocZ { count: 1 }, End]).is_none());
        assert!(prolog_rows(&[SaveNext, End]).is_none());
    }

    #[test]
    fn rows_past_the_function_end_are_dropped() {
        let rows = prolog_rows(&[AllocSmall { size_bytes: 16 }, End]).unwrap();
        let mut out = Vec::new();
        write_function(&mut out, 0x1000, 4, &rows).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "STACK CFI INIT 1000 4 .cfa: sp 0 + .ra: x30\n"
        );
    }

    /// Builds a packed `.pdata` entry: Flag=1 (packed function) with the given fields.
    fn packed(length: u32, reg_i: u32, cr: u32, frame_size: u32) -> Arm64RuntimeFunction {
        Arm64RuntimeFunction {
            begin_address: 0x1000,
            unwind_data: 1 | (length / 4) << 2 | reg_i << 16 | cr << 21 | (frame_size / 16) << 23,
        }
    }

    #[test]
    fn packed_leaf_allocates_stack() {
        // CR=0, FrameSize=32: `sub sp, sp, #32`.
        let codes = packed_codes(&packed(0x34, 0, 0, 32)).unwrap();
        assert_eq!(codes, [AllocMedium { size_bytes: 32 }, End]);
        assert_eq!(
            rules(&codes),
            vec![
                (0, " .cfa: sp 0 + .ra: x30".into()),
                (4, " .cfa: sp 32 +".into()),
            ]
        );
    }

    #[test]
    fn packed_saved_lr() {
        // CR=1, RegI=0, FrameSize=16: `str lr, [sp, #-16]!`.
        let codes = packed_codes(&packed(0x20, 0, 1, 16)).unwrap();
        assert_eq!(
            rules(&codes),
            vec![
                (0, " .cfa: sp 0 + .ra: x30".into()),
                (4, " .cfa: sp 16 + .ra: .cfa -16 + ^".into()),
            ]
        );
    }

    #[test]
    fn packed_chained_frame_with_saved_registers() {
        // CR=3, RegI=2, FrameSize=48:
        // stp x19, x20, [sp, #-16]! ; stp x29, lr, [sp, #-32]! ; mov x29, sp
        let codes = packed_codes(&packed(0x40, 2, 3, 48)).unwrap();
        assert_eq!(
            rules(&codes),
            vec![
                (0, " .cfa: sp 0 + .ra: x30".into()),
                (
                    4,
                    " .cfa: sp 16 + x19: .cfa -16 + ^ x20: .cfa -8 + ^".into()
                ),
                (
                    8,
                    " .cfa: sp 48 + x29: .cfa -48 + ^ .ra: .cfa -40 + ^".into()
                ),
                (12, " .cfa: x29 48 +".into()),
            ]
        );
    }

    #[test]
    fn packed_fragment_has_established_frame() {
        let mut function = packed(0x20, 0, 1, 16);
        function.unwind_data = (function.unwind_data & !3) | 2;
        let codes = packed_codes(&function).unwrap();
        assert_eq!(codes[0], EndC);
        assert_eq!(
            rules(&codes),
            vec![(0, " .cfa: sp 16 + .ra: .cfa -16 + ^".into())]
        );
    }

    #[test]
    fn full_xdata_entries_are_not_packed() {
        let function = Arm64RuntimeFunction {
            begin_address: 0x1000,
            unwind_data: 0x2000,
        };
        assert!(packed_codes(&function).is_none());
    }
}
