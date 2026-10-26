# Windows ARM64 PE unwind fixture

Generated from the adjacent `fixture.c` with clang-cl (LLVM 23) targeting `aarch64-pc-windows-msvc`,
`/Z7 /Od /GS-`, and lld-link `/machine:arm64 /entry:entry /subsystem:console /nodefaultlib /debug:full`.
No Windows runtime is required.

`caller_frame` has a full `.xdata` record (`sub sp, sp, #64` then `str x30, [sp, #48]`). The
other two functions use packed `.pdata` entries.

The synthetic minidump stops in `caller_frame` at RVA 0x105c, after its call to `crash_frame`, so
`x30` already holds the clobbered value 0x1058. SP is 0x120000, and the saved return address into
`entry` (RVA 0x1078) is at SP+48. A correct CFI must recover `entry()` from the stack slot
(`.ra: .cfa -16 + ^`) with CFI trust.
