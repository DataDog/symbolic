# Local Windows unwind fixture

Generated from the adjacent `fixture.c` with clang-cl 21 targeting i686-pc-windows-msvc,
`/Z7 /O2 /GS-`, lld-link `/entry:entry /subsystem:console /nodefaultlib /debug:full`,
and Mozilla dump_syms 2.3.9 `--check-cfi --inlines`. No Windows runtime required.
The synthetic minidump captures crash_frame at RVA 0x1010, ESP 0x120000;
return addresses 0x401040 and 0x401057 are at ESP+8 and ESP+20.
The three frames must be crash_frame, caller_frame, entry, with CFI caller trust.
This exercises STACK WIN argument sizes which symcache alone does not preserve.
