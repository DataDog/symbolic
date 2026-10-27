"""Writes fixture.dmp: a minimal ARM64 Windows minidump for fixture.exe.

The thread stopped in `caller_frame` at RVA 0x105c, after its call to `crash_frame`, so x30 holds
the clobbered return address 0x1058. SP is 0x120000, and the saved return address into `entry`
(RVA 0x1078) is in the stack memory at SP+48. Usage: python3 make_dump.py (next to fixture.exe).
"""
import struct
from pathlib import Path

here = Path(__file__).resolve().parent
exe = (here / "fixture.exe").read_bytes()
pe = struct.unpack_from("<I", exe, 60)[0]
base = struct.unpack_from("<Q", exe, pe + 24 + 24)[0]  # ImageBase
size = struct.unpack_from("<I", exe, pe + 24 + 56)[0]  # SizeOfImage
cv = exe.index(b"RSDS")
codeview = exe[cv : cv + 24] + b"fixture.pdb\0"  # RSDS signature, GUID, age, PDB name

CRASH_PC, CLOBBERED_LR, CALLER_RA = 0x105C, 0x1058, 0x1078
SP = 0x120000

# CONTEXT_ARM64 (912 bytes): ContextFlags = CONTEXT_ARM64_FULL, x30, sp, pc.
context = bytearray(912)
struct.pack_into("<I", context, 0, 0x400007)
struct.pack_into("<Q", context, 8 + 30 * 8, base + CLOBBERED_LR)
struct.pack_into("<QQ", context, 256, SP, base + CRASH_PC)
# 256 bytes of stack at SP; the saved return address is at SP+48.
stack = bytearray(256)
struct.pack_into("<Q", stack, 0x30, base + CALLER_RA)

# MINIDUMP_HEADER: signature, version, 4 streams, stream directory at 32.
data = bytearray(80)
struct.pack_into("<IIIIIIQ", data, 0, 0x504D444D, 0xA793, 4, 32, 0, 0, 0)


def add(blob):
    offset = len(data)
    data.extend(blob)
    return offset


context_rva, stack_rva, codeview_rva = add(context), add(stack), add(codeview)
name = "fixture.exe".encode("utf-16-le")
name_rva = add(struct.pack("<I", len(name)) + name)

thread = bytearray(48)  # MINIDUMP_THREAD: id 1, stack memory and context locations.
struct.pack_into("<II", thread, 0, 1, 1)
struct.pack_into("<QIIII", thread, 24, SP, len(stack), stack_rva, len(context), context_rva)
module = bytearray(108)  # MINIDUMP_MODULE: base, size, name and CodeView record.
struct.pack_into("<QIIII", module, 0, base, size, 0, 0, name_rva)
struct.pack_into("<II", module, 76, len(codeview), codeview_rva)
system = bytearray(56)  # MINIDUMP_SYSTEM_INFO: PROCESSOR_ARCHITECTURE_ARM64, Windows NT.
struct.pack_into("<H", system, 0, 12)
system[6] = 1
struct.pack_into("<I", system, 20, 2)
exception = bytearray(168)  # MINIDUMP_EXCEPTION_STREAM: access violation at the crash PC.
struct.pack_into("<II", exception, 0, 1, 0)
struct.pack_into("<I", exception, 8, 0xC0000005)
struct.pack_into("<Q", exception, 24, base + CRASH_PC)
struct.pack_into("<II", exception, 160, len(context), context_rva)

streams = [(3, struct.pack("<I", 1) + thread), (4, struct.pack("<I", 1) + module), (7, system), (6, exception)]
for i, (kind, blob) in enumerate(streams):
    struct.pack_into("<III", data, 32 + 12 * i, kind, len(blob), add(blob))

(here / "fixture.dmp").write_bytes(bytes(data))
