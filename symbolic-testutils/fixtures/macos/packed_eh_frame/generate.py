"""Generate packed_eh_frame: a minimal arm64 MH_DSYM whose __TEXT,__eh_frame data is packed at the
segment file offset (as dsymutil does), not at fileoff + (addr - vmaddr).

Input: an Xcode-produced iOS dSYM (CrashMe.app.dSYM, from dd-go rum/ios/fixtures/CrashMeInline.zip).
Keeps its first CIE and three FDEs. Usage: python3 generate.py <dSYM DWARF file> packed_eh_frame"""
import struct,sys
src=open(sys.argv[1],'rb').read()
EH_OFF,EH_ADDR,EH_SIZE=1835008,0x1001c3e48,0x101a4
eh=src[EH_OFF:EH_OFF+EH_SIZE]
# keep a contiguous prefix of records so CIE pointers and pc-relative FDE addresses stay valid
out=b''; pos=0; fdes=0
while pos<len(eh) and fdes<3:
    (ln,)=struct.unpack_from('<I',eh,pos)
    (cie_id,)=struct.unpack_from('<I',eh,pos+4)
    out+=eh[pos:pos+4+ln]; fdes+=cie_id!=0; pos+=4+ln
out+=b'\0'*4
VMADDR=0x100000000; ADDR=VMADDR+0x200   # move the section close to the segment start
# FDE pc_begin is pc-relative (CIE augmentation zR, encoding 0x10, 8 bytes): rebase it so the
# described functions keep their original addresses after moving the section.
buf=bytearray(out); pos=0; delta=EH_ADDR-ADDR
while pos<len(buf):
    (ln,)=struct.unpack_from('<I',buf,pos)
    if ln==0: break
    (cie_id,)=struct.unpack_from('<I',buf,pos+4)
    if cie_id: struct.pack_into('<q',buf,pos+8,struct.unpack_from('<q',buf,pos+8)[0]+delta)
    pos+=4+ln
out=bytes(buf)
REL=ADDR-VMADDR
FILEOFF=0x1000
lc_uuid=struct.pack('<II16s',0x1b,24,bytes.fromhex('d9b375ec42583eb4aad361faed9fb4a4'))
sect=struct.pack('<16s16sQQIIIIIIII',b'__eh_frame',b'__TEXT',ADDR,len(out),FILEOFF,3,0,0,0,0,0,0)
seg=struct.pack('<II16sQQQQiiII',0x19,72+80,b'__TEXT',VMADDR,0x20000,FILEOFF,len(out),5,5,1,0)+sect
cmds=lc_uuid+seg
hdr=struct.pack('<IiiIIIII',0xfeedfacf,0x0100000c,0,0xa,2,len(cmds),0,0)
data=hdr+cmds
data+=b'\0'*(FILEOFF-len(data))+out
data+=b'\xaa'*(FILEOFF+REL+len(out)-len(data))   # bytes a segment-relative read would hit
open(sys.argv[2],'wb').write(data)
print(len(data),'bytes; eh_frame',len(out),'fdes',fdes)
