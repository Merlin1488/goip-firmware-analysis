#!/usr/bin/env python3
"""Analyze libtdi.so for ioctl usage on /dev/aci"""
import struct

TDI_PATH = r'c:\goip\extracted\libtdi.so'
with open(TDI_PATH, 'rb') as f:
    tdi = f.read()

print(f"libtdi.so size: {len(tdi)} bytes")
print(f"ELF type: {struct.unpack_from('<H', tdi, 16)[0]} (3=DYN)")

# Parse ELF sections
e_shoff = struct.unpack_from('<I', tdi, 32)[0]
e_shentsize = struct.unpack_from('<H', tdi, 46)[0]
e_shnum = struct.unpack_from('<H', tdi, 48)[0]
e_shstrndx = struct.unpack_from('<H', tdi, 50)[0]

sections = []
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    sh = {}
    for j, f in enumerate(['name_off','type','flags','addr','offset','size','link','info','addralign','entsize']):
        sh[f] = struct.unpack_from('<I', tdi, off+j*4)[0]
    sections.append(sh)

sstr = tdi[sections[e_shstrndx]['offset']:sections[e_shstrndx]['offset']+sections[e_shstrndx]['size']]
for s in sections:
    end = sstr.index(b'\x00', s['name_off'])
    s['name'] = sstr[s['name_off']:end].decode()

# 1. Check dynamic symbols for ioctl
dynsym = next((s for s in sections if s['name'] == '.dynsym'), None)
dynstr = next((s for s in sections if s['name'] == '.dynstr'), None)

if dynsym and dynstr:
    dstr = tdi[dynstr['offset']:dynstr['offset']+dynstr['size']]
    num_syms = dynsym['size'] // 16
    
    print(f"\n{'='*70}")
    print("Dynamic symbols in libtdi.so")
    print('='*70)
    
    for i in range(num_syms):
        off = dynsym['offset'] + i * 16
        st_name = struct.unpack_from('<I', tdi, off)[0]
        st_value = struct.unpack_from('<I', tdi, off+4)[0]
        st_size = struct.unpack_from('<I', tdi, off+8)[0]
        st_info = tdi[off+12]
        end = dstr.index(b'\x00', st_name)
        name = dstr[st_name:end].decode() if st_name else ''
        bind = st_info >> 4
        stype = st_info & 0xf
        if name:
            if any(k in name.lower() for k in ['ioctl','open','close','read','write','fv_','tdi','aci','spi','dev','mmap','fcntl','poll','select']):
                bind_str = 'GLOBAL' if bind == 1 else 'WEAK' if bind == 2 else f'bind={bind}'
                type_str = 'FUNC' if stype == 2 else 'OBJECT' if stype == 1 else f'type={stype}'
                imp_exp = 'IMPORT' if st_value == 0 and stype == 0 else 'EXPORT' if st_value != 0 else 'UNDEF'
                print(f"  {name:40s} val=0x{st_value:08x} size={st_size:5d} {bind_str:7s} {type_str:7s} {imp_exp}")

# 2. Search for SWI ioctl instructions
print(f"\n{'='*70}")
print("SWI (syscall) instrutions in libtdi.so")
print('='*70)

for i in range(0, len(tdi) - 4, 4):
    insn = struct.unpack_from('<I', tdi, i)[0]
    if (insn & 0x0F000000) == 0x0F000000:
        imm = insn & 0x00FFFFFF
        if 0x900000 <= imm <= 0x9001FF:
            nr = imm - 0x900000
            names = {3:'read', 4:'write', 5:'open', 6:'close', 54:'ioctl', 118:'fsync',
                    142:'_newselect', 168:'poll', 221:'fcntl64', 55:'fcntl'}
            name = names.get(nr, f'syscall_{nr}')
            print(f"  0x{i:06x}: SWI #0x{imm:06x}  __NR_{name} ({nr})")

# 3. Search for ACI ioctl command constants
print(f"\n{'='*70}")
print("ACI ioctl constants in libtdi.so")
print('='*70)

ioctl_cmds = {
    0x00005002: '_IO(P, 2) SET_TX_FLAG',
    0x00005003: '_IO(P, 3) RESET_CHANNEL',
    0x00005004: '_IO(P, 4) ENABLE',
    0x00005005: '_IO(P, 5) DISABLE',
    0x00005006: '_IO(P, 6) ENABLE',
    0x00005007: '_IO(P, 7) SET_SUPPLEMENT',
    0x00005008: '_IO(P, 8) CLR_SUPPLEMENT',
    0x00005009: '_IO(P, 9) FULL_RESET',
    0x40045000: '_IOW(P, 0) SET_VALUE',
    0x40045001: '_IOW(P, 1) NOP',
    0x4004500a: '_IOW(P, 10) SET_FRAME_PARAM',
    0x4004500b: '_IOW(P, 11) SET_EVENT_MASK',
    0x4004500c: '_IOW(P, 12) CLR_EVENT_MASK',
    0x8004500d: '_IOR(P, 13) GET_EVENTS',
    0x8004500e: '_IOR(P, 14) GET_EVENT_DATA',
}

for val, name in sorted(ioctl_cmds.items()):
    packed = struct.pack('<I', val)
    pos = 0
    while True:
        found = tdi.find(packed, pos)
        if found < 0:
            break
        print(f"  0x{found:06x}: 0x{val:08x} {name}")
        pos = found + 1

# Also search for ARM MOV/LDR with ioctl constants 
print(f"\n{'='*70}")
print("ARM instructions loading ioctl-related constants")
print('='*70)

REGS = ['r0','r1','r2','r3','r4','r5','r6','r7','r8','r9','r10','r11','r12','sp','lr','pc']
for i in range(0, len(tdi) - 4, 4):
    insn = struct.unpack_from('<I', tdi, i)[0]
    
    # LDR Rd, [PC, #offset] - PC-relative literal pool load
    if (insn & 0x0F7F0000) == 0x051F0000:
        Rd = (insn >> 12) & 0xF
        off12 = insn & 0xFFF
        U = (insn >> 23) & 1
        target = (i + 8 + off12) if U else (i + 8 - off12)
        if 0 <= target <= len(tdi) - 4:
            val = struct.unpack_from('<I', tdi, target)[0]
            if val in ioctl_cmds:
                print(f"  0x{i:06x}: LDR {REGS[Rd]}, =0x{val:08x}  ; {ioctl_cmds[val]}  (pool@0x{target:x})")

# 4. All strings in libtdi.so
print(f"\n{'='*70}")
print("All significant strings in libtdi.so")
print('='*70)

rodata = next((s for s in sections if s['name'] == '.rodata'), None)
if rodata:
    rd = tdi[rodata['offset']:rodata['offset']+rodata['size']]
    j = 0
    while j < len(rd):
        end = rd.find(b'\x00', j)
        if end < 0: break
        s = rd[j:end]
        try:
            t = s.decode('ascii')
            if len(t) >= 3:
                print(f"  [{j:04x}] {t}")
        except:
            pass
        j = end + 1
        while j < len(rd) and rd[j] == 0:
            j += 1

# 5. Search all strings in full binary
print(f"\n{'='*70}")
print("/dev/ strings in libtdi.so")
print('='*70)
j = 0
while j < len(tdi):
    pos = tdi.find(b'/dev/', j)
    if pos < 0: break
    end = tdi.find(b'\x00', pos)
    if end > pos:
        s = tdi[pos:end].decode('ascii', errors='replace')
        print(f"  0x{pos:06x}: {s}")
    j = pos + 1
