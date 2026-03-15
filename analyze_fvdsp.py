#!/usr/bin/env python3
"""Deep analysis of fvdsp's interaction with /dev/aci"""
import struct

FVDSP_PATH = r'c:\goip\extracted\fvdsp'
with open(FVDSP_PATH, 'rb') as f:
    fvdsp = f.read()

# 1. Search for ALL relevant strings
print("=" * 70)
print("All strings in fvdsp containing 'aci', 'dev', 'tdi', 'spi', 'sim'")
print("=" * 70)

terms = [b'/dev/', b'aci', b'ACI', b'tdi', b'TDI', b'spi', b'SPI', b'ioctl', b'IOCTL',
         b'SIM', b'sim_', b'APDU', b'ATR', b'ISO', b'fvdsp', b'fv_', b'cmd_', b'CMD_',
         b'RESET', b'7816', b'smart', b'card']

found_strings = set()
for term in terms:
    i = 0
    while i < len(fvdsp) - len(term):
        pos = fvdsp.find(term, i)
        if pos < 0:
            break
        # Find string boundaries
        start = pos
        while start > 0 and fvdsp[start-1] >= 0x20 and fvdsp[start-1] < 0x7f:
            start -= 1
        end = fvdsp.find(b'\x00', pos)
        if end < 0:
            end = pos + 100
        s = fvdsp[start:end]
        try:
            decoded = s.decode('ascii')
            if len(decoded) >= 3 and len(decoded) < 200:
                if start not in found_strings:
                    found_strings.add(start)
                    print(f"  0x{start:06x}: {decoded}")
        except:
            pass
        i = pos + 1

# 2. Search for SWI (syscall) instructions
print(f"\n{'='*70}")
print("SWI (syscall) instructions in fvdsp")
print("=" * 70)

swi_count = 0
for i in range(0, len(fvdsp) - 4, 4):
    insn = struct.unpack_from('<I', fvdsp, i)[0]
    # SWI/SVC: condition[31:28] 1111[27:24] imm24[23:0]
    if (insn & 0x0F000000) == 0x0F000000:
        imm = insn & 0x00FFFFFF
        # OABI: SWI #0x900000 + nr, EABI: SWI #0
        if imm == 0x900036:  # __NR_ioctl = 54
            print(f"  0x{i:06x}: SWI #0x{imm:x}  (__NR_ioctl OABI)")
            swi_count += 1
        elif imm == 0:  # EABI
            # Check if r7 was loaded with 54 (0x36) before
            pass
        elif 0x900000 <= imm <= 0x9001FF:
            nr = imm - 0x900000
            syscall_names = {1:'exit', 2:'fork', 3:'read', 4:'write', 5:'open', 6:'close',
                           36:'sync', 54:'ioctl', 55:'fcntl', 63:'dup2', 90:'mmap',
                           102:'socketcall', 114:'wait4', 118:'fsync', 142:'select',
                           162:'nanosleep', 168:'poll', 195:'stat64', 197:'fstat64',
                           221:'fcntl64', 240:'futex', 248:'exit_group'}
            name = syscall_names.get(nr, f'nr={nr}')
            if swi_count < 50:
                print(f"  0x{i:06x}: SWI #0x{imm:x}  (__NR_{name} = {nr})")
            swi_count += 1

print(f"\nTotal SWI instructions found: {swi_count}")

# 3. Check for ioctl via glibc/uclibc wrapper in PLT
print(f"\n{'='*70}")
print("PLT entries (function stubs)")
print("=" * 70)

# Parse ELF to find PLT and .rel.plt
e_shoff = struct.unpack_from('<I', fvdsp, 32)[0]
e_shentsize = struct.unpack_from('<H', fvdsp, 46)[0]
e_shnum = struct.unpack_from('<H', fvdsp, 48)[0]
e_shstrndx = struct.unpack_from('<H', fvdsp, 50)[0]

fv_sections = []
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    sh = {}
    for j, f in enumerate(['name_off','type','flags','addr','offset','size','link','info','addralign','entsize']):
        sh[f] = struct.unpack_from('<I', fvdsp, off+j*4)[0]
    fv_sections.append(sh)

fv_sstr = fvdsp[fv_sections[e_shstrndx]['offset']:fv_sections[e_shstrndx]['offset']+fv_sections[e_shstrndx]['size']]
for s in fv_sections:
    end = fv_sstr.index(b'\x00', s['name_off'])
    s['name'] = fv_sstr[s['name_off']:end].decode()

# List all sections
print("\nSections:")
for i, s in enumerate(fv_sections):
    if s['size'] > 0:
        print(f"  [{i:2d}] {s['name']:25s} type={s['type']:2d} off=0x{s['offset']:06x} size=0x{s['size']:06x} addr=0x{s['addr']:08x}")

# Find dynamic string table and symbol table
dynsym = next((s for s in fv_sections if s['name'] == '.dynsym'), None)
dynstr = next((s for s in fv_sections if s['name'] == '.dynstr'), None)
rel_plt = next((s for s in fv_sections if s['name'] == '.rel.plt'), None)

if dynsym and dynstr and rel_plt:
    dstr = fvdsp[dynstr['offset']:dynstr['offset']+dynstr['size']]
    
    # Print ALL dynamic symbols (not just filtered)
    print(f"\nALL dynamic symbols that contain i/o related terms:")
    num_dsyms = dynsym['size'] // 16
    for i in range(num_dsyms):
        off = dynsym['offset'] + i * 16
        st_name = struct.unpack_from('<I', fvdsp, off)[0]
        st_value = struct.unpack_from('<I', fvdsp, off+4)[0]
        st_size = struct.unpack_from('<I', fvdsp, off+8)[0]
        st_info = fvdsp[off+12]
        end = dstr.index(b'\x00', st_name)
        name = dstr[st_name:end].decode() if st_name else ''
        if name and any(k in name.lower() for k in ['ioctl','_io','fv_','dev','port','channel']):
            print(f"  [{i:3d}] {name:40s} val=0x{st_value:08x} size={st_size}")

# 4. Look for /dev/aci string and trace references
print(f"\n{'='*70}")
print("/dev/ string references in fvdsp")
print("=" * 70)

# Find all /dev/ strings
i = 0
dev_strings = []
while i < len(fvdsp):
    pos = fvdsp.find(b'/dev/', i)
    if pos < 0:
        break
    end = fvdsp.find(b'\x00', pos)
    if end > pos:
        s = fvdsp[pos:end].decode('ascii', errors='replace')
        print(f"  0x{pos:06x}: \"{s}\"")
        dev_strings.append((pos, s))
    i = pos + 1

# 5. Look for fv_tdi functions
print(f"\n{'='*70}")
print("fv_tdi related strings and references")
print("=" * 70)
i = 0
while i < len(fvdsp):
    pos = fvdsp.find(b'fv_', i)
    if pos < 0: break
    start = pos
    while start > 0 and fvdsp[start-1] >= 0x20 and fvdsp[start-1] < 0x7f:
        start -= 1
    end = fvdsp.find(b'\x00', pos)
    if end > pos and end - start < 100:
        s = fvdsp[start:end].decode('ascii', errors='replace')
        if 'fv_' in s and s not in ('.fv_', ''):
            print(f"  0x{start:06x}: {s}")
    i = pos + 1
