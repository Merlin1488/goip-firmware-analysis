#!/usr/bin/env python3
"""Analyze ACI_extra functions (SIM card) and ACI_dev_write/read for data format"""
import struct

KO_PATH = r'c:\goip\extracted\fvaci.ko'
FVDSP_PATH = r'c:\goip\extracted\fvdsp'

with open(KO_PATH, 'rb') as f:
    data = f.read()

# Parse ELF sections
fmt = '<'
e_shoff = struct.unpack_from(f'{fmt}I', data, 32)[0]
e_shentsize = struct.unpack_from(f'{fmt}H', data, 46)[0]
e_shnum = struct.unpack_from(f'{fmt}H', data, 48)[0]
e_shstrndx = struct.unpack_from(f'{fmt}H', data, 50)[0]

sections = []
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    sh = {f: struct.unpack_from(f'{fmt}I', data, off+j*4)[0] for j, f in 
          enumerate(['name_off','type','flags','addr','offset','size'])}
    sections.append(sh)

sstr = data[sections[e_shstrndx]['offset']:sections[e_shstrndx]['offset']+sections[e_shstrndx]['size']]
for s in sections:
    end = sstr.index(b'\x00', s['name_off'])
    s['name'] = sstr[s['name_off']:end].decode()

text_sect = next(s for s in sections if s['name'] == '.text')
symtab_sect = next(s for s in sections if s['type'] == 2)
strtab_sect = next(s for s in sections if s['name'] == '.strtab')
sym_str = data[strtab_sect['offset']:strtab_sect['offset']+strtab_sect['size']]

symbols = {}
for i in range(symtab_sect['size'] // 16):
    off = symtab_sect['offset'] + i * 16
    st_name = struct.unpack_from('<I', data, off)[0]
    st_value = struct.unpack_from('<I', data, off+4)[0]
    st_size = struct.unpack_from('<I', data, off+8)[0]
    st_info = data[off+12]
    st_shndx = struct.unpack_from('<H', data, off+14)[0]
    end = sym_str.index(b'\x00', st_name)
    name = sym_str[st_name:end].decode() if st_name else ''
    if name:
        symbols[name] = {'value': st_value, 'size': st_size, 'shndx': st_shndx}

CONDS = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','','NV']
REGS = ['r0','r1','r2','r3','r4','r5','r6','r7','r8','r9','r10','r11','r12','sp','lr','pc']

def decode_arm(insn, pc):
    cond = (insn >> 28) & 0xf
    cs = CONDS[cond]
    if (insn & 0x0E000000) == 0x0A000000:
        L = (insn >> 24) & 1
        offset = insn & 0x00FFFFFF
        if offset & 0x800000: offset -= 0x1000000
        target = pc + offset * 4 + 8
        return f"B{'L' if L else ''}{cs} 0x{target&0xffffffff:x}"
    if (insn & 0x0C000000) == 0x00000000:
        I = (insn >> 25) & 1; op = (insn >> 21) & 0xf; S = (insn >> 20) & 1
        Rn = (insn >> 16) & 0xf; Rd = (insn >> 12) & 0xf
        ops = ['AND','EOR','SUB','RSB','ADD','ADC','SBC','RSC','TST','TEQ','CMP','CMN','ORR','MOV','BIC','MVN']
        if I:
            rot = ((insn >> 8) & 0xf) * 2; imm8 = insn & 0xff
            imm = ((imm8 >> rot) | (imm8 << (32 - rot))) & 0xffffffff if rot else imm8
            if op in (8,9,10,11): return f"{ops[op]}{cs} {REGS[Rn]}, #0x{imm:x}"
            elif op in (13,15): return f"{ops[op]}{cs}{'S' if S else ''} {REGS[Rd]}, #0x{imm:x}"
            else: return f"{ops[op]}{cs}{'S' if S else ''} {REGS[Rd]}, {REGS[Rn]}, #0x{imm:x}"
        else:
            Rm = insn & 0xf; st = (insn >> 5) & 3; si = (insn >> 7) & 0x1f
            sn = ['LSL','LSR','ASR','ROR']
            ss = f", {sn[st]} #{si}" if si or st else ""
            if op in (8,9,10,11): return f"{ops[op]}{cs} {REGS[Rn]}, {REGS[Rm]}{ss}"
            elif op in (13,15): return f"{ops[op]}{cs}{'S' if S else ''} {REGS[Rd]}, {REGS[Rm]}{ss}"
            else: return f"{ops[op]}{cs}{'S' if S else ''} {REGS[Rd]}, {REGS[Rn]}, {REGS[Rm]}{ss}"
    if (insn & 0x0C000000) == 0x04000000:
        I = (insn >> 25) & 1; P = (insn >> 24) & 1; U = (insn >> 23) & 1
        B = (insn >> 22) & 1; L = (insn >> 20) & 1
        Rn = (insn >> 16) & 0xf; Rd = (insn >> 12) & 0xf
        op = 'LDR' if L else 'STR'
        bs = 'B' if B else ''
        if not I:
            off12 = insn & 0xfff; sgn = '+' if U else '-'
            return f"{op}{cs}{bs} {REGS[Rd]}, [{REGS[Rn]}, #{sgn}{off12}]"
        else:
            Rm = insn & 0xf; sgn = '+' if U else '-'
            return f"{op}{cs}{bs} {REGS[Rd]}, [{REGS[Rn]}, {sgn}{REGS[Rm]}]"
    if (insn & 0x0E000000) == 0x08000000:
        L = (insn >> 20) & 1; Rn = (insn >> 16) & 0xf
        regs = [REGS[i] for i in range(16) if insn & (1 << i)]
        return f"{'LDM' if L else 'STM'}{cs} {REGS[Rn]}, {{{','.join(regs)}}}"
    if (insn & 0x0E000090) == 0x00000090 and (insn & 0x60):
        L = (insn >> 20) & 1; Rn = (insn >> 16) & 0xf; Rd = (insn >> 12) & 0xf
        SH = (insn >> 5) & 3; U = (insn >> 23) & 1; II = (insn >> 22) & 1
        ops = {1: 'H', 2: 'SB', 3: 'SH'}
        if II:
            imm = ((insn >> 4) & 0xf0) | (insn & 0xf)
            return f"{'LDR' if L else 'STR'}{cs}{ops.get(SH,'')} {REGS[Rd]}, [{REGS[Rn]}, #{'+'if U else '-'}{imm}]"
        else:
            Rm = insn & 0xf
            return f"{'LDR' if L else 'STR'}{cs}{ops.get(SH,'')} {REGS[Rd]}, [{REGS[Rn]}, {'+'if U else '-'}{REGS[Rm]}]"
    return f"DCD 0x{insn:08x}"

def disasm_func(name, max_lines=100):
    sym = symbols.get(name)
    if not sym:
        print(f"  Symbol {name} not found")
        return
    shndx = sym['shndx']
    sect = sections[shndx]
    file_off = sect['offset'] + sym['value']
    size = sym['size']
    func_data = data[file_off:file_off+size]
    print(f"\n  {name} @ .{sect['name']}+0x{sym['value']:x}, size={size}")
    for i in range(0, min(size, max_lines*4), 4):
        insn = struct.unpack_from('<I', func_data, i)[0]
        pc = sym['value'] + i
        print(f"    {pc:04x}: {insn:08x}  {decode_arm(insn, pc)}")

# ============================================================
# Disassemble key functions
# ============================================================

print("=" * 70)
print("ACI EXTRA (SIM Card Interface) Functions")
print("=" * 70)

for func_name in ['ACI_extra_init', 'ACI_extra_reset', 'ACI_extra_transmit_handler',
                   'ACI_extra_receive_handler', 'ACI_extra_get_event_data', 'ACI_extra_clean']:
    disasm_func(func_name, max_lines=60)

print("\n" + "=" * 70)
print("ACI_dev_write (first 60 instructions)")
print("=" * 70)
disasm_func('ACI_dev_write', max_lines=60)

print("\n" + "=" * 70)
print("ACI_dev_read (first 60 instructions)")
print("=" * 70)
disasm_func('ACI_dev_read', max_lines=60)

print("\n" + "=" * 70)
print("ACI_cardiac_mechanism")
print("=" * 70)
disasm_func('ACI_cardiac_mechanism', max_lines=30)

print("\n" + "=" * 70)
print("ACI_initialize")
print("=" * 70)
disasm_func('ACI_initialize', max_lines=50)

# ============================================================
# Check fvdsp for ioctl syscalls
# ============================================================
print("\n" + "=" * 70)
print("fvdsp: Searching for ioctl syscall patterns")
print("=" * 70)

with open(FVDSP_PATH, 'rb') as f:
    fvdsp = f.read()

# Check if fvdsp is dynamically linked
print(f"fvdsp ELF type: {struct.unpack_from('<H', fvdsp, 16)[0]} (2=EXEC, 3=DYN)")

# Find dynamic section
fv_e_phoff = struct.unpack_from('<I', fvdsp, 28)[0]
fv_e_phentsize = struct.unpack_from('<H', fvdsp, 42)[0]
fv_e_phnum = struct.unpack_from('<H', fvdsp, 44)[0]

print(f"Program headers: {fv_e_phnum} at offset {fv_e_phoff}")

for i in range(fv_e_phnum):
    off = fv_e_phoff + i * fv_e_phentsize
    p_type = struct.unpack_from('<I', fvdsp, off)[0]
    p_offset = struct.unpack_from('<I', fvdsp, off+4)[0]
    p_filesz = struct.unpack_from('<I', fvdsp, off+16)[0]
    type_names = {0:'NULL', 1:'LOAD', 2:'DYNAMIC', 3:'INTERP', 4:'NOTE', 6:'PHDR', 7:'TLS'}
    tname = type_names.get(p_type, f'0x{p_type:x}')
    if p_type in (2, 3):  # DYNAMIC or INTERP
        if p_type == 3:
            interp = fvdsp[p_offset:p_offset+p_filesz].rstrip(b'\x00').decode()
            print(f"  INTERP: {interp}")
        else:
            print(f"  DYNAMIC: offset=0x{p_offset:x}, size={p_filesz}")

# Look for open/ioctl/read/write in dynamic symbol names
fv_e_shoff = struct.unpack_from('<I', fvdsp, 32)[0]
fv_e_shentsize = struct.unpack_from('<H', fvdsp, 46)[0]
fv_e_shnum = struct.unpack_from('<H', fvdsp, 48)[0]
fv_e_shstrndx = struct.unpack_from('<H', fvdsp, 50)[0]

fv_sections = []
for i in range(fv_e_shnum):
    off = fv_e_shoff + i * fv_e_shentsize
    sh = {f: struct.unpack_from('<I', fvdsp, off+j*4)[0] for j, f in
          enumerate(['name_off','type','flags','addr','offset','size'])}
    fv_sections.append(sh)

fv_shstrtab = fv_sections[fv_e_shstrndx]
fv_sstr = fvdsp[fv_shstrtab['offset']:fv_shstrtab['offset']+fv_shstrtab['size']]

for s in fv_sections:
    end = fv_sstr.index(b'\x00', s['name_off'])
    s['name'] = fv_sstr[s['name_off']:end].decode()

# Find .dynsym and .dynstr
dynsym_sect = next((s for s in fv_sections if s['name'] == '.dynsym'), None)
dynstr_sect = next((s for s in fv_sections if s['name'] == '.dynstr'), None)

if dynsym_sect and dynstr_sect:
    dynstr = fvdsp[dynstr_sect['offset']:dynstr_sect['offset']+dynstr_sect['size']]
    print(f"\nDynamic symbols (filtered for IO):")
    for i in range(dynsym_sect['size'] // 16):
        off = dynsym_sect['offset'] + i * 16
        st_name = struct.unpack_from('<I', fvdsp, off)[0]
        st_value = struct.unpack_from('<I', fvdsp, off+4)[0]
        st_info = fvdsp[off+12]
        end = dynstr.index(b'\x00', st_name)
        name = dynstr[st_name:end].decode() if st_name else ''
        if name and any(k in name.lower() for k in ['ioctl','open','read','write','close','poll','select','mmap','fcntl','sim','aci','spi']):
            bind = st_info >> 4
            stype = st_info & 0xf
            print(f"  {name:30s} val=0x{st_value:08x} bind={'G' if bind==1 else 'L'} type={stype}")

# Search for 0x5000..0x500f pattern in ARM instructions (ioctl type 'P')
# Look for MOV/LDR with these values
print(f"\nSearching for ARM instructions that load ioctl constants:")
# In ARM, small constants are loaded with MOV immediate
# For _IO('P', n) = 0x0000500n, this would be: MOV Rd, #0x5000 + n
# In ARM encoding: 0xe3a0_XYYY where X encodes rotation and Y is immediate
# 0x5000 = 0x50 rotated right by 16 (= rotate field 8): e3a0X850
# So MOV Rd, #0x5000 = e3a0_0850 where _ encodes Rd

for i in range(0, len(fvdsp) - 4, 4):
    insn = struct.unpack_from('<I', fvdsp, i)[0]
    # Check for MOV Rd, #0x5000 variants
    if (insn & 0x0FFF0F00) == 0x03A00800:
        imm8 = insn & 0xFF
        rot = ((insn >> 8) & 0xF) * 2
        if rot:
            val = ((imm8 >> rot) | (imm8 << (32 - rot))) & 0xffffffff
        else:
            val = imm8
        if 0x5000 <= val <= 0x500F:
            Rd = (insn >> 12) & 0xF
            print(f"  0x{i:06x}: MOV {REGS[Rd]}, #0x{val:x}  (insn={insn:08x})")
    
    # Check for LDR from literal pool
    if (insn & 0x0F7F0000) == 0x051F0000:  # LDR Rd, [PC, #offset]
        Rd = (insn >> 12) & 0xF
        off12 = insn & 0xFFF
        U = (insn >> 23) & 1
        if U:
            target = i + 8 + off12
        else:
            target = i + 8 - off12
        if 0 <= target <= len(fvdsp) - 4:
            val = struct.unpack_from('<I', fvdsp, target)[0]
            if val in (0x00005002, 0x00005003, 0x00005004, 0x00005005,
                       0x00005006, 0x00005007, 0x00005008, 0x00005009,
                       0x40045000, 0x40045001, 0x4004500a, 0x4004500b,
                       0x4004500c, 0x8004500d, 0x8004500e):
                print(f"  0x{i:06x}: LDR {REGS[Rd]}, =0x{val:08x}  (pool at 0x{target:x})")
