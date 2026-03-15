#!/usr/bin/env python3
"""Full ARM disassembly of ACI_dev_ioctl and analysis of fvaci.ko"""
import struct

KO_PATH = r'c:\goip\extracted\fvaci.ko'
FVDSP_PATH = r'c:\goip\extracted\fvdsp'

with open(KO_PATH, 'rb') as f:
    data = f.read()

# Parse ELF
fmt = '<'
e_shoff = struct.unpack_from(f'{fmt}I', data, 32)[0]
e_shentsize = struct.unpack_from(f'{fmt}H', data, 46)[0]
e_shnum = struct.unpack_from(f'{fmt}H', data, 48)[0]
e_shstrndx = struct.unpack_from(f'{fmt}H', data, 50)[0]

sections = []
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    sh = {
        'name_off': struct.unpack_from(f'{fmt}I', data, off)[0],
        'type': struct.unpack_from(f'{fmt}I', data, off+4)[0],
        'flags': struct.unpack_from(f'{fmt}I', data, off+8)[0],
        'addr': struct.unpack_from(f'{fmt}I', data, off+12)[0],
        'offset': struct.unpack_from(f'{fmt}I', data, off+16)[0],
        'size': struct.unpack_from(f'{fmt}I', data, off+20)[0],
    }
    sections.append(sh)

shstrtab = sections[e_shstrndx]
sstr = data[shstrtab['offset']:shstrtab['offset']+shstrtab['size']]
def get_sname(off):
    end = sstr.index(b'\x00', off)
    return sstr[off:end].decode()

for s in sections:
    s['name'] = get_sname(s['name_off'])

# Find .text section
text_sect = next(s for s in sections if s['name'] == '.text')
text_data = data[text_sect['offset']:text_sect['offset']+text_sect['size']]
text_base = text_sect['offset']

# Find symbol table
symtab_sect = next(s for s in sections if s['type'] == 2)
strtab_sect = next(s for s in sections if s['name'] == '.strtab')
sym_str = data[strtab_sect['offset']:strtab_sect['offset']+strtab_sect['size']]

def get_sym_name(off):
    end = sym_str.index(b'\x00', off)
    return sym_str[off:end].decode()

# Read all symbols
symbols = {}
num_syms = symtab_sect['size'] // 16  # 16 bytes per Elf32_Sym
for i in range(num_syms):
    off = symtab_sect['offset'] + i * 16
    st_name = struct.unpack_from('<I', data, off)[0]
    st_value = struct.unpack_from('<I', data, off+4)[0]
    st_size = struct.unpack_from('<I', data, off+8)[0]
    st_info = data[off+12]
    st_shndx = struct.unpack_from('<H', data, off+14)[0]
    name = get_sym_name(st_name) if st_name else ''
    if name and st_shndx < len(sections):
        symbols[name] = {'value': st_value, 'size': st_size, 'shndx': st_shndx,
                        'bind': st_info >> 4, 'type': st_info & 0xf}

# Find .rodata.str1.4 for string references
rodata_str_sect = next((s for s in sections if s['name'] == '.rodata.str1.4'), None)
rodata_sect = next((s for s in sections if s['name'] == '.rodata'), None)
data_sect = next((s for s in sections if s['name'] == '.data'), None)

if rodata_str_sect:
    rodata_str = data[rodata_str_sect['offset']:rodata_str_sect['offset']+rodata_str_sect['size']]
    print("=== .rodata.str1.4 strings ===")
    i = 0
    while i < len(rodata_str):
        end = rodata_str.find(b'\x00', i)
        if end < 0: break
        s = rodata_str[i:end]
        if len(s) > 0:
            try:
                print(f"  [{i:04x}] {s.decode('ascii')}")
            except:
                print(f"  [{i:04x}] <binary>")
        i = end + 1
        while i < len(rodata_str) and rodata_str[i] == 0:
            i += 1

# Decode ARM conditions
CONDS = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','','NV']
REGS = ['r0','r1','r2','r3','r4','r5','r6','r7','r8','r9','r10','r11','r12','sp','lr','pc']

def decode_arm(insn, pc_offset):
    """Decode a single ARM instruction"""
    cond = (insn >> 28) & 0xf
    cs = CONDS[cond]
    
    # Branch
    if (insn & 0x0E000000) == 0x0A000000:
        L = (insn >> 24) & 1
        offset = insn & 0x00FFFFFF
        if offset & 0x800000:
            offset = offset - 0x1000000
        target = pc_offset + offset * 4 + 8
        return f"B{'L' if L else ''}{cs}\t0x{target & 0xffffffff:x}"
    
    # Data processing
    if (insn & 0x0C000000) == 0x00000000:
        I = (insn >> 25) & 1
        op = (insn >> 21) & 0xf
        S = (insn >> 20) & 1
        Rn = (insn >> 16) & 0xf
        Rd = (insn >> 12) & 0xf
        
        ops = ['AND','EOR','SUB','RSB','ADD','ADC','SBC','RSC',
               'TST','TEQ','CMP','CMN','ORR','MOV','BIC','MVN']
        
        if I:
            rotate = ((insn >> 8) & 0xf) * 2
            imm8 = insn & 0xff
            if rotate:
                imm = ((imm8 >> rotate) | (imm8 << (32 - rotate))) & 0xffffffff
            else:
                imm = imm8
            
            if op in (8,9,10,11):  # TST,TEQ,CMP,CMN - no Rd
                return f"{ops[op]}{cs}\t{REGS[Rn]}, #0x{imm:x}"
            elif op in (13,15):  # MOV,MVN - no Rn
                return f"{ops[op]}{cs}{'S' if S else ''}\t{REGS[Rd]}, #0x{imm:x}"
            else:
                return f"{ops[op]}{cs}{'S' if S else ''}\t{REGS[Rd]}, {REGS[Rn]}, #0x{imm:x}"
        else:
            Rm = insn & 0xf
            shift_type = (insn >> 5) & 3
            shift_names = ['LSL','LSR','ASR','ROR']
            
            if (insn >> 4) & 1:  # register shift
                Rs = (insn >> 8) & 0xf
                shift_str = f", {shift_names[shift_type]} {REGS[Rs]}" if ((insn >> 4) & 0xff) != 0 else ""
            else:
                shift_imm = (insn >> 7) & 0x1f
                if shift_imm == 0 and shift_type == 0:
                    shift_str = ""
                else:
                    shift_str = f", {shift_names[shift_type]} #{shift_imm}"
            
            if op in (8,9,10,11):
                return f"{ops[op]}{cs}\t{REGS[Rn]}, {REGS[Rm]}{shift_str}"
            elif op in (13,15):
                return f"{ops[op]}{cs}{'S' if S else ''}\t{REGS[Rd]}, {REGS[Rm]}{shift_str}"
            else:
                return f"{ops[op]}{cs}{'S' if S else ''}\t{REGS[Rd]}, {REGS[Rn]}, {REGS[Rm]}{shift_str}"
    
    # LDR/STR
    if (insn & 0x0C000000) == 0x04000000:
        I = (insn >> 25) & 1
        P = (insn >> 24) & 1
        U = (insn >> 23) & 1
        B = (insn >> 22) & 1
        W = (insn >> 21) & 1
        L = (insn >> 20) & 1
        Rn = (insn >> 16) & 0xf
        Rd = (insn >> 12) & 0xf
        
        op = 'LDR' if L else 'STR'
        bs = 'B' if B else ''
        
        if not I:  # immediate offset
            offset = insn & 0xfff
            sign = '+' if U else '-'
            if P:
                if W:
                    return f"{op}{cs}{bs}\t{REGS[Rd]}, [{REGS[Rn]}, #{sign}{offset}]!"
                else:
                    return f"{op}{cs}{bs}\t{REGS[Rd]}, [{REGS[Rn]}, #{sign}{offset}]"
            else:
                return f"{op}{cs}{bs}\t{REGS[Rd]}, [{REGS[Rn]}], #{sign}{offset}"
        else:  # register offset
            Rm = insn & 0xf
            shift_imm = (insn >> 7) & 0x1f
            shift_type = (insn >> 5) & 3
            shift_names = ['LSL','LSR','ASR','ROR']
            sign = '+' if U else '-'
            if shift_imm:
                return f"{op}{cs}{bs}\t{REGS[Rd]}, [{REGS[Rn]}, {sign}{REGS[Rm]}, {shift_names[shift_type]} #{shift_imm}]"
            else:
                return f"{op}{cs}{bs}\t{REGS[Rd]}, [{REGS[Rn]}, {sign}{REGS[Rm]}]"
    
    # LDM/STM
    if (insn & 0x0E000000) == 0x08000000:
        P = (insn >> 24) & 1
        U = (insn >> 23) & 1
        S = (insn >> 22) & 1
        W = (insn >> 21) & 1
        L = (insn >> 20) & 1
        Rn = (insn >> 16) & 0xf
        reglist = insn & 0xffff
        
        regs = []
        for i in range(16):
            if reglist & (1 << i):
                regs.append(REGS[i])
        
        modes = {(0,1):'DA', (1,1):'IB', (0,0):'DB', (1,0):'IA'}
        mode = modes.get((U,P), '??')
        
        op = 'LDM' if L else 'STM'
        wb = '!' if W else ''
        return f"{op}{cs}{mode}\t{REGS[Rn]}{wb}, {{{', '.join(regs)}}}"
    
    # Halfword/signed transfer
    if (insn & 0x0E000090) == 0x00000090 and (insn & 0x00000060) != 0:
        P = (insn >> 24) & 1
        U = (insn >> 23) & 1
        I = (insn >> 22) & 1
        W = (insn >> 21) & 1
        L = (insn >> 20) & 1
        Rn = (insn >> 16) & 0xf
        Rd = (insn >> 12) & 0xf
        SH = (insn >> 5) & 3
        
        ops = {1: ('H', L), 2: ('SB', 1), 3: ('SH', 1)}
        if SH in ops:
            suffix, is_load = ops[SH]
            op = 'LDR' if is_load else 'STR'
            if I:
                hi = (insn >> 8) & 0xf
                lo = insn & 0xf
                offset = (hi << 4) | lo
                sign = '+' if U else '-'
                return f"{op}{cs}{suffix}\t{REGS[Rd]}, [{REGS[Rn]}, #{sign}{offset}]"
            else:
                Rm = insn & 0xf
                sign = '+' if U else '-'
                return f"{op}{cs}{suffix}\t{REGS[Rd]}, [{REGS[Rn]}, {sign}{REGS[Rm]}]"
    
    # MUL/MLA
    if (insn & 0x0FC000F0) == 0x00000090:
        Rd = (insn >> 16) & 0xf
        Rn = (insn >> 12) & 0xf
        Rs = (insn >> 8) & 0xf
        Rm = insn & 0xf
        A = (insn >> 21) & 1
        S = (insn >> 20) & 1
        if A:
            return f"MLA{cs}{'S' if S else ''}\t{REGS[Rd]}, {REGS[Rm]}, {REGS[Rs]}, {REGS[Rn]}"
        else:
            return f"MUL{cs}{'S' if S else ''}\t{REGS[Rd]}, {REGS[Rm]}, {REGS[Rs]}"
    
    # SWI
    if (insn & 0x0F000000) == 0x0F000000:
        return f"SWI{cs}\t#0x{insn & 0x00FFFFFF:x}"
    
    # MCR/MRC
    if (insn & 0x0F000010) == 0x0E000010:
        L = (insn >> 20) & 1
        return f"{'MRC' if L else 'MCR'}{cs}\t..."
    
    return f"DCD\t0x{insn:08x}"

# ACI_dev_ioctl
ioctl_sym = symbols['ACI_dev_ioctl']
ioctl_offset = ioctl_sym['value']  # offset in .text
ioctl_size = ioctl_sym['size']
ioctl_file_offset = text_sect['offset'] + ioctl_offset
ioctl_bytes = data[ioctl_file_offset:ioctl_file_offset+ioctl_size]

print(f"\n{'='*60}")
print(f"ACI_dev_ioctl disassembly")
print(f"  .text offset: 0x{ioctl_offset:x}")
print(f"  File offset:  0x{ioctl_file_offset:x}")
print(f"  Size:         {ioctl_size} bytes ({ioctl_size//4} instructions)")
print(f"{'='*60}")

# Build symbol lookup for .text references
text_syms = {}
for name, sym in symbols.items():
    if sym['shndx'] == 1:  # .text section index
        text_syms[sym['value']] = name

for i in range(0, ioctl_size, 4):
    insn = struct.unpack_from('<I', ioctl_bytes, i)[0]
    pc = ioctl_offset + i
    decoded = decode_arm(insn, pc)
    
    # Check if this address has a symbol
    sym_label = text_syms.get(pc, '')
    if sym_label:
        print(f"\n  ; --- {sym_label} ---")
    
    print(f"  {pc:04x}:  {insn:08x}  {decoded}")

# Now analyze ioctl command numbers
print(f"\n{'='*60}")
print("IOCTL Command Number Analysis")
print(f"{'='*60}")

# Extract all CMP instructions and immediate values
print("\nAll CMP instructions in ACI_dev_ioctl:")
for i in range(0, ioctl_size, 4):
    insn = struct.unpack_from('<I', ioctl_bytes, i)[0]
    # CMP immediate: cccc 0011 0101 Rn__ xxxx rotate imm8
    if (insn & 0x0FF00000) == 0x03500000:
        Rn = (insn >> 16) & 0xf
        rotate = ((insn >> 8) & 0xf) * 2
        imm8 = insn & 0xff
        if rotate:
            imm = ((imm8 >> rotate) | (imm8 << (32 - rotate))) & 0xffffffff
        else:
            imm = imm8
        pc = ioctl_offset + i
        print(f"  {pc:04x}: CMP {REGS[Rn]}, #0x{imm:x} ({imm})")

# Also look for SUB+CMP pattern (switch statement optimization)
print("\nAll SUB instructions with immediate:")
for i in range(0, ioctl_size, 4):
    insn = struct.unpack_from('<I', ioctl_bytes, i)[0]
    if (insn & 0x0FE00000) == 0x02400000:  # SUB immediate
        S = (insn >> 20) & 1
        Rn = (insn >> 16) & 0xf
        Rd = (insn >> 12) & 0xf
        rotate = ((insn >> 8) & 0xf) * 2
        imm8 = insn & 0xff
        if rotate:
            imm = ((imm8 >> rotate) | (imm8 << (32 - rotate))) & 0xffffffff
        else:
            imm = imm8
        pc = ioctl_offset + i
        print(f"  {pc:04x}: SUB{'S' if S else ''} {REGS[Rd]}, {REGS[Rn]}, #0x{imm:x} ({imm})")

# Look for LDR r15, [pc, Rx, LSL #2] - jump table
print("\nPotential jump table instructions (LDR pc, ...):")
for i in range(0, ioctl_size, 4):
    insn = struct.unpack_from('<I', ioctl_bytes, i)[0]
    Rd = (insn >> 12) & 0xf
    if Rd == 15:  # pc
        pc = ioctl_offset + i
        decoded = decode_arm(insn, pc)
        print(f"  {pc:04x}: {decoded}")

# Print literal pool data at end
print("\n=== Data at end of function ===")
# Look for 4-byte values that look like ioctl constants
for i in range(0, ioctl_size, 4):
    val = struct.unpack_from('<I', ioctl_bytes, i)[0]
    # Check if it looks like an ioctl number with type 'P' (0x50)
    if (val & 0x0000FF00) == 0x00005000:
        nr = val & 0xff
        dir_val = (val >> 30) & 3
        size_val = (val >> 16) & 0x3fff
        dir_names = {0:'_IO', 1:'_IOW', 2:'_IOR', 3:'_IOWR'}
        pc = ioctl_offset + i
        print(f"  {pc:04x}: 0x{val:08x} = {dir_names.get(dir_val,'?')}('P', {nr}) size={size_val}")

# Also look at ACI_fops to verify function pointers
print(f"\n{'='*60}")
print("ACI_fops (file_operations)")
print(f"{'='*60}")

# ACI_fops is in .data section
fops_sym = symbols.get('ACI_fops')
if fops_sym:
    data_sect2 = sections[fops_sym['shndx']]
    fops_off = data_sect2['offset'] + fops_sym['value']
    fops_size = fops_sym['size']
    fops_data2 = data[fops_off:fops_off+fops_size]
    
    # Read relocations for .data section
    rel_data_sect = next((s for s in sections if s['name'] == '.rel.data'), None)
    relocations = {}
    if rel_data_sect:
        for ri in range(rel_data_sect['size'] // 8):
            roff = rel_data_sect['offset'] + ri * 8
            r_offset = struct.unpack_from('<I', data, roff)[0]
            r_info = struct.unpack_from('<I', data, roff+4)[0]
            r_sym = r_info >> 8
            r_type = r_info & 0xff
            
            # Get symbol name
            sym_off = symtab_sect['offset'] + r_sym * 16
            sym_name_off = struct.unpack_from('<I', data, sym_off)[0]
            sym_name = get_sym_name(sym_name_off) if sym_name_off else '<none>'
            sym_val = struct.unpack_from('<I', data, sym_off+4)[0]
            
            relocations[r_offset] = (sym_name, sym_val, r_type)
    
    # Linux 2.6.17 struct file_operations field order
    fops_fields = ['owner', 'llseek', 'read', 'write', 'readdir', 'poll',
                   'ioctl', 'mmap', 'open', 'flush', 'release', 'fsync',
                   'aio_fsync', 'fasync', 'lock', 'readv', 'writev',
                   'sendfile', 'sendpage', 'get_unmapped_area', 'check_flags']
    
    for k, fname in enumerate(fops_fields):
        field_off = k * 4
        if field_off + 4 > len(fops_data2):
            break
        val = struct.unpack_from('<I', fops_data2, field_off)[0]
        
        # Check relocations
        abs_off = fops_sym['value'] + field_off + data_sect2['offset']  # approximate
        rel_off_in_data = fops_sym['value'] + field_off
        
        if val:
            print(f"  {fname:20s}: 0x{val:08x}")
        else:
            # Check if there's a relocation for this field
            rel_key = rel_off_in_data
            if rel_key in relocations:
                sym_name, sym_val, rtype = relocations[rel_key]
                print(f"  {fname:20s}: -> {sym_name} (reloc)")
            else:
                print(f"  {fname:20s}: NULL")

# Extract strings from .rodata section
print(f"\n{'='*60}")
print(".rodata section (version/func names)")
print(f"{'='*60}")
if rodata_sect:
    rd = data[rodata_sect['offset']:rodata_sect['offset']+rodata_sect['size']]
    i = 0
    while i < len(rd):
        end = rd.find(b'\x00', i)
        if end < 0: break
        s = rd[i:end]
        if len(s) > 0:
            try:
                t = s.decode('ascii')
                print(f"  [{i:04x}] {t}")
            except:
                pass
        i = end + 1
        while i < len(rd) and rd[i] == 0:
            i += 1

# Check aci_hw_settings
print(f"\n{'='*60}")
print("aci_hw_settings")
print(f"{'='*60}")
hw_sym = symbols.get('aci_hw_settings')
if hw_sym:
    data_sect2 = sections[hw_sym['shndx']]
    hw_off = data_sect2['offset'] + hw_sym['value']
    hw_size = hw_sym['size']
    hw_data = data[hw_off:hw_off+hw_size]
    for j in range(0, hw_size, 4):
        val = struct.unpack_from('<I', hw_data, j)[0]
        print(f"  [{j:2d}] 0x{val:08x} ({val})")
