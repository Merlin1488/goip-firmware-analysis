#!/usr/bin/env python3
"""Disassemble key libtdi.so functions to map ioctl calls"""
import struct

TDI_PATH = r'c:\goip\extracted\libtdi.so'
with open(TDI_PATH, 'rb') as f:
    tdi = f.read()

REGS = ['r0','r1','r2','r3','r4','r5','r6','r7','r8','r9','r10','r11','r12','sp','lr','pc']

def decode_arm(insn, addr, data):
    """Decode ARM instruction to string"""
    cond = (insn >> 28) & 0xF
    conds = ['eq','ne','cs','cc','mi','pl','vs','vc','hi','ls','ge','lt','gt','le','','nv']
    cs = conds[cond]
    
    if (insn & 0x0F000000) == 0x0F000000:
        return f"SWI{cs} #0x{insn & 0x00FFFFFF:06x}"
    
    if (insn & 0x0E000000) == 0x0A000000:
        L = (insn >> 24) & 1
        off = insn & 0x00FFFFFF
        if off & 0x800000: off -= 0x1000000
        target = addr + 8 + off * 4
        return f"B{'L' if L else ''}{cs} 0x{target:x}"
    
    # Data processing
    if (insn & 0x0C000000) == 0x00000000:
        I = (insn >> 25) & 1
        opcode = (insn >> 21) & 0xF
        S = (insn >> 20) & 1
        Rn = (insn >> 16) & 0xF
        Rd = (insn >> 12) & 0xF
        ops = ['AND','EOR','SUB','RSB','ADD','ADC','SBC','RSC','TST','TEQ','CMP','CMN','ORR','MOV','BIC','MVN']
        op = ops[opcode]
        if I:
            imm8 = insn & 0xFF
            rot = (insn >> 8) & 0xF
            val = (imm8 >> (rot*2)) | (imm8 << (32 - rot*2)) & 0xFFFFFFFF
            op2 = f"#0x{val:x}" if val > 9 else f"#{val}"
        else:
            Rm = insn & 0xF
            shift_type = (insn >> 5) & 3
            shift_imm = (insn >> 7) & 0x1F
            shtypes = ['LSL','LSR','ASR','ROR']
            if shift_imm == 0 and shift_type == 0:
                op2 = REGS[Rm]
            else:
                op2 = f"{REGS[Rm]}, {shtypes[shift_type]} #{shift_imm}"
        
        if opcode in (13, 15):  # MOV, MVN
            return f"{op}{cs}{'S' if S else ''} {REGS[Rd]}, {op2}"
        elif opcode in (8, 9, 10, 11):  # TST, TEQ, CMP, CMN
            return f"{op}{cs} {REGS[Rn]}, {op2}"
        else:
            return f"{op}{cs}{'S' if S else ''} {REGS[Rd]}, {REGS[Rn]}, {op2}"
    
    # LDR/STR
    if (insn & 0x0C000000) == 0x04000000:
        I = (insn >> 25) & 1
        P = (insn >> 24) & 1
        U = (insn >> 23) & 1
        B = (insn >> 22) & 1
        W = (insn >> 21) & 1
        L = (insn >> 20) & 1
        Rn = (insn >> 16) & 0xF
        Rd = (insn >> 12) & 0xF
        off12 = insn & 0xFFF
        op = 'LDR' if L else 'STR'
        if B: op += 'B'
        sign = '+' if U else '-'
        if Rn == 15 and P and not I:
            target = (addr + 8 + off12) if U else (addr + 8 - off12)
            if 0 <= target < len(data):
                val = struct.unpack_from('<I', data, target)[0]
                return f"{op}{cs} {REGS[Rd]}, =0x{val:08x}  ; [pool@0x{target:x}]"
            return f"{op}{cs} {REGS[Rd]}, [pc, #{sign}{off12}]"
        if P:
            if off12 == 0:
                return f"{op}{cs} {REGS[Rd]}, [{REGS[Rn]}]{'!' if W else ''}"
            return f"{op}{cs} {REGS[Rd]}, [{REGS[Rn]}, #{sign}{off12}]{('!' if W else '')}"
        else:
            return f"{op}{cs} {REGS[Rd]}, [{REGS[Rn]}], #{sign}{off12}"
    
    # LDM/STM
    if (insn & 0x0E000000) == 0x08000000:
        P = (insn >> 24) & 1
        U = (insn >> 23) & 1
        S = (insn >> 22) & 1
        W = (insn >> 21) & 1
        L = (insn >> 20) & 1
        Rn = (insn >> 16) & 0xF
        reglist = insn & 0xFFFF
        regs = [REGS[i] for i in range(16) if reglist & (1 << i)]
        modes = {(0,1):'DA',(0,0):'DB',(1,1):'IA',(1,0):'IB'}
        mode = modes.get((U,P),'')
        op = 'LDM' if L else 'STM'
        w = '!' if W else ''
        return f"{op}{cs}{mode} {REGS[Rn]}{w}, {{{','.join(regs)}}}"
    
    # MUL
    if (insn & 0x0FC000F0) == 0x00000090:
        Rd = (insn >> 16) & 0xF
        Rn = (insn >> 12) & 0xF
        Rs = (insn >> 8) & 0xF
        Rm = insn & 0xF
        S = (insn >> 20) & 1
        A = (insn >> 21) & 1
        if A:
            return f"MLA{cs}{'S' if S else ''} {REGS[Rd]}, {REGS[Rm]}, {REGS[Rs]}, {REGS[Rn]}"
        else:
            return f"MUL{cs}{'S' if S else ''} {REGS[Rd]}, {REGS[Rm]}, {REGS[Rs]}"

    return f"??? 0x{insn:08x}"

# Parse ELF for .text section and symbol table
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

# Get .symtab (static symbols) - richer than .dynsym
symtab = next((s for s in sections if s['name'] == '.symtab'), None)
strtab = next((s for s in sections if s['name'] == '.strtab'), None)

symbols = {}
if symtab and strtab:
    strs = tdi[strtab['offset']:strtab['offset']+strtab['size']]
    num_syms = symtab['size'] // 16
    for i in range(num_syms):
        off = symtab['offset'] + i * 16
        st_name = struct.unpack_from('<I', tdi, off)[0]
        st_value = struct.unpack_from('<I', tdi, off+4)[0]
        st_size = struct.unpack_from('<I', tdi, off+8)[0]
        if st_name and st_value:
            end = strs.index(b'\x00', st_name)
            name = strs[st_name:end].decode()
            if st_size > 0:
                symbols[st_value] = (name, st_size)

# .text section
text = next((s for s in sections if s['name'] == '.text'), None)

# Also get PLT for ioctl call resolution
plt = next((s for s in sections if s['name'] == '.plt'), None)

# Find ioctl PLT entry by searching .rel.plt
relplt = next((s for s in sections if s['name'] == '.rel.plt'), None)
dynsym = next((s for s in sections if s['name'] == '.dynsym'), None)
dynstr = next((s for s in sections if s['name'] == '.dynstr'), None)

plt_entries = {}
if relplt and dynsym and dynstr and plt:
    dstr = tdi[dynstr['offset']:dynstr['offset']+dynstr['size']]
    num_rels = relplt['size'] // 8
    for i in range(num_rels):
        off = relplt['offset'] + i * 8
        r_offset = struct.unpack_from('<I', tdi, off)[0]
        r_info = struct.unpack_from('<I', tdi, off + 4)[0]
        sym_idx = r_info >> 8
        if sym_idx > 0:
            soff = dynsym['offset'] + sym_idx * 16
            st_name = struct.unpack_from('<I', tdi, soff)[0]
            end = dstr.index(b'\x00', st_name)
            name = dstr[st_name:end].decode()
            # PLT stub = plt start + (i+1) * 12 (standard ARM PLT layout)
            plt_addr = plt['addr'] + (i + 1) * 12
            plt_entries[plt_addr] = name

print("PLT entries:")
for addr, name in sorted(plt_entries.items()):
    print(f"  0x{addr:06x}: {name}")

# Functions to disassemble
targets = [
    ('fv_tdi_open', 0x57e0, 280),
    ('fv_tdi_ctrl', 0x5cb0, 40),
    ('fv_tdi_close', 0x58f8, 96),
    ('fv_tdi_init', 0x5728, 76),
    ('fv_tdi_get_event', 0x5ab0, 40),
    ('fv_tdi_play', 0x5a68, 32),
    ('fv_tdi_record', 0x5a48, 32),
    ('fv_tdi_hookstate', 0x5a88, 40),
    ('fv_tdi_set_bufsz', 0x5b90, 64),
    ('fv_tdi_playstart', 0x59a8, 40),
    ('fv_tdi_playstop', 0x59d0, 40),
    ('fv_tdi_recordstart', 0x59f8, 40),
    ('fv_tdi_recordstop', 0x5a20, 40),
    ('fv_tdi_tonestart', 0x5958, 40),
    ('fv_tdi_tonestop', 0x5980, 40),
    ('fv_tdi_reset', 0x5ad8, 32),
    ('fv_tdi_offhook', 0x5af8, 40),
    ('fv_tdi_onhook', 0x5b20, 40),
    ('fv_tdi_set_tx_gain', 0x5bd0, 52),
    ('fv_tdi_set_rx_gain', 0x5c04, 52),
    ('fv_tdi_polarity_reversal', 0x5c38, 40),
    ('fv_tdi_polarity_normal', 0x5c60, 40),
    ('fv_tdi_get_status', 0x5c88, 40),
    ('fv_tdi_func_register', 0x5cd8, 100),
    ('fv_tdi_slic_open', 0x7280, 740),
    ('fv_tdi_snd_open', 0xffb0, 752),
    ('fv_tdi_snd_ctrl', 0x105d8, 376),
]

# Since this is a shared library, addr == file offset (no load offset for our purposes)
# Actually for ET_DYN, we need to check program headers
e_phoff = struct.unpack_from('<I', tdi, 28)[0]
e_phentsize = struct.unpack_from('<H', tdi, 42)[0]
e_phnum = struct.unpack_from('<H', tdi, 44)[0]

print(f"\nProgram headers (to map vaddr to file offset):")
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type = struct.unpack_from('<I', tdi, off)[0]
    p_offset = struct.unpack_from('<I', tdi, off+4)[0]
    p_vaddr = struct.unpack_from('<I', tdi, off+8)[0]
    p_filesz = struct.unpack_from('<I', tdi, off+16)[0]
    p_memsz = struct.unpack_from('<I', tdi, off+20)[0]
    types = {0:'NULL',1:'LOAD',2:'DYNAMIC',3:'INTERP',4:'NOTE',6:'PHDR',0x70000001:'ARM_EXIDX'}
    tname = types.get(p_type, f'0x{p_type:x}')
    print(f"  [{i}] {tname:12s} offset=0x{p_offset:06x} vaddr=0x{p_vaddr:08x} filesz=0x{p_filesz:x} memsz=0x{p_memsz:x}")

# For ET_DYN, typically the first LOAD segment has offset=0, vaddr=0, so file offset == vaddr
# Let's verify with .text section
print(f"\n.text section: addr=0x{text['addr']:x}, offset=0x{text['offset']:x}, size=0x{text['size']:x}")
print(f"  addr - offset = 0x{text['addr'] - text['offset']:x}")

# file_offset = vaddr - load_vaddr + load_offset
# For most shared libs, load_vaddr == load_offset, so file_offset == vaddr
vaddr_to_file = text['offset'] - text['addr']  # should be 0 for typical .so

print(f"\nDisassembling {len(targets)} functions from libtdi.so:")
print(f"vaddr_to_file adjustment: {vaddr_to_file}")

for fname, vaddr, size in targets:
    foff = vaddr + vaddr_to_file
    print(f"\n{'='*70}")
    print(f"{fname} @ 0x{vaddr:06x} ({size} bytes, {size//4} instructions)")
    print('='*70)
    for i in range(0, size, 4):
        a = vaddr + i
        off = foff + i
        if off + 4 > len(tdi):
            print(f"  0x{a:06x}: <past end of file>")
            break
        insn = struct.unpack_from('<I', tdi, off)[0]
        dis = decode_arm(insn, a, tdi)
        
        # Annotate BL targets with symbol names
        if 'BL' in dis and '0x' in dis:
            try:
                target_str = dis.split('0x')[1].rstrip()
                target_addr = int(target_str, 16)
                if target_addr in plt_entries:
                    dis += f"  ; <{plt_entries[target_addr]}>"
                elif target_addr in symbols:
                    dis += f"  ; <{symbols[target_addr][0]}>"
            except:
                pass
        
        print(f"  0x{a:06x}: {insn:08x}  {dis}")
