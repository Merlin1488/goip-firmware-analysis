#!/usr/bin/env python3
"""Analyze fvaci.ko ELF structure and disassemble ACI_dev_ioctl"""
import struct
import sys

KO_PATH = r'c:\goip\extracted\fvaci.ko'

with open(KO_PATH, 'rb') as f:
    data = f.read()

print(f"File size: {len(data)}")
print(f"Magic: {data[:4]}")
print(f"EI_CLASS: {data[4]} (1=32bit, 2=64bit)")
print(f"EI_DATA: {data[5]} (1=LE, 2=BE)")

if data[:4] != b'\x7fELF':
    print("NOT an ELF file!")
    sys.exit(1)

le = data[5] == 1
fmt = '<' if le else '>'

# ELF header for 32-bit
e_type = struct.unpack_from(f'{fmt}H', data, 16)[0]
e_machine = struct.unpack_from(f'{fmt}H', data, 18)[0]
e_shoff = struct.unpack_from(f'{fmt}I', data, 32)[0]
e_shentsize = struct.unpack_from(f'{fmt}H', data, 46)[0]
e_shnum = struct.unpack_from(f'{fmt}H', data, 48)[0]
e_shstrndx = struct.unpack_from(f'{fmt}H', data, 50)[0]

print(f"Type: {e_type} (1=REL, 2=EXEC, 3=DYN)")
print(f"Machine: {e_machine} (40=ARM)")
print(f"Section header offset: {e_shoff}")
print(f"Section header entry size: {e_shentsize}")
print(f"Number of sections: {e_shnum}")
print(f"Section name string table index: {e_shstrndx}")

# Read section headers
sections = []
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    sh_name = struct.unpack_from(f'{fmt}I', data, off)[0]
    sh_type = struct.unpack_from(f'{fmt}I', data, off+4)[0]
    sh_flags = struct.unpack_from(f'{fmt}I', data, off+8)[0]
    sh_addr = struct.unpack_from(f'{fmt}I', data, off+12)[0]
    sh_offset = struct.unpack_from(f'{fmt}I', data, off+16)[0]
    sh_size = struct.unpack_from(f'{fmt}I', data, off+20)[0]
    sh_link = struct.unpack_from(f'{fmt}I', data, off+24)[0]
    sh_info = struct.unpack_from(f'{fmt}I', data, off+28)[0]
    sh_addralign = struct.unpack_from(f'{fmt}I', data, off+32)[0]
    sh_entsize = struct.unpack_from(f'{fmt}I', data, off+36)[0]
    sections.append({
        'name_off': sh_name, 'type': sh_type, 'flags': sh_flags,
        'addr': sh_addr, 'offset': sh_offset, 'size': sh_size,
        'link': sh_link, 'info': sh_info, 'addralign': sh_addralign,
        'entsize': sh_entsize
    })

# Get section names
shstrtab = sections[e_shstrndx]
strtab_data = data[shstrtab['offset']:shstrtab['offset']+shstrtab['size']]

def get_str(offset):
    end = strtab_data.index(b'\x00', offset)
    return strtab_data[offset:end].decode('ascii', errors='replace')

print("\n=== Sections ===")
text_sections = {}
symtab_idx = None
strtab_idx = None

for i, s in enumerate(sections):
    name = get_str(s['name_off'])
    s['name'] = name
    type_names = {0:'NULL', 1:'PROGBITS', 2:'SYMTAB', 3:'STRTAB', 4:'RELA', 8:'NOBITS', 9:'REL'}
    tname = type_names.get(s['type'], f"type={s['type']}")
    flags_str = ''
    if s['flags'] & 1: flags_str += 'W'
    if s['flags'] & 2: flags_str += 'A'
    if s['flags'] & 4: flags_str += 'X'
    print(f"  [{i:2d}] {name:30s} {tname:10s} off={s['offset']:6x} size={s['size']:6x} flags={flags_str}")
    
    if name.startswith('.text') and s['type'] == 1:
        text_sections[name] = i
    if s['type'] == 2:  # SYMTAB
        symtab_idx = i
    if name == '.strtab' and s['type'] == 3:
        strtab_idx = i

# Read symbol table
if symtab_idx is not None and strtab_idx is not None:
    symtab = sections[symtab_idx]
    sym_strtab = sections[strtab_idx]
    sym_str_data = data[sym_strtab['offset']:sym_strtab['offset']+sym_strtab['size']]
    
    def get_sym_str(offset):
        end = sym_str_data.index(b'\x00', offset)
        return sym_str_data[offset:end].decode('ascii', errors='replace')
    
    num_syms = symtab['size'] // symtab['entsize']
    
    print(f"\n=== Symbols (total: {num_syms}) ===")
    print("Key ACI symbols:")
    
    aci_syms = {}
    for i in range(num_syms):
        off = symtab['offset'] + i * symtab['entsize']
        st_name = struct.unpack_from(f'{fmt}I', data, off)[0]
        st_value = struct.unpack_from(f'{fmt}I', data, off+4)[0]
        st_size = struct.unpack_from(f'{fmt}I', data, off+8)[0]
        st_info = data[off+12]
        st_shndx = struct.unpack_from(f'{fmt}H', data, off+14)[0]
        
        name = get_sym_str(st_name) if st_name else ''
        
        bind = st_info >> 4
        stype = st_info & 0xf
        
        if 'ACI' in name or 'aci' in name:
            sect_name = sections[st_shndx]['name'] if st_shndx < len(sections) else f'shndx={st_shndx}'
            bind_str = {0:'LOCAL', 1:'GLOBAL', 2:'WEAK'}.get(bind, f'bind={bind}')
            type_str = {0:'NOTYPE', 1:'OBJECT', 2:'FUNC', 13:'LOPROC'}.get(stype, f'type={stype}')
            print(f"  {name:40s} val={st_value:08x} size={st_size:5d} {bind_str:7s} {type_str:7s} sect={sect_name}")
            aci_syms[name] = {'value': st_value, 'size': st_size, 'shndx': st_shndx, 'type': stype}
    
    # Find ACI_dev_ioctl
    if 'ACI_dev_ioctl' in aci_syms:
        sym = aci_syms['ACI_dev_ioctl']
        shndx = sym['shndx']
        sect = sections[shndx]
        file_offset = sect['offset'] + sym['value']
        size = sym['size']
        print(f"\n=== ACI_dev_ioctl ===")
        print(f"  Section: {sect['name']} (#{shndx})")
        print(f"  Value (offset in section): 0x{sym['value']:x}")
        print(f"  Size: {size} bytes")
        print(f"  File offset: 0x{file_offset:x}")
        
        # Dump the raw bytes
        ioctl_bytes = data[file_offset:file_offset+size]
        print(f"  First 64 bytes hex: {ioctl_bytes[:64].hex()}")
        
        # Try to find ioctl command numbers (ARM immediate values)
        # In ARM, ioctl numbers are typically loaded with MOV/MOVT or LDR from literal pool
        # Common pattern: CMP reg, #imm
        print(f"\n  --- Raw ARM instructions (first 40) ---")
        for j in range(0, min(size, 160), 4):
            insn = struct.unpack_from('<I', ioctl_bytes, j)[0]
            # Decode basic ARM instruction
            cond = (insn >> 28) & 0xf
            cond_str = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV'][cond]
            
            desc = ''
            # Check if it's a data processing instruction
            if (insn & 0x0C000000) == 0x00000000:
                op = (insn >> 21) & 0xf
                I = (insn >> 25) & 1
                S = (insn >> 20) & 1
                Rn = (insn >> 16) & 0xf
                Rd = (insn >> 12) & 0xf
                
                ops = ['AND','EOR','SUB','RSB','ADD','ADC','SBC','RSC','TST','TEQ','CMP','CMN','ORR','MOV','BIC','MVN']
                
                if I:  # immediate
                    rotate = ((insn >> 8) & 0xf) * 2
                    imm8 = insn & 0xff
                    imm = (imm8 >> rotate) | (imm8 << (32 - rotate)) if rotate else imm8
                    imm &= 0xffffffff
                    
                    if op == 10:  # CMP
                        desc = f"CMP r{Rn}, #0x{imm:x} ({imm})"
                    elif op == 13:  # MOV
                        desc = f"MOV r{Rd}, #0x{imm:x}"
                    elif op == 1:  # EOR
                        desc = f"EOR r{Rd}, r{Rn}, #0x{imm:x}"
                    elif op == 4:  # ADD
                        desc = f"ADD r{Rd}, r{Rn}, #0x{imm:x}"
                    elif op == 2:  # SUB
                        desc = f"SUB r{Rd}, r{Rn}, #0x{imm:x}"
                    else:
                        desc = f"{ops[op]} r{Rd}, r{Rn}, #0x{imm:x}"
                else:
                    Rm = insn & 0xf
                    if op == 10:  # CMP
                        desc = f"CMP r{Rn}, r{Rm}"
                    elif op == 13:  # MOV
                        desc = f"MOV r{Rd}, r{Rm}"
                    else:
                        desc = f"{ops[op]} r{Rd}, r{Rn}, r{Rm}"
            
            elif (insn & 0x0F000000) == 0x0A000000:  # Branch
                offset = insn & 0x00FFFFFF
                if offset & 0x800000: offset |= 0xFF000000
                offset = (offset << 2) + 8
                L = (insn >> 24) & 1
                desc = f"{'BL' if L else 'B'} PC+0x{offset & 0xffffffff:x}"
            
            elif (insn & 0x0C000000) == 0x04000000:  # LDR/STR
                L = (insn >> 20) & 1
                B = (insn >> 22) & 1
                Rn = (insn >> 16) & 0xf
                Rd = (insn >> 12) & 0xf
                offset12 = insn & 0xfff
                U = (insn >> 23) & 1
                P = (insn >> 24) & 1
                desc = f"{'LDR' if L else 'STR'}{'B' if B else ''} r{Rd}, [r{Rn}, #{'+'if U else '-'}{offset12}]"
            
            print(f"    {j:04x}: {insn:08x}  {cond_str} {desc}")
        
        # Look for literal pool values near the end of the function
        # These might contain ioctl command numbers
        if size > 64:
            print(f"\n  --- Literal pool (last {min(128, size-size//2)} bytes) ---")
            pool_start = size - min(128, size - size//2)
            # Align to 4
            pool_start = (pool_start) & ~3
            for j in range(pool_start, size, 4):
                val = struct.unpack_from('<I', ioctl_bytes, j)[0]
                print(f"    {j:04x}: {val:08x}")
    
    # Also look at ACI_fops to understand the file_operations layout
    if 'ACI_fops' in aci_syms:
        sym = aci_syms['ACI_fops']
        shndx = sym['shndx']
        sect = sections[shndx]
        file_offset = sect['offset'] + sym['value']
        size = sym['size'] if sym['size'] else 64  # typical file_operations is ~56 bytes on 2.6.17
        fops_bytes = data[file_offset:file_offset+size]
        print(f"\n=== ACI_fops at file offset 0x{file_offset:x} ===")
        # Linux 2.6.17 struct file_operations (32bit ARM):
        # owner, llseek, read, write, readdir, poll, ioctl, mmap, open, flush, release, ...
        fops_fields = ['owner', 'llseek', 'read', 'write', 'readdir', 'poll', 'ioctl', 'mmap', 'open', 'flush', 'release', 'fsync', 'aio_fsync', 'fasync', 'lock', 'readv', 'writev']
        for k, name in enumerate(fops_fields):
            if k*4 + 4 > len(fops_bytes): break
            val = struct.unpack_from('<I', fops_bytes, k*4)[0]
            if val:
                print(f"  {name:15s}: 0x{val:08x}")
            else:
                print(f"  {name:15s}: NULL")
