#!/usr/bin/env python3
"""Trace ACI_dev_ioctl command tree and analyze fvdsp usage"""
import struct

KO_PATH = r'c:\goip\extracted\fvaci.ko'
FVDSP_PATH = r'c:\goip\extracted\fvdsp'

# ============================================================
# Part 1: Decode all ioctl commands from the binary search tree
# ============================================================

# From the disassembly, the literal pool contains these reference values:
# At 0x634: 0x00005009 = _IO('P', 9)
# At 0x638: 0x00005007 = _IO('P', 7)
# At 0x63c: 0x4004500b = _IOW('P', 11, int)
# At 0x640: 0x8004500d = _IOR('P', 13, int)

# The binary search tree in the ioctl handler:
# Root compares with _IO('P', 9) = 0x00005009

def decode_ioctl(val):
    nr = val & 0xff
    typ = (val >> 8) & 0xff
    size = (val >> 16) & 0x3fff
    dir_val = (val >> 30) & 3
    dir_names = {0: '_IO', 1: '_IOW', 2: '_IOR', 3: '_IOWR'}
    if size:
        return f"{dir_names[dir_val]}('{chr(typ)}', {nr}, size={size})"
    else:
        return f"{dir_names[dir_val]}('{chr(typ)}', {nr})"

# Traced from the binary search tree in ACI_dev_ioctl:
commands = {
    0x00005002: ('_IO(P, 2)',  0x458, 'SET_TX_FLAG', 'Sets transmit flag: private[40] = 1'),
    0x00005003: ('_IO(P, 3)',  0x468, 'RESET_CHANNEL', 'Reset channel: disable IRQ if active, reset counters, set frame_size=320'),
    0x00005004: ('_IO(P, 4)',  0x4cc, 'ENABLE (same as 6)', 'Enable IRQ, set state=-1 (active)'),
    0x00005005: ('_IO(P, 5)',  0x4a8, 'DISABLE', 'Disable IRQ if active, clear state'),
    0x00005006: ('_IO(P, 6)',  0x4cc, 'ENABLE (same as 4)', 'Enable IRQ, set state=-1 (active)'),
    0x00005007: ('_IO(P, 7)',  0x4f8, 'SET_SUPPLEMENT', 'Set bit 4 of control register byte'),
    0x00005008: ('_IO(P, 8)',  0x50c, 'CLR_SUPPLEMENT', 'Clear bit 4 of control register byte'),
    0x00005009: ('_IO(P, 9)',  0x564, 'FULL_RESET', 'Full reset: clear 13 fields, set frame_size=320'),
    0x40045000: ('_IOW(P, 0, int)', 0x444, 'SET_VALUE', 'get_user(val, arg); private[56] = val'),
    0x40045001: ('_IOW(P, 1, int)', 0x628, 'NOP', 'No operation, returns 0'),
    0x4004500a: ('_IOW(P, 10, int)', 0x524, 'SET_FRAME_PARAM', 'Set frame size parameter from userspace'),
    0x4004500b: ('_IOW(P, 11, int)', 0x5a8, 'SET_EVENT_MASK', 'OR event bits into mask at private[1188]'),
    0x4004500c: ('_IOW(P, 12, int)', 0x5d0, 'CLR_EVENT_MASK', 'Clear event bits from mask at private[1188]'),
    0x8004500d: ('_IOR(P, 13, int)', 0x5ec, 'GET_EVENTS', 'Read+clear pending events from private[1192]'),
    0x8004500e: ('_IOR(P, 14, int)', 0x610, 'CALL_FUNC', 'Call function(private_data, arg)'),
}

print("=" * 70)
print("FVACI IOCTL Command Table")
print("=" * 70)
print(f"{'Value':>12s}  {'Macro':25s} {'Name':20s} Description")
print("-" * 70)
for val in sorted(commands.keys()):
    macro, handler, name, desc = commands[val]
    print(f"  0x{val:08x}  {macro:25s} {name:20s} {desc}")

# Error return values:
# -ENOTTY (-25 = 0xFFFFFFE7 → MVN r1, #0x18 = -25): wrong ioctl type (not 'P') or nr > 15
# -EFAULT (-14 = 0xFFFFFFF2 → MVN r1, #0xd = -14): access_ok failed  
# -EINVAL (-22 = 0xFFFFFFEA → MVN r1, #0x15 = -22): unknown command number

print(f"\nError codes:")
print(f"  -ENOTTY (-25): wrong ioctl type (not 'P') or nr > 15")
print(f"  -EFAULT (-14): access_ok() failed (bad userspace pointer)")
print(f"  -EINVAL (-22): unknown/unsupported command number")

# ============================================================
# Part 2: Private data structure offsets
# ============================================================
print(f"\n{'=' * 70}")
print("Private Data Structure Offsets (from ioctl handler)")
print("=" * 70)
offsets = {
    16: 'ctrl_reg_ptr (pointer to control register struct)',
    20: 'irq_number (used with enable_irq/disable_irq)',
    40: 'tx_flag (set to 1 by cmd 2)',
    44: 'state (-1=active, 0=idle)',
    56: 'user_value (set by cmd 0)',
    60: 'frame_param (set by cmd 10)',
    64: 'frame_param2 (derived)',
    68: 'counter1 (cleared by reset)',
    116: '(struct file->private_data pointer offset)',
    120: 'counter2',
    124: 'counter3',
    156: 'counter4',
    160: 'counter5',
    164: 'frame_size (set to 320 on reset)',
    168: 'counter6',
    500: 'counter7',
    504: 'counter8',
    508: 'frame_size2 (set to 320 on reset)',
    512: 'counter9',
    516: 'counter10',
    520: 'counter11',
    1188: 'event_mask (bits set/cleared by cmds 11/12, 0x4A4)',
    1192: 'event_pending (read/cleared by cmd 13, 0x4A8)',
}
for off in sorted(offsets.keys()):
    print(f"  +{off:4d} (0x{off:03x}): {offsets[off]}")

# ============================================================
# Part 3: Analyze fvdsp binary for ioctl usage
# ============================================================
print(f"\n{'=' * 70}")
print("Searching fvdsp binary for ACI ioctl constants")
print("=" * 70)

with open(FVDSP_PATH, 'rb') as f:
    fvdsp = f.read()

print(f"fvdsp size: {len(fvdsp)} bytes")

# Search for ioctl command values in fvdsp
for val in sorted(commands.keys()):
    macro, handler, name, desc = commands[val]
    packed = struct.pack('<I', val)
    
    positions = []
    start = 0
    while True:
        pos = fvdsp.find(packed, start)
        if pos < 0:
            break
        positions.append(pos)
        start = pos + 1
    
    if positions:
        print(f"  0x{val:08x} ({macro:25s} {name:20s}): found at offsets {', '.join(f'0x{p:x}' for p in positions)}")

# Also search for /dev/aci strings
print(f"\nStrings containing 'aci' or 'ACI' in fvdsp:")
i = 0
while i < len(fvdsp):
    # Look for /dev/aci
    if fvdsp[i:i+8] == b'/dev/aci':
        end = fvdsp.find(b'\x00', i)
        if end > 0:
            s = fvdsp[i:end].decode('ascii', errors='replace')
            print(f"  0x{i:06x}: {s}")
        i = end + 1
    # Look for ACI_ or aci_
    elif fvdsp[i:i+4] in (b'ACI_', b'aci_', b'Aci_'):
        end = fvdsp.find(b'\x00', i)
        if end > 0:
            s = fvdsp[i:end].decode('ascii', errors='replace')
            if len(s) < 80:
                print(f"  0x{i:06x}: {s}")
        i = end + 1
    else:
        i += 1

# Search for "ioctl" string in fvdsp
print(f"\n'ioctl' strings in fvdsp:")
i = 0
while i < len(fvdsp) - 5:
    if fvdsp[i:i+5] == b'ioctl':
        start = i
        while start > 0 and fvdsp[start-1] != 0:
            start -= 1
        end = fvdsp.find(b'\x00', i)
        if end > 0:
            s = fvdsp[start:end].decode('ascii', errors='replace')
            if len(s) < 100:
                print(f"  0x{start:06x}: {s}")
        i = end + 1
    else:
        i += 1

# Search for SIM/APDU/ATR/ISO7816 strings in fvdsp
print(f"\nSIM/APDU/ATR related strings in fvdsp:")
search_terms = [b'SIM', b'APDU', b'ATR', b'ISO7816', b'sim_', b'apdu', b'atr', b'reset', b'RESET', b'smartcard', b'ISO 7816']
for term in search_terms:
    i = 0
    found = 0
    while i < len(fvdsp) - len(term) and found < 5:
        if fvdsp[i:i+len(term)] == term:
            start = i
            while start > 0 and fvdsp[start-1] >= 0x20 and fvdsp[start-1] < 0x7f:
                start -= 1
            end = fvdsp.find(b'\x00', i)
            if end > 0 and end - start < 100:
                s = fvdsp[start:end].decode('ascii', errors='replace')
                if len(s) > 2:
                    print(f"  0x{start:06x}: {s}")
                    found += 1
            i = end + 1
        else:
            i += 1

# Search for known SIM-related ioctl values that might be different
# Maybe fvdsp uses different SIM-specific ioctls
print(f"\nSearching for other potential ioctl type bytes in fvdsp:")
# Look for _IOC_TYPE patterns with common SIM-related types
for typ_byte in [0x50, 0x53, 0x73]:  # 'P', 'S', 's'
    for nr in range(0, 32):
        for dir_val in [0, 1, 2, 3]:
            for size in [0, 4, 8, 16, 256, 512]:
                val = (dir_val << 30) | (size << 16) | (typ_byte << 8) | nr
                packed = struct.pack('<I', val)
                pos = fvdsp.find(packed)
                if pos >= 0 and val not in commands:
                    print(f"  0x{val:08x} = _IOx('{chr(typ_byte)}', {nr}, size={size}) at 0x{pos:x}")
