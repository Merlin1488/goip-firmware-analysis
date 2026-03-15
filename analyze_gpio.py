#!/usr/bin/env python3
"""Analyze ata_fv binary for SIMPIPE GPIO pin mapping"""
import struct

data = open('dbltek_update/ata_fv', 'rb').read()

# Find all occurrences of SIMPIPE string
print("=== SIMPIPE strings ===")
idx = 0
while True:
    pos = data.find(b'SIMPIPE', idx)
    if pos == -1: break
    start = max(0, pos - 30)
    end = min(len(data), pos + 50)
    ctx = data[start:end]
    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
    print(f"  0x{pos:06x}: {printable}")
    idx = pos + 1

# Find AT+GTSET strings
print("\n=== AT+GTSET strings ===")
idx = 0
while True:
    pos = data.find(b'GTSET', idx)
    if pos == -1: break
    start = max(0, pos - 30)
    end = min(len(data), pos + 50)
    ctx = data[start:end]
    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
    print(f"  0x{pos:06x}: {printable}")
    idx = pos + 1

# Find /dev/gpio0
print("\n=== /dev/gpio0 ===")
idx = 0
while True:
    pos = data.find(b'/dev/gpio0', idx)
    if pos == -1: break
    print(f"  0x{pos:06x}")
    idx = pos + 1

# Find sim_pipe or simpipe references
print("\n=== sim_pipe/simpipe references ===")
for pat in [b'sim_pipe', b'simpipe', b'SIMPIPE', b'SIM_PIPE']:
    idx = 0
    while True:
        pos = data.find(pat, idx)
        if pos == -1: break
        start = max(0, pos - 20)
        end = min(len(data), pos + 60)
        ctx = data[start:end]
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
        print(f"  {pat.decode():12s} at 0x{pos:06x}: {printable}")
        idx = pos + 1

# Find gpio-related function strings (GPIO config patterns)
print("\n=== GPIO config values (looking for MKGPIOCONFIG patterns) ===")
# MKGPIOCONFIG(reg,pin,dir) = (reg<<8)|((pin&0xf)<<4)|(dir?1:0)
# Look for common GPIO config values as 32-bit words in the binary
gpio_vals = {}
for reg in range(0x20):  # GPIOA=0 through BGPIO9=0x19
    for pin in range(16):
        for d in [0, 1]:
            val = (reg << 8) | ((pin & 0xf) << 4) | (1 if d else 0)
            gpio_vals[val] = f"reg=0x{reg:02x} pin={pin} dir={'out' if d else 'in'}"

# Find ioctl-related patterns. VPIOC magic is likely 'VP' = 0x5650 or similar
# Common ioctl encoding: _IOW(type, nr, size) 
# Let's find ioctl call patterns near gpio0 open
# Actually, let's look for the VPMAGIC constant
print("\n=== VP/VPIOC magic search ===")
for pat in [b'VPMAGIC', b'_VPIOC', b'VPIOC']:
    idx = 0
    while True:
        pos = data.find(pat, idx)
        if pos == -1: break
        start = max(0, pos - 10)
        end = min(len(data), pos + 40)
        ctx = data[start:end]
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
        print(f"  {pat.decode():12s} at 0x{pos:06x}: {printable}")
        idx = pos + 1

# Find rmsim references
print("\n=== rmsim references ===")
for pat in [b'rmsim', b'RMSIM', b'rmsim_enable', b'RMSIM_ENABLE']:
    idx = 0
    while True:
        pos = data.find(pat, idx)
        if pos == -1: break
        start = max(0, pos - 10)
        end = min(len(data), pos + 60)
        ctx = data[start:end]
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
        print(f"  {pat.decode():15s} at 0x{pos:06x}: {printable}")
        idx = pos + 1

# Look for SIM/Type string (used by M35)
print("\n=== SIM/Type references ===")
idx = 0
while True:
    pos = data.find(b'SIM/Type', idx)
    if pos == -1: break
    start = max(0, pos - 30)
    end = min(len(data), pos + 40)
    ctx = data[start:end]
    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
    print(f"  0x{pos:06x}: {printable}")
    idx = pos + 1

# Look for specific AT commands related to SIM switching
print("\n=== SIM switching AT commands ===")
for pat in [b'AT+QSIMDET', b'AT+QSIMSTAT', b'AT+QSIM', b'AT+CFUN']:
    idx = 0
    while True:
        pos = data.find(pat, idx)
        if pos == -1: break
        start = max(0, pos - 5)
        end = min(len(data), pos + 50)
        ctx = data[start:end]
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
        print(f"  0x{pos:06x}: {printable}")
        idx = pos + 1

# Look for simulation pipe / GPIO set patterns in ARM code
# In ARM, ioctl is typically syscall #54 (0x36)
# But more practically, let's look for immediate values used near gpio writes
# GPIO config values that would make sense for SIM switch:
# BGPIO6=0x16, BGPIO7=0x17, BGPIO8=0x18, BGPIO9=0x19
print("\n=== Searching for BGPIO immediate values in ARM code ===")
# In ARM, small immediates are encoded differently. Let's search for the raw bytes
for bgpio_name, bgpio_val in [("BGPIO6", 0x16), ("BGPIO7", 0x17), 
                                ("BGPIO8", 0x18), ("BGPIO9", 0x19)]:
    # As a MKGPIOCONFIG value: (bgpio_val << 8) | (pin << 4) | dir
    for pin in range(16):
        for d in [0, 1]:
            val = (bgpio_val << 8) | ((pin & 0xf) << 4) | (1 if d else 0)
            # These values are 0x1600 range. In ARM little-endian as 4-byte word:
            packed = struct.pack('<I', val)
            # Search for this as an immediate
            pos = data.find(packed)
            if pos != -1:
                print(f"  {bgpio_name} pin={pin} dir={'out' if d else 'in'} val=0x{val:04x} at 0x{pos:06x}")

# Also search GPIOA-D
for gpio_name, gpio_val in [("GPIOA", 0), ("GPIOB", 1), ("GPIOC", 2), ("GPIOD", 3)]:
    for pin in range(16):
        for d in [0, 1]:
            val = (gpio_val << 8) | ((pin & 0xf) << 4) | (1 if d else 0)
            packed = struct.pack('<I', val)
            pos = data.find(packed)
            while pos != -1:
                # Only report if it's in the code section (first ~5MB)
                if pos < 0x500000:
                    print(f"  {gpio_name} pin={pin} dir={'out' if d else 'in'} val=0x{val:04x} at 0x{pos:06x}")
                pos = data.find(packed, pos + 1)

print("\n=== Done ===")
