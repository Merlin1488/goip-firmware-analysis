#!/usr/bin/env python3
"""Deeper analysis of DBLTEK .pkg firmware format"""
import struct, hashlib, sys

def read_pkg(path):
    with open(path, 'rb') as f:
        return f.read()

pkg = read_pkg('dbltek_update/GHSFVT-1.1-68-11.pkg')
print(f"File size: {len(pkg)} = 0x{len(pkg):x}")

# Header analysis
print("\n=== HEADER (0x00 - 0xFF) ===")
print(f"0x00 magic:     {pkg[0:4].hex()} (0xDBAD475E)")
print(f"0x04 format_ver:{pkg[4:8].hex()}")

# 0x08: number of 64K blocks = total file size / 0x10000
blocks = struct.unpack('>H', pkg[8:10])[0]
print(f"0x08 blocks:    {blocks} (x 64KB = {blocks*65536} = file size? {blocks*65536 == len(pkg)})")
print(f"0x0A u16be:     {struct.unpack('>H', pkg[10:12])[0]}")

hash16 = pkg[12:28]
print(f"0x0C hash(16B): {hash16.hex()}")

# sizes
for off, name in [(0x1C, 'size1'), (0x20, 'size2'), (0x24, 'size3'), (0x28, 'size4')]:
    v = struct.unpack('<I', pkg[off:off+4])[0]
    print(f"0x{off:02x} {name}:     {v} (0x{v:x})")

# Strings
print(f"\n0x2E: {pkg[0x2E]:#x}")
i = 0x30
while i < 0x68:
    if pkg[i] == 0:
        i += 1
        continue
    end = pkg.index(b'\x00', i)
    tag = pkg[i:end].decode('ascii', errors='replace')
    i = end + 1
    if i < len(pkg) and pkg[i] != 0:
        end2 = pkg.index(b'\x00', i)
        val = pkg[i:end2].decode('ascii', errors='replace')
        i = end2 + 1
    else:
        val = ''
    print(f"  Tag: {tag} = '{val}'")

# Field at 0x5F
print(f"\n0x5F: {pkg[0x5F]:#x}")
print(f"0x60: {pkg[0x60]:#x}")
# FW_VER field  
print(f"0x62-68: {pkg[0x62:0x69].decode('ascii', errors='replace')}")
print(f"0x69 FW_VER value: {pkg[0x69]}")

# Remaining header bytes
print(f"\n0x6A-0x78: {pkg[0x6a:0x79].hex()}")
for off in range(0x6a, 0x7a, 4):
    v = struct.unpack('<I', pkg[off:off+4])[0]
    print(f"  0x{off:x}: u32le = {v} (0x{v:x})")

# SquashFS at 0x40000
print(f"\n=== SQUASHFS at 0x40000 ===")
sq = pkg[0x40000:]
print(f"Magic at 0x40000: {sq[0:4]}")
print(f"Raw hex: {sq[0:64].hex()}")

# SquashFS 2.1 superblock format (different from 4.0!)
# struct squashfs_super_block {
#   u32 s_magic;        // 0x00
#   u32 inodes;         // 0x04
#   u32 bytes_used;     // 0x08 (was bytes_used_2 in 2.0)
#   u32 uid_start;      // 0x0C
#   u32 guid_start;     // 0x10
#   u32 inode_table_start; // 0x14
#   u32 directory_table_start; // 0x18
#   u16 s_major;        // 0x1C
#   u16 s_minor;        // 0x1E
#   u16 block_size_1;   // 0x20 (log2)
#   u16 block_log;      // 0x22
#   u8  flags;          // 0x24
#   u8  no_uids;        // 0x25
#   u8  no_guids;       // 0x26
#   u32 mkfs_time;      // 0x27 (unaligned!)
#   sqfs_inode_t root_inode; // 0x2B (8 bytes)
#   u32 block_size;     // 0x33
#   u32 fragments;      // 0x37
#   u32 fragment_table_start; // 0x3B
# }

sq_inodes = struct.unpack('<I', sq[4:8])[0]
sq_bytes_used = struct.unpack('<I', sq[8:12])[0]
sq_uid_start = struct.unpack('<I', sq[12:16])[0]
sq_guid_start = struct.unpack('<I', sq[16:20])[0]
sq_inode_table = struct.unpack('<I', sq[20:24])[0]
sq_dir_table = struct.unpack('<I', sq[24:28])[0]
sq_major = struct.unpack('<H', sq[28:30])[0]
sq_minor = struct.unpack('<H', sq[30:32])[0]
sq_block_size_1 = struct.unpack('<H', sq[32:34])[0]
sq_block_log = struct.unpack('<H', sq[34:36])[0]

print(f"inodes:       {sq_inodes}")
print(f"bytes_used:   {sq_bytes_used} (0x{sq_bytes_used:x})")
print(f"uid_start:    0x{sq_uid_start:x}")
print(f"guid_start:   0x{sq_guid_start:x}")
print(f"inode_table:  0x{sq_inode_table:x}")
print(f"dir_table:    0x{sq_dir_table:x}")
print(f"version:      {sq_major}.{sq_minor}")
print(f"block_size_1: {sq_block_size_1}")
print(f"block_log:    {sq_block_log}")

sq_end = 0x40000 + sq_bytes_used
print(f"\nSquashFS ends at: 0x{sq_end:x}")
print(f"File ends at: 0x{len(pkg):x}")
print(f"Trailing: {len(pkg) - sq_end} bytes")

# Check trailing data
if sq_end < len(pkg):
    trail = pkg[sq_end:]
    nz_trail = sum(1 for b in trail if b != 0)
    print(f"Non-zero trailing: {nz_trail}")

# Checksum tests
print("\n=== CHECKSUM ANALYSIS ===")
data_after_header = pkg[0x100:]
print(f"MD5 of 0x100+: {hashlib.md5(data_after_header).hexdigest()}")
data_payload = pkg[0x40000:]
print(f"MD5 of squashfs: {hashlib.md5(data_payload).hexdigest()}")
full = pkg[0x1C:]
print(f"MD5 of 0x1C+: {hashlib.md5(full).hexdigest()}")
# Try whole file with hash zeroed
hdr_copy = bytearray(pkg[:0x100])
hdr_copy[12:28] = b'\x00' * 16
test = bytes(hdr_copy) + pkg[0x100:]
print(f"MD5 of file(hash zeroed): {hashlib.md5(test).hexdigest()}")
# Try just the data part 0x10000+
data_10000 = pkg[0x10000:]
print(f"MD5 of 0x10000+: {hashlib.md5(data_10000).hexdigest()}")
# Show expected hash
print(f"Expected hash from header: {hash16.hex()}")

# Try CRC32
import binascii
print(f"\nCRC32 of full file: {binascii.crc32(pkg):#010x}")
print(f"CRC32 of 0x100+: {binascii.crc32(data_after_header):#010x}")
print(f"CRC32 of 0x40000+: {binascii.crc32(data_payload):#010x}")

# Is the 16 byte hash just 2x CRC32 or something else?
# Check another version for comparison
try:
    pkg2 = read_pkg('dbltek_update/GHSFVT-1.1-68-10.pkg')
    h2 = pkg2[12:28]
    print(f"\n=== 68-10 comparison ===")
    print(f"68-10 hash: {h2.hex()}")
    print(f"68-10 MD5 of 0x10000+: {hashlib.md5(pkg2[0x10000:]).hexdigest()}")
    print(f"68-10 MD5 of 0x100+: {hashlib.md5(pkg2[0x100:]).hexdigest()}")
    
    # Check if header hash is MD5 of data with header hash zeroed
    hdr2 = bytearray(pkg2[:0x100])  
    hdr2[12:28] = b'\x00' * 16
    test2 = bytes(hdr2) + pkg2[0x100:]
    print(f"68-10 MD5(file,hash=0): {hashlib.md5(test2).hexdigest()}")
    
    # Try: MD5 of just 0x1C onwards (sizes + strings + data)
    print(f"68-10 MD5 of 0x1C+: {hashlib.md5(pkg2[0x1C:]).hexdigest()}")
    
    # Try: hash of data + sizes (without the hash itself)
    combined = pkg2[:12] + pkg2[28:]
    print(f"68-10 MD5(hdr[:12]+hdr[28:]+data): {hashlib.md5(combined).hexdigest()}")
    
except Exception as e:
    print(f"Compare failed: {e}")
