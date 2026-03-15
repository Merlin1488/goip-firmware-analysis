import struct, sys

f = open('dbltek_update/GHSFVT-1.1-68-11.pkg','rb')
data = f.read()
f.close()
print('Size:', len(data))

print('\n=== HEADER ===')
print('0x00 magic:', data[:4].hex())
print('0x04-07:', data[4:8].hex())
print('0x08 u16be:', struct.unpack('>H', data[8:10])[0])
print('0x0A u16be:', struct.unpack('>H', data[10:12])[0])
print('0x0C-13:', data[12:20].hex())
print('0x14-1B:', data[20:28].hex())
print('0x1C u32le:', struct.unpack('<I', data[28:32])[0], hex(struct.unpack('<I', data[28:32])[0]))
print('0x20 u32le:', struct.unpack('<I', data[32:36])[0], hex(struct.unpack('<I', data[32:36])[0]))
print('0x24 u32le:', struct.unpack('<I', data[36:40])[0], hex(struct.unpack('<I', data[36:40])[0]))
print('0x28 u32le:', struct.unpack('<I', data[40:44])[0], hex(struct.unpack('<I', data[40:44])[0]))
print('0x2C u16le:', struct.unpack('<H', data[44:46])[0])

# strings
print('\n=== STRINGS ===')
i = 0x2E
while i < 0x100:
    if data[i] == 0:
        i += 1
        continue
    end = data.index(b'\x00', i)
    s = data[i:end].decode('ascii', errors='replace')
    print(f'  0x{i:x}: "{s}"')
    i = end + 1

# Data regions
print('\n=== DATA REGIONS ===')
for start, end, name in [(0x68, 0x100, '0x68-0x100'), (0x100, 0x200, '0x100-0x200'), 
                           (0x200, 0x10000, '0x200-0x10000'), (0x10000, 0x40000, '0x10000-0x40000')]:
    nz = sum(1 for b in data[start:end] if b != 0)
    print(f'{name}: {nz} nonzero of {end-start}')

# Squashfs
sqofs = data.find(b'hsqs')
print(f'\n=== SQUASHFS at 0x{sqofs:x} ===')
sq_inode_count = struct.unpack('<I', data[sqofs+4:sqofs+8])[0]
sq_mkfs_time = struct.unpack('<I', data[sqofs+8:sqofs+12])[0]
sq_block_size = struct.unpack('<I', data[sqofs+12:sqofs+16])[0]
sq_fragment_count = struct.unpack('<I', data[sqofs+16:sqofs+20])[0]
sq_compressor = struct.unpack('<H', data[sqofs+20:sqofs+22])[0]
sq_block_log = struct.unpack('<H', data[sqofs+22:sqofs+24])[0]
sq_flags = struct.unpack('<H', data[sqofs+24:sqofs+26])[0]
sq_id_count = struct.unpack('<H', data[sqofs+26:sqofs+28])[0]
sq_ver_major = struct.unpack('<H', data[sqofs+28:sqofs+30])[0]
sq_ver_minor = struct.unpack('<H', data[sqofs+30:sqofs+32])[0]
sq_bytes_used = struct.unpack('<Q', data[sqofs+40:sqofs+48])[0]
print(f'inodes: {sq_inode_count}')
print(f'block_size: {sq_block_size}')
print(f'version: {sq_ver_major}.{sq_ver_minor}')
print(f'compressor: {sq_compressor} (1=gzip,2=lzma,3=lzo,4=xz)')
print(f'bytes_used: {sq_bytes_used} (0x{sq_bytes_used:x})')
sq_end = sqofs + sq_bytes_used
print(f'sqfs ends at 0x{sq_end:x}')
print(f'file ends at 0x{len(data):x}')
pad = len(data) - sq_end
print(f'padding: {pad} bytes')

# Region before squashfs
print(f'\n=== REGION 0x10000 - 0x40000 (bootloader?) ===')
r = data[0x10000:0x40000]
nz = sum(1 for b in r if b != 0)
print(f'Size: {0x30000} ({0x30000//1024}KB), nonzero: {nz}')
print(f'First 64:', data[0x10000:0x10040].hex())

# Compare with 68-10
print('\n=== COMPARE 68-11 vs 68-10 ===')
f2 = open('dbltek_update/GHSFVT-1.1-68-10.pkg','rb')
d2 = f2.read()
f2.close()
diffs = []
for i in range(min(len(data), len(d2))):
    if data[i] != d2[i]:
        diffs.append(i)
print(f'Total different bytes: {len(diffs)}')
if diffs:
    print(f'First diff at: 0x{diffs[0]:x}')
    print(f'Last diff at: 0x{diffs[-1]:x}')
    # count diffs per region
    h_diffs = sum(1 for d in diffs if d < 0x100)
    r1_diffs = sum(1 for d in diffs if 0x100 <= d < 0x10000)
    r2_diffs = sum(1 for d in diffs if 0x10000 <= d < 0x40000)
    sq_diffs = sum(1 for d in diffs if d >= 0x40000)
    print(f'Header (0-0xFF): {h_diffs} diffs')
    print(f'Region 0x100-0x10000: {r1_diffs} diffs')
    print(f'Region 0x10000-0x40000: {r2_diffs} diffs')
    print(f'SquashFS (0x40000+): {sq_diffs} diffs')
