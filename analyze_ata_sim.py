#!/usr/bin/env python3
"""Analyze ata binary for SIM/SIMPIPE/RMSIM mechanisms"""
import re
import os

def extract_strings(filepath, min_len=4):
    data = open(filepath, 'rb').read()
    return data, re.findall(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}', data)

data, strings = extract_strings(r'c:\goip\dbltek_update\ata')

# 1. Configuration variable strings
print('=== Configuration variable strings ===')
cfg = sorted(set(s.decode() for s in strings if any(p in s for p in [b'SIMPIPE', b'RMSIM', b'SMB_RMSIM', b'GSM_SIM', b'SIM_ID', b'RMSIMD', b'RMSIME'])))
for c in cfg:
    print(f'  {c}')

# 2. GSM init sequence
print('\n=== GSM module init strings ===')
gsm_init = sorted(set(s.decode() for s in strings if any(p in s for p in [b'ATE0', b'ATV1', b'IPR', b'CMEE', b'CNMI', b'CSMS', b'AT+GSN', b'CGMM', b'+GMM'])))
for g in gsm_init:
    print(f'  {g}')

# 3. modem model detection
print('\n=== Modem model detection ===')
modem = sorted(set(s.decode() for s in strings if any(p in s for p in [b'ATCGMM', b'EC20', b'M26', b'M25', b'M35', b'MTK', b'H330', b'G610', b'ZTE', b'SIMCOM', b'MC8618'])))
for m in modem:
    print(f'  {m}')

# 4. SMB communication
print('\n=== SMB communication strings ===')
smb = sorted(set(s.decode() for s in strings if any(p in s for p in [b'.smb', b'smb_', b'SMB_', b'uart_write'])))
for s_str in smb:
    print(f'  {s_str}')

# 5. RSIM firmware strings
print('\n=== RSIM firmware strings ===')
rsim = sorted(set(s.decode() for s in strings if any(p in s for p in [b'RSIM', b'_RSIM', b'rsim', b'M25MAR', b'M26FBR', b'M35FAR'])))
for r in rsim:
    print(f'  {r}')

# 6. Check ata_5 for RSIM firmware references
print('\n=== ata_5 RSIM firmware strings ===')
data5, strings5 = extract_strings(r'c:\goip\dbltek_update\ata_5')
rsim5 = sorted(set(s.decode() for s in strings5 if any(p in s for p in [b'RSIM', b'_RSIM', b'M25MAR', b'M26FBR', b'M35FAR'])))
for r in rsim5:
    print(f'  {r}')

# 7. Complete SIM initialization flow
print('\n=== Complete SIM init flow (from gsm.c strings area) ===')
# Find strings near gsm_init, cpin_checking, etc.
for fname in [b'gsm_init', b'cpin_checking', b'cgmm_checking', b'module_rebooting', b'gsm_set_cnmi']:
    idx = data.find(fname)
    if idx != -1:
        ctx_start = max(0, idx - 500)
        ctx_end = min(len(data), idx + 500)
        ctx = data[ctx_start:ctx_end]
        ctx_strings = re.findall(rb'[\x20-\x7e]{4,}', ctx)
        print(f'\n  --- {fname.decode()} context (0x{idx:06x}) ---')
        for s1 in ctx_strings:
            print(f'    {s1.decode()}')

# 8. serial_init context
print('\n=== serial_init context ===')
idx = data.find(b'serial_init')
if idx != -1:
    ctx_start = max(0, idx - 200)
    ctx_end = min(len(data), idx + 200)
    ctx = data[ctx_start:ctx_end]
    ctx_strings = re.findall(rb'[\x20-\x7e]{4,}', ctx)
    for s1 in ctx_strings:
        print(f'  {s1.decode()}')

# 9. All config key names read from config
print('\n=== All config keys (L%d_ and LINE%d_ patterns) ===')
config_keys = sorted(set(s.decode() for s in strings if (s.startswith(b'L%d_') or s.startswith(b'LINE%d_') or s.startswith(b'ALL_') or s.startswith(b'SIM')) and len(s) < 40))
for k in config_keys:
    print(f'  {k}')
