import re
data = open(r'c:\goip\dbltek_update\ata_fv', 'rb').read()

def extract_context_strings(data, offset, window=400):
    ctx_start = max(0, offset - window)
    ctx_end = min(len(data), offset + window)
    chunk = data[ctx_start:ctx_end]
    strs = []
    cur = []
    for b in chunk:
        if 32 <= b <= 126:
            cur.append(chr(b))
        else:
            if len(cur) >= 3:
                strs.append(''.join(cur))
            cur = []
    if cur and len(cur) >= 3:
        strs.append(''.join(cur))
    return strs

# Search for key patterns
searches = [
    ('AT+SIMDATA=%s', b'AT+SIMDATA='),
    ('tty_callback', b'tty_callback'),
    ('dummy_sim.c', b'dummy_sim.c'),
    ('dummy_sim_create', b'dummy_sim_create'),
    ('FCP:', b'FCP:'),
    ('/tmp/sim%d', b'/tmp/sim%d'),
    ('00A4', b'00A4'),
    ('00C0', b'00C0'),
    ('cm5001api.c', b'cm5001api.c'),
    ('RMSIM_ENABLE', b'RMSIM_ENABLE'),
    ('RMSIMD', b'RMSIMD'),
    ('SMB_RMSIM', b'SMB_RMSIM'),
]

for label, pat in searches:
    idx = 0
    occ = 0
    while True:
        idx = data.find(pat, idx)
        if idx < 0:
            break
        occ += 1
        if occ <= 2:  # Show first 2 occurrences
            strs = extract_context_strings(data, idx, 400)
            print(f'\n=== {label} #{occ} (@0x{idx:06x}) ===')
            for s in strs:
                print(f'  {s}')
        idx += len(pat)
    if occ == 0:
        print(f'\n=== {label}: NOT FOUND ===')
    elif occ > 2:
        print(f'  ... ({occ} total occurrences)')
