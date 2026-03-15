#!/usr/bin/env python3
"""Analyze ata binary for UDP protocol commands"""
import subprocess, re

# Extract strings from ata
result = subprocess.run(
    ['C:\\Windows\\System32\\wsl.exe', '-d', 'Ubuntu-24.04', '-e', 'bash', '-c',
     'strings /root/fw_extracted/_fw.pkg.extracted/squashfs-root/usr/bin/ata'],
    capture_output=True, text=True
)

strings = result.stdout.split('\n')

# Find protocol message keywords
keywords = ['SEND', 'MSG', 'PASSWORD', 'USSD', 'USSDEXIT', 'RECEIVE', 'STATE',
            'OK', 'ERROR', 'DELIVER', 'DONE', 'HANGUP', 'STATUS', 'GET', 'SET',
            'REQ', 'DIAL', 'ATCMD', 'KEEPALIVE', 'RECORD', 'CELLINFO', 
            'EXPIRY', 'REMAIN', 'REBOOT', 'DND', 'IMEI', 'RESET', 'ACK']

print("=== PROTOCOL COMMANDS IN ATA ===")
for kw in keywords:
    matching = [s for s in strings if s.startswith(kw + ' ') or s == kw]
    if matching:
        for m in matching[:5]:
            print(f"  {m}")

print("\n=== FORMAT STRINGS WITH %d/%s (protocol-like) ===")
for s in strings:
    # Match lines starting with uppercase word followed by %d or %s
    if re.match(r'^[A-Z]{2,} %[ds]', s):
        print(f"  {s}")

print("\n=== RECV HANDLER ===")
for s in strings:
    if any(x in s for x in ['recv:', 'recv_ctlmsg', 'send_ctlmsg', 'netsrv', 'dispatch_msg', 'handle_msg']):
        print(f"  {s}")
