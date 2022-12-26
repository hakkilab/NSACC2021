#!/usr/bin/env python3

# Python implementation of decoded_ps_script
with open("./property", 'rb') as f:
    arr = bytearray(f.read())

prev = 30

out = []
for i in range(len(arr)):
    prev = arr[i] ^ prev
    out.append(chr(prev))

with open("./ps_payload.ps1", 'w') as f:
    for c in out:
        f.write(c)
