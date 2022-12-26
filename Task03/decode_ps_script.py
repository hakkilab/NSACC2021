#!/usr/bin/env python3

import base64 as b64

with open("./attachments/sam2.jpg", 'r') as f:
    base64_str = f.read().strip().split()[-1]
    decoded_str = b64.b64decode(base64_str).decode('utf-8')

with open("./decoded_ps_script.ps1", 'w') as f:
    f.write(decoded_str)
