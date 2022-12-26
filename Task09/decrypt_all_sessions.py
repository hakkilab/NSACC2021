#!/usr/bin/env python3

import json
import hashlib
import nacl.secret

# Read in session keys for decryption
session_keys = {}
with open("./session_keys.txt") as f:
    for line in f:
        ip, key = line.strip().split(",")
        session_keys[ip] = key

# Iterate over malware sessions to decrypt sessions
for ip in session_keys:
    # Read in initialization packets json data
    with open(f"./{ip}_packets.json", 'r') as f:
        packets = json.loads(f.read())

    # Extract messages for decryption
    encrypted_messages = []
    for pkt in packets:
        pkt_info = pkt["_source"]["layers"]
        ip_addr = pkt_info["ip"]["ip.src"]
        encrypted_msg = bytes([int(h, 16) for h in pkt_info["tcp"]["tcp.payload"].split(":")])
        encrypted_messages.append((ip_addr, encrypted_msg))

    # Initialize secret box for decryption
    hashed_key = hashlib.sha256(bytes([ord(x) for x in session_keys[ip]])).digest()
    box = nacl.secret.SecretBox(hashed_key)

    # Output decrypted message data
    with open(f"./{ip}_decrypted.txt", 'w') as f:
        for ip_addr, message in encrypted_messages:
            decrypted = box.decrypt(message[4:])
            f.write(f"{ip_addr}:\t{decrypted}\n")
