#!/usr/bin/env python3

import nacl.secret
import nacl.exceptions
import hashlib

# Read in encrypted message data
ciphers = []
with open("encrypted_messages.txt", 'r') as f:
    for line in f:
        ip, pkt_time, ciphered_msg = line.strip().split(",")
        pkt_time = int(float(pkt_time))
        # make bytes object from hex representation of message
        cipher_bytes = bytes([int(ciphered_msg[i:i+2], 16) for i in range(0, len(ciphered_msg), 2)])
        ciphers.append((ip, pkt_time, cipher_bytes))

# +/- 10 seconds from packet timestamp
time_tol = 10

# versions with format X.X.X.X whre X is 0-9
versions = [".".join(list(str(i).zfill(4))) for i in range(0, 10000)]

# Read in usernames from SecLists names.txt
user_list = []
with open("./names.txt", 'r') as f:
    for line in f:
        # convert all usernames to lowercase
        user_list.append(line.strip().lower())

def brute_force_session(ip, pkt_time, cipher):
    # Iterate over all combos of username, version, and timestamp to decrypt message
    for v in versions:
        # Print for checking progress of script
        print(ip, v)
        for t_delt in range(-time_tol, time_tol+1):
            for user in user_list:
                # Generate session key and secret box
                session_key = user + '+' + v + '+' + str(pkt_time+t_delt)
                hashed_key = hashlib.sha256(bytes([ord(x) for x in session_key])).digest()
                box = nacl.secret.SecretBox(hashed_key)
                try:
                    # remove length header before decrypting
                    decrypted = box.decrypt(cipher[4:])
                except nacl.exceptions.CryptoError:
                    # Skip to next session key on failur
                    continue
                # Output session key and UUID to files on success
                print(f"Success: {ip}, {session_key}")
                with open("./session_keys.txt", 'a') as f:
                    f.write(ip + "," + session_key + '\n')
                with open("./answer.txt", 'a') as f:
                    uuid_hexes = [hex(b)[2:].zfill(2) for b in decrypted[-20:-4]]
                    # Processing to add in dashes for UUID
                    uuid = ""
                    for i, h in enumerate(uuid_hexes):
                        if i in [4, 6, 8, 10]:
                            uuid += "-"
                        uuid += h
                    f.write(uuid + '\n')
                return

# Brute force decrypt each session
for ip, pkt_time, cipher in ciphers:
    brute_force_session(ip, pkt_time, cipher)
