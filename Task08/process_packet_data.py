#!/usr/bin/env python3

import json

# Read in initialization packets json data
with open("./initialization_packets.json", 'r') as f:
    packets = json.loads(f.read())

# Read in DIB ip addresses
ips = []
with open("./DIB_ips.txt", 'r') as f:
    for line in f:
        ips.append(line.strip())

# Extract info needed for DIB initialization messages
processed_messages = []
for pkt in packets:
    message = []
    pkt_info = pkt["_source"]["layers"]
    message.append(pkt_info["ip"]["ip.src"])
    if message[0] in ips:
        message.append(pkt_info["frame"]["frame.time_epoch"])
        message.append("".join(pkt_info["tcp"]["tcp.payload"].split(":")))
        processed_messages.append(",".join(message))

# Output encrypted message data
with open("./encrypted_messages.txt", 'w') as f:
    for message in processed_messages:
        f.write(message + '\n')
