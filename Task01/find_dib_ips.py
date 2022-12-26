#!/usr/bin/env python3

import re
import ipaddress

# Read in IP addresses from Wireshark statistics
ip_regex = "[^\d](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[^\d]"
with open("./ip_stats.txt", 'r') as f:
    matched_ips = re.findall(ip_regex, f.read())
    pcap_ips = [ipaddress.ip_address(ip) for ip in matched_ips]

# Read in provided IP address ranges
dib_ranges = []
with open("./ip_ranges.txt", 'r') as f:
    for line in f:
        cidr = line.strip()
        ip_network = ipaddress.ip_network(cidr)
        dib_ranges.append(ip_network)

# Find pcap IP addresses that are in the DIB
dib_ips = []
for ip_address in pcap_ips:
    for ip_network in dib_ranges:
        if ip_address in ip_network:
            dib_ips.append(ip_address)
            break

# Output overlapping IP addresses to file
with open("./answer.txt", 'w') as f:
    for ip in dib_ips:
        f.write(str(ip) + '\n')
