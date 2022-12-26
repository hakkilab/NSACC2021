#!/usr/bin/env python3

import re
import json
from datetime import datetime

# Read in IP address for proxy event and calculate event timestamp
with open("./proxy_event.txt", 'r') as f:
    dateline, eventline = f.readlines()
    event_contents = eventline.strip().split()
    event_ip = event_contents[3]
    # Find +/-XXXX and turn it into +/-XX:XX
    hour_min_offset = re.findall("UTC([+-]\d{2})(\d{2})", dateline)[0]
    timezone_offset = ":".join(hour_min_offset)
    # Join date, time, and timezone offset into an iso 8601 format
    event_iso_time = "T".join(event_contents[:2]) + timezone_offset
    proxy_event_time = datetime.fromisoformat(event_iso_time).timestamp()

# Read in all login json data
login_entries = []
with open("./logins.json", 'r') as f:
    for line in f:
        entry = json.loads(line.strip())
        login_entries.append(entry)

# Build collections of logons and logoffs
logons = []
logoffs = []
ip_regex = "[^\d](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[^\d]"
for entry in login_entries:
    logon_id = entry["PayloadData3"].split()[1]
    # remove decimal precision from time
    iso_timestamp = re.sub("\.\d+\+", "+", entry["TimeCreated"])
    timestamp = datetime.fromisoformat(iso_timestamp).timestamp()
    if "logon" in entry["MapDescription"].lower():
        ip_addr = re.findall(ip_regex, entry["RemoteHost"])[0]
        logons.append((timestamp, logon_id, ip_addr))
    elif "logged off" in entry["MapDescription"].lower():
        logoffs.append((timestamp, logon_id))

# Match up logons with first matching logoff with no duplications
sessions = []
while len(logons) > 0 and len(logoffs) > 0:
    logon_time, logon_id, ip_addr = logons.pop(0)
    for i in range(len(logoffs)):
        logoff_time, logoff_id = logoffs[i]
        if logon_time <= logoff_time and logon_id == logoff_id:
            logoffs.pop(i)
            sessions.append((logon_time, logoff_time, logon_id, ip_addr))
            break

# Output logon ID matching proxy event to file
with open("./answer.txt", 'w') as f:
    for logon_time, logoff_time, logon_id, ip_addr in sessions:
        if logon_time <= proxy_event_time <= logoff_time and ip_addr == event_ip:
            f.write(logon_id + '\n')
