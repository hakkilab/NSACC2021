
# **Task 1**

## <ins>Topics:</ins>

Network Forensics, Command Line

## <ins>Task Description<ins>

The NSA Cybersecurity Collaboration Center has a mission to prevent and eradicate threats to the US Defense Industrial Base (DIB). Based on information sharing agreements with several DIB companies, we need to determine if any of those companies are communicating with the actor's infrastructure.

You have been provided a capture of data en route to the listening post as well as a list of DIB company IP ranges. Identify any IPs associated with the DIB that have communicated with the LP.

## <ins>Provided Files<ins>

<ul>
<li>Network traffic heading to the LP (capture.pcap)</li>
<li>DIB IP address ranges (ip_ranges.txt)</li>
</ul>

## <ins>Solution<ins>

### **1) Extracting IP Addresses from capture.pcap**

We start by opening up `capture.pcap` in [Wireshark](https://www.wireshark.org/).

Using `Statistics > IPv4 Statistics > All Addresses` we can export a list of all ip addresses in `capture.pcap` to another file (in my case, `ip_stats.txt`).

### **2) Comparing IP Addresses to those in the DIB**

Looking at the IP ranges in `ip_ranges.txt`, we see they are in [CIDR Notation](http://intronetworks.cs.luc.edu/current2/html/bigrouting.html#classless-internet-domain-routing-cidr). 

We can use the Python standard library `ipaddress` to test which extracted IP addresses fall inside any of the provided CIDR blocks.

Running our script `find_dib_ips.py` shows that the following DIB IP addresses have communicated with the LP:

<ul>
<li>10.104.223.215</li>
<li>10.221.200.250</li>
<li>198.18.147.4</li>
<li>198.18.159.74</li>
</ul>
