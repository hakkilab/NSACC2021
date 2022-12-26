
# **Task 2**

## <ins>Topics:</ins>

Log Analysis

## <ins>Task Description<ins>

NSA notified FBI, which notified the potentially-compromised DIB Companies. The companies reported the compromise to the Defense Cyber Crime Center (DC3). One of them, Online Operations and Production Services (OOPS) requested FBI assistance. At the request of the FBI, we've agreed to partner with them in order to continue the investigation and understand the compromise.

OOPS is a cloud containerization provider that acts as a one-stop shop for hosting and launching all sorts of containers -- rkt, Docker, Hyper-V, and more. They have provided us with logs from their network proxy and domain controller that coincide with the time that their traffic to the cyber actor's listening post was captured.

Identify the logon ID of the user session that communicated with the malicious LP (i.e.: on the machine that sent the beacon *and* active at the time the beacon was sent).

## <ins>Provided Files<ins>

<ul>
<li>Subnet associated with OOPS (oops_subnet.txt)</li>
<li>Network proxy logs from Bluecoat server (proxy.log)</li>
<li>Login data from domain controller (logins.json)</li>
</ul>

## <ins>Solution<ins>

### **1) Finding the right event in proxy.log**

Looking at `oops_subnet.txt`, we see that we have a CIDR provided to us, 198.18.159.72/29. This corresponds to IP addresses 198.18.159.7X, where X is 2-9.

Taking a look at `ip_stats.txt` from Task 1, we see that we have one IP address in `capture.pcap` in this range, 198.18.159.74.

Opening `capture.pcap` in Wireshark and applying the filter `ip.dst == 198.18.159.74 or ip.src == 198.18.159.74`, we can see that this OOPS IP is communicating with 10.78.211.175, which must be the LP.

We use `grep` to search for these IP addresses in `proxy.log` (using our script `get_proxy_event.sh`) and get one hit. At the same time, we use grep to also pull out the `#Date` line for future use in timezone conversions.

### **2) **Correlating proxy_event.txt with events in logins.json**

Looking at `logins.json`, we see each piece of json data has a `MapDescription` field that can contain the text `"Successful logon"` or `"An account was logged off"`, a `TimeCreated` field with an [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601) timestamp, a `PayloadData3` field which contains logon IDs, and a `RemoteHost` field which has an IP address in either `"::ffff:IP:PORT"` format or `"- (IP)"` format.

So what we can do is go through the logins and build a list of logon sessions with a logon time, logoff time, and logon ID, then find which session corresponds to the time and IP address of the LP communication event we found in `proxy.log` earlier.

The `proxy.log` file lists the software version as `SGOS 6.7.5.3`. Referencing the [ProxySG Log Fields and Substitutions](https://techdocs.broadcom.com/content/dam/broadcom/techdocs/symantec-security-software/web-and-network-security/proxysg/common/LogFieldsSubs.pdf) document for ProxySG-6.7, we see that the `c-ip` field is what we want to use for matching the ip address. We will also use the `date` and `time` fields from our proxy event.

Running our script `find_logon_id.py` we see that the logon ID corresponding to the proxy event is:

0X36728F
