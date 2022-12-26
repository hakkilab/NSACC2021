
# **Task 4**

## <ins>Topics:</ins>

PowerShell, Registry Analysis

## <ins>Task Description<ins>

A number of OOPS employees fell victim to the same attack, and we need to figure out what's been compromised! Examine the malware more closely to understand what it's doing. Then, use these artifacts to determine which account on the OOPS network has been compromised.

## <ins>Provided Files<ins>

<ul>
<li>OOPS forensic artifacts (artifacts.zip)</li>
</ul>

## <ins>Solution<ins>

### **1) Determining what powershell payload does**

Reading through `ps_payload.ps1`, we can see that it is collecting info from `\SOFTWARE\SimonTatham\PuTTY\Sessions` and `\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions` in each Windows user registry hive. Of particular interest, for each saved WinSCP session in `\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions` the script tries to collect hostname, username, and password. Additionally, for each saved PuTTY session the script tries to collect hostname and .ppk file path, and using that .ppk file path, tries to collect the protocol, private key encryption algorithm, comment, private key, and private MAC address.

### **2) Determining what WinSCP/PuTTY session was compromised**

After using `unzip` to extract files from `artifacts.zip`, we can see a collection of .ppk and .pub 

Using `hivexsh` we can browse through `NTUSER.DAT` to see what information the script was able to collect.

For all of the saved WinSCP sessions, the only info available to collect was hostname and username, so none of those sessions were compromised.

For all of the saved PuTTY sessions, both hostname and .ppk file path were available to collect, so we need to look through the associated .ppk files to see what info was avaiable for collection there. When we look through the .ppk files, we see that one of them, `dkr_prd76.ppk` has encryption listed as `none` which means the private key is stored as plain text. This is our compromised session, so looking back at the value for hostname in `NTUSER.DAT` we get the compromised hostname and username:

<ul>
<li>dkr_prd76</li>
<li>hyperwbot</li>
</ul>