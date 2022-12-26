
# **Task 9**

## <ins>Topics:</ins>

Protocol Analysis, Software Development

## <ins>Task Description<ins>

Now that we're able to register, let's send some commands! Use the knowledge and material from previous tasks to identify other clients that have registered with the LP.

## <ins>Provided Files<ins>

None

## <ins>Solution<ins>

### **1) Decrypting malware communication sessions**

We start by decrypting all communications for some of the malware sessions in `capture.pcap`.

Using Wireshark, we export all packets from `capture.pcap` (except for the initial crypt negotiation packets) from the malware sessions we decrypted in Task 8 with `File > Export Packet Dissections > As JSON...`. We filter using the queries `(ip.dst == X or ip.src == X) and tcp.payload` where X is 198.18.147.4, 10.221.200.250, or 10.104.223.215.

We then run our script `decrypt_all_sessions.py` to decrypt each packet we exported so we can investigate the expanded protocol.

### **2) Analyzing full communication protocol**

Looking at the messages being sent back an forth, we see two kinds of messages of particular interest.

The first kind is a command like the following:

`b'\x14B@sN\x00\x00\x02\x00\x04N\x08\x00\x10\xd8\xd9w?\x1b\x1bE\xb1\x86\xc4\xa5\x05\x87\xa82~N\x14\x00</tmp/endpoints/d8d9773f-1b1b-45b1-86c4-a50587a8327e/tasking\x00\xe6O\x14\x95'`

This command has a `/tmp` subfolder directory name in it, and the response this command recieves looks like the following:

`b'\x14B@sN\x18\x00\x07task-3\x00N\x18\x00\x07task-2\x00N\x18\x00\x07task-1\x00\xe6O\x14\x95'`

This command appears to have a few items in it, and it is a safe assumption that these are contents of the provided directory in the command. So the command structure looks to be the following:

MAGIC_START+PARAM_CMD+CMD_LENGTH+0004+PARAM_UUID+UUID_LENGTH+UUID+4e14+DIRNAME_LENGTH+DIRNAME+MAGIC_END

The other command of interest looks like the following:

`b'\x14B@sN\x00\x00\x02\x00\x05N\x08\x00\x10\xd8\xd9w?\x1b\x1bE\xb1\x86\xc4\xa5\x05\x87\xa82~N\x14\x00</tmp/endpoints/d8d9773f-1b1b-45b1-86c4-a50587a8327e/tasking\x00N\x1c\x00\x07task-3\x00\xe6O\x14\x95'`

Here we see the directory from the last command and a file listed in the response from the last command. The response to this command is:

`b'\x14B@sN \x00\x08RUN: id\n\xe6O\x14\x95'`

It is safe to assume that these are the file contents of the file in the command. So the structure looks to be the following:

MAGIC_START+PARAM_CMD+CMD_LENGTH+0005+PARAM_UUID+UUID_LENGTH+UUID+4e14+DIRNAME_LENGTH+DIRNAME+4e1c+FILENAME_LENGTH+FILENAME+MAGIC_END

These commands give the ability to read arbitrary files from the listening post, which can be used to read which other endpoints have registered.

### **3) Reading UUIDs from Listening Post**

Using knowledge of how the malwares processes messages to send to the listening post from Task 8 and knowledge of the protocol form this task, a script for connecting to the listening post, reading all folders in the `/tmp/endpoints/` folder, and leaking the `id_rsa` file contents in `.ssh` was created (`leak_lp_data.py`) and used to find the following UUIDs for other registered malware instances:

d53a0ef4-a97c-44c4-a54d-56fc8a26628a

6ff21204-af39-47a2-838a-8ab1ed80d692

03097428-e199-4955-89db-4a4f9392b93d

43a464dc-f9db-4d32-afe9-2d44fd328c57

f3d32f05-df6c-4d0d-b6c7-3d796e4caa05