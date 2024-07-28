#!/usr/bin/env python3

import os
import sys
import struct


def memfrob(data: bytes) -> bytes:
    tmp = 0xFF
    result = []

    for i, byte in enumerate(data):
        byte = (byte ^ tmp) & 0xFF

        byte = (byte ^ (i)) & 0xFF
        byte = (byte + (i*i)) & 0xFF
        byte = (byte ^ (i*i*i)) & 0xFF
        byte = (byte + (i*i*i*i)) & 0xFF

        result.append(byte)

        tmp = (tmp + byte) & 0xFF

    return bytes(result)


def unmemfrob(data: bytes) -> bytes:
    tmp = 0xFF
    tmp = (tmp + sum(data)) & 0xFF

    unprotected = []

    for i, byte in reversed(list(enumerate(data))):
        tmp = (tmp - byte) & 0xFF

        byte = (byte - (i*i*i*i)) & 0xFF
        byte = (byte ^ (i*i*i)) & 0xFF
        byte = (byte - (i*i)) & 0xFF
        byte = (byte ^ (i)) & 0xFF

        byte = (byte ^ tmp) & 0xFF

        unprotected.append(byte)

    return bytes(unprotected[::-1])


def decode_java_bytes(data: bytes) -> bytes:
    result = []
    index = 0

    while index < len(data):
        byte = data[index]

        if byte == 0xc0:
            index += 1
            byte = 0x00
        elif byte == 0xc2:
            index += 1
            byte = data[index]
        elif byte == 0xc3:
            index += 1
            byte = (data[index] + 0x40) & 0xFF

        result.append(byte)
    
    return bytes(result)


def encode_java_bytes(data: bytes) -> bytes:
    result = []

    for byte in data:
        if byte == 0x00:
            result.append(0xc0)
            result.append(0x80)
        elif 0x80 <= byte <= 0xbf:
            result.append(0xc2)
            result.append(byte)
        elif 0xc0 <= byte <= 0xff:
            result.append(0xc3)
            result.append(byte - 0x40)
        else:
            result.append(byte)
    
    return bytes(result)


def patch_dollyclass() -> None:
    print('### patch dollyclass ###')

    chunk_size = 20_000

    with open('Dolly.class', 'rb') as file:
        dollyclass = file.read()

    with open('libchecker.so', 'rb') as file:
        libchecker = file.read()

    # pyinit_main+194
    offset = 0x102eaa

    chunk_start = chunk_size * (offset // chunk_size)
    chunk_offset = offset % chunk_size

    chunk = libchecker[chunk_start : chunk_start+chunk_size]

    java_encoded_part = encode_java_bytes(unmemfrob(chunk[:chunk_offset]))
    java_encoded_chunk = encode_java_bytes(unmemfrob(chunk))

    target = java_encoded_chunk[len(java_encoded_part):]
    target_offset = dollyclass.find(target)

    part = chunk[:chunk_offset]
    encoded_chunk = memfrob(chunk)

    # call to hook_marshal_loads
    '''
    mov rax, QWORD PTR [rsp + 0x38]
    add rax, 0x17f2e
    call rax
    add rsp, 0x30
    pop rbx
    ret
    '''
    patch = bytes([
        0x48, 0x8b, 0x44, 0x24, 0x38, 0x48, 0x05, 0x2e, 
        0x7f, 0x01, 0x00, 0xff, 0xd0, 0x48, 0x83, 0xc4, 
        0x30, 0x5b, 0xc3, 
    ])

    suffix = b''

    for i in range(100000):
        suffix = os.urandom(4)

        patched = patch + suffix

        java_encoded_patch = encode_java_bytes(unmemfrob(chunk[:len(part) + len(patched)]))
        java_encoded_patched = encode_java_bytes(unmemfrob(part + patched))

        if len(java_encoded_patch) == len(java_encoded_patched):
            break

    patch += suffix
    print(f'patch = {patch.hex()}, length = {len(patch)}')

    java_encoded_patch = encode_java_bytes(unmemfrob(chunk[:len(part) + len(patch)]))
    java_encoded_patched = encode_java_bytes(unmemfrob(part + patch))

    index = dollyclass.find(java_encoded_patch)
    print(f'index = {index}')

    print(f'target len: {len(java_encoded_patch)}, result len: {len(java_encoded_patched)}')

    part_length = len(encode_java_bytes(unmemfrob(part)))

    patch_start = index + part_length
    patch_length = len(java_encoded_patch) - part_length
    # patch_length = patch_length + (0x30 - (patch_length % 0x30))

    print(f'patch_start = {hex(patch_start)}, patch_length = {hex(patch_length)}')

    before_patch = dollyclass[patch_start : patch_start+patch_length]
    print(f'before_patch: {before_patch.hex()}')

    dollyclass_patched = dollyclass.replace(java_encoded_patch, java_encoded_patched)

    after_patch = dollyclass_patched[patch_start : patch_start+patch_length]
    print(f'after_patch: {after_patch.hex()}')

    # with open('Dolly.class.patched', 'wb') as file:
    #     file.write(dollyclass_patched)

    dollyclass_encrypted = bytes(
        x^0xAA for x in dollyclass_patched
    )

    patch_result = dollyclass_encrypted[patch_start : patch_start+patch_length]
    print(f'patch_result: {patch_result.hex()}')

    return


def patch_dolly_segment(dolly: bytes, patch: bytes, offset: int, length: int) -> bytes:
    patch = patch + os.urandom(length - len(patch))
    assert len(patch) == length

    print(f'payload before: {dolly[offset : offset+length].hex()}')

    dolly = dolly[:offset] + patch + dolly[offset + length:]

    print(f'payload after: {dolly[offset : offset+length].hex()}')

    return dolly


def patch_dolly(dollyclass_patch: bytes, check_result: bytes) -> None:
    print('### patch dolly ###')

    with open('dolly', 'rb') as file:
        dolly = file.read()

    # patched data for DollyClass

    # _ZGTtNSt11logic_errorC1EPKc
    dollyclass_patch_addr = 0x382d0
    dollyclass_patch_length = 0x100

    dolly = patch_dolly_segment(
        dolly, dollyclass_patch, dollyclass_patch_addr, dollyclass_patch_length,
    )

    # call sigaltstack & patch write.got

    # _ZGTtNSt11logic_errorC1EPKc + 0x30
    call_sigaltstack_addr = 0x382d0 + 0x30
    call_sigaltstack_length = 0x100 - 0x30

    # 0x8ec9c: offset from rcx to check flag (_Unwind_Backtrace)
    # 0x2cd07c: offset from rax to write.got
    # 0x30: offset from constants to flag
    # save original write in +0x400
    '''
    push rax
    push 0x0
    add rax, 0x30
    push rax
    xor esi, esi
    mov rdi, rsp
    mov eax, 0x83
    syscall
    add rsp, 0x18
    mov rax, rcx
    add rcx, 0x8ec9c
    add rax, 0x2cd07c
    mov rdi, QWORD PTR [rax]
    mov QWORD PTR [rax], rcx
    add rax, 0x400
    mov QWORD PTR [rax], rdi
    ret
    '''

    call_sigaltstack_code = bytes([
        0x50, 0x6a, 0x00, 0x48, 0x83, 0xc0, 0x30, 0x50, 
        0x31, 0xf6, 0x48, 0x89, 0xe7, 0xb8, 0x83, 0x00, 
        0x00, 0x00, 0x0f, 0x05, 0x48, 0x83, 0xc4, 0x18, 
        0x48, 0x89, 0xc8, 0x48, 0x81, 0xc1, 0x9c, 0xec, 
        0x08, 0x00, 0x48, 0x05, 0x7c, 0xd0, 0x2c, 0x00, 
        0x48, 0x8b, 0x38, 0x48, 0x89, 0x08, 0x48, 0x05, 
        0x00, 0x04, 0x00, 0x00, 0x48, 0x89, 0x38, 0xc3, 
    ])

    dolly = patch_dolly_segment(
        dolly, call_sigaltstack_code, call_sigaltstack_addr, call_sigaltstack_length,
    )

    # check flag code

    # _Unwind_Backtrace
    check_flag_addr = 0xc6fb0
    check_flag_length = 0x100

    # check flag if string in rsi starts with "[-] "
    # else just write
    # rax is already 1
    # 0x2370e21: offset from rip to secret
    # constants in r8, secret in r9, results in r12
    # 0x3b47217cfd6e251b: constant for multiplication
    # -0x18587d: offset from constants to "[+] Correct flag"
    # 0x15: offset from "[+] Correct flag" to "[-] Wrong flag"
    # 0x2370d4d: offset to encrypted flag
    # 0x23e320+0x400: offset to saved write.plt
    '''
    push r8
    mov r8d, DWORD PTR [rsi]
    sub r8, 0x205d2d5b
    test r8, r8
    jnz write
    lea r9, [rip + 0x2370e21]
    lea r8, [r9 - 0x30]
    lea r12, [r8 - 0x2370d4d]
    mov r10, 0x3b47217cfd6e251b
    lea rsi, [r8 - 0x18587d]
    mov edx, 18
    mov ecx, 6
    mov r15, 0
    check:
    lea r11, QWORD PTR [r8 + 8*r15]
    mov r11, QWORD PTR [r11]
    imul r10, r11
    lea r11, QWORD PTR [r9 + 8*r15]
    mov r13, QWORD PTR [r11]
    xor r13, r10
    lea r11, QWORD PTR [r12 + 8*r15]
    mov r11, QWORD PTR [r11]
    sub r13, r11
    test r13, r13
    jz correct
    add rsi, 0x15
    jmp finish
    correct:
    inc r15
    loop check
    finish:
    lea r12, [r12 + 0x23e320 + 0x400]
    mov r11, QWORD PTR [r12]
    sub r12, 0x400
    mov QWORD PTR [r12], r11
    call r11
    mov rax, 0xe7
    mov rdi, 0
    syscall
    write:
    syscall
    pop r8
    ret
    '''

    check_flag_code = bytes([
        0x41, 0x50, 0x44, 0x8b, 0x06, 0x49, 0x81, 0xe8, 
        0x5b, 0x2d, 0x5d, 0x20, 0x4d, 0x85, 0xc0, 0x0f, 
        0x85, 0x8d, 0x00, 0x00, 0x00, 0x4c, 0x8d, 0x0d, 
        0x21, 0x0e, 0x37, 0x02, 0x4d, 0x8d, 0x41, 0xd0, 
        0x4d, 0x8d, 0xa0, 0xb3, 0xf2, 0xc8, 0xfd, 0x49, 
        0xba, 0x1b, 0x25, 0x6e, 0xfd, 0x7c, 0x21, 0x47, 
        0x3b, 0x49, 0x8d, 0xb0, 0x83, 0xa7, 0xe7, 0xff, 
        0xba, 0x12, 0x00, 0x00, 0x00, 0xb9, 0x06, 0x00, 
        0x00, 0x00, 0x49, 0xc7, 0xc7, 0x00, 0x00, 0x00, 
        0x00, 0x4f, 0x8d, 0x1c, 0xf8, 0x4d, 0x8b, 0x1b, 
        0x4d, 0x0f, 0xaf, 0xd3, 0x4f, 0x8d, 0x1c, 0xf9, 
        0x4d, 0x8b, 0x2b, 0x4d, 0x31, 0xd5, 0x4f, 0x8d, 
        0x1c, 0xfc, 0x4d, 0x8b, 0x1b, 0x4d, 0x29, 0xdd, 
        0x4d, 0x85, 0xed, 0x74, 0x06, 0x48, 0x83, 0xc6, 
        0x15, 0xeb, 0x05, 0x49, 0xff, 0xc7, 0xe2, 0xd1, 
        0x4d, 0x8d, 0xa4, 0x24, 0x20, 0xe7, 0x23, 0x00, 
        0x4d, 0x8b, 0x1c, 0x24, 0x49, 0x81, 0xec, 0x00, 
        0x04, 0x00, 0x00, 0x4d, 0x89, 0x1c, 0x24, 0x41, 
        0xff, 0xd3, 0x48, 0xc7, 0xc0, 0xe7, 0x00, 0x00, 
        0x00, 0x48, 0xc7, 0xc7, 0x00, 0x00, 0x00, 0x00, 
        0x0f, 0x05, 0x0f, 0x05, 0x41, 0x58, 0xc3, 
    ])

    dolly = patch_dolly_segment(
        dolly, check_flag_code, check_flag_addr, check_flag_length,
    )

    encrypted_flag = check_result
    encrypted_flag_addr = check_flag_addr + 0xc0
    encrypted_flag_length = 0x100 - 0xc0

    dolly = patch_dolly_segment(
        dolly, encrypted_flag, encrypted_flag_addr, encrypted_flag_length,
    )

    # patch DollyClass code

    # 0x2f8c938: offset to _ZGTtNSt11logic_errorC1EPKc
    # 0x2277d30: offset to DollyClass
    # 0x187dc4: patch location inside DollyClass
    # 0x20: patch length
    # -0x55f: offset to memcpy.plt
    # 0x2520b: offset to call sigaltstack (_ZGTtNSt11logic_errorC1EPKc + 0x30)

    '''
    push rdi
    push rdx
    lea rsi, [rdi - 0x2f8c938]
    lea rdi, [rsi + 0x2277d30 + 0x187dc4]
    mov edx, 0x20
    call -0x55f
    call 0x2520b
    pop rdx
    pop rdi
    xor eax, eax
    xor esi, esi
    pop rbp
    ret
    '''
    patch_dollyclass = bytes([
        0x57, 0x52, 0x48, 0x8d, 0xb7, 0xc8, 0x36, 0x07, 
        0xfd, 0x48, 0x8d, 0xbe, 0xf4, 0xfa, 0x3f, 0x02, 
        0xba, 0x20, 0x00, 0x00, 0x00, 0xe8, 0x87, 0xfa, 
        0xff, 0xff, 0xe8, 0xec, 0x51, 0x02, 0x00, 0x5a, 
        0x5f, 0x31, 0xc0, 0x31, 0xf6, 0x5d, 0xc3, 
    ])

    # register_tm_clones + 21
    patch_dollyclass_addr = 0x130e0 + 21
    patch_dollyclass_length = len(patch_dollyclass)

    dolly = patch_dolly_segment(
        dolly, patch_dollyclass, patch_dollyclass_addr, patch_dollyclass_length,
    )

    with open('dolly.patched', 'wb') as file:
        file.write(dolly)

    return


def generate_check_result():
    flag = b'brics+{n1ce_j0b_y0u_h4ck3d_th3_d0lly_sh33p_1337}'
    mask = bytes.fromhex('111b0e021f5f081a50000e5f19ee958c0d13079e72744f23647d31b1df47860c4401d6609b3a2e93121ef37ab78447d7018d0dcebf2cc129b9d51279ce58129db9fd1eb08bdf900963c0b22b45f118d3551c04017d6c0025cead0b7f08c839fe069276399d2d84cbb673ff10f16390c42679cabce1fe2593fae171eb8d99358149b89176e82951766031de4f9061a46e33e8c5b83e4bec21dddaa06c9f3eea8f812c27246fa8bb13cacbd51b8e27fc53a49fe1535d93ce271b7933034dd8bf7d5bf1f5d3e1e413e84cea3f457c6601d8932e82fbe1d0202666ab3f41e58b80c8fef840e8e1e7827cfb815d9ccb5265231adeeef4904bb7e06ff4f0b9a10fa89d')
    secret = bytes(x ^ y for x, y in zip(mask, flag))

    secret_values = struct.unpack('<QQQQQQ', secret)
    check_values = [
        0xb6c280c0b4c37a5e, 0x1803675653a1c364,
        0xc321a5c3aec384c3, 0x5c2014357f9ec2bb,
        0xc32595c261b4c304, 0xbac3397faac357b0,
    ]

    results = []

    value = 0x3b47217cfd6e251b

    for check, secret in zip(check_values, secret_values):
        value = (value * check) & 0xFFFFFFFFFFFFFFFF
        secret = secret ^ value

        results.append(secret)

    result = struct.pack('<QQQQQQ', *results)

    return result


def main() -> None:
    if sys.argv[1] == 'DOLLYCLASS':
        patch_dollyclass()

    if sys.argv[1] == 'DOLLY':
        patch_start = 0x187dc4
        patch_length = 0x20

        patch_result = bytes.fromhex('f5d0691e6a2a681cce690bf9fccda9b2692e6904690f8b69116834d5b795cc8b')

        check_result = generate_check_result()
        
        patch_dolly(patch_result, check_result)

    return


if __name__ == '__main__':
    main()
