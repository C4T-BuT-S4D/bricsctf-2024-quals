#!/usr/bin/env python3
import sys
import os
import base64

MAX_USER_INPUT = 76

def checkElf(data: bytes) -> bool:
    if data[0:4] != b'\x7fELF':
        return False
    if data[0x12] != 0x3e:
        return False
    if data[0x10] != 0x2:
        return False

    return True

def main():
    elf_data = input("[?] Enter base64 encoded ELF x64 executable: ")

    try:
        elf_data = base64.b64decode(elf_data)
    except:
        print("[-] Can't decode base64!")
        sys.exit(0)
    
    if len(elf_data) > MAX_USER_INPUT:
        print("[-] Error ELF size!")
        sys.exit(0)
    
    elf_data += b'\x00' * 4
    filename = "/tmp/{}".format(os.urandom(16).hex())
    fd = open(filename, 'wb')
    fd.write(elf_data)
    fd.close()

    os.chmod(filename, 0o755)
    os.execve(filename, [filename], {})

if __name__ == "__main__":
    main()
