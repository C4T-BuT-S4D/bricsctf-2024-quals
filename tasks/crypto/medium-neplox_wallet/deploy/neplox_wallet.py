#!/usr/bin/env python3
import os

def crc32_my(buffer, crc=0):
    crc = ~crc % 2**32
    for i in range(len(buffer)):
        crc ^= buffer[i]
        for k in range(8):
            crc = (crc >> 1 ^ 0xedb88320) if (crc & 1) else (crc >> 1)
        crc = crc * 0x29c20eeb % 2**32
    return ~crc % 2**32

print(f"{hash(b'Plox!')= }")
print(f"{hash(b'GigaPlox!')= }")

m1 = bytes.fromhex(input('input m1 hex: '))
m2 = bytes.fromhex(input('input m2 hex: '))

assert len(m1) < 200
assert len(m2) < 200

def my_second_hash(prefix, m):
    return hash((prefix,) + tuple(int.from_bytes(m[i : i + 8], 'big') for i in range(0,len(m),8)))

assert crc32_my(      b'Neplox'+ m1) == crc32_my(      b'GigaNeplox'+ m2) == 0x1337
assert my_second_hash(b'Plox!',  m1) == my_second_hash(b'GigaPlox!',  m2)

print(os.getenv("FLAG", "flag{test_flag}"))
