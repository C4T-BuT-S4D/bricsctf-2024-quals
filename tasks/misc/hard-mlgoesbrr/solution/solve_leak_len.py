import sys
from pwn import *

conn = remote(sys.argv[1], sys.argv[2])

with open(sys.argv[3], 'rb') as f:
    zip_data = f.read()

conn.sendline(str(len(zip_data)).encode())

conn.recvuntil(b"Send me the zip archive with your model\n")

conn.send(zip_data)

conn.recvuntil(b"Expecting features")

conn.recvuntil(b"]\n")

conn.sendline(b'{"cat": "num_chars"}')

print(conn.recvline().decode())

conn.close()