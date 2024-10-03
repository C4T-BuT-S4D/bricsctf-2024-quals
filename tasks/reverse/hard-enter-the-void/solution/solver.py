import struct
from Crypto.Cipher import AES
from Crypto.Hash import SHA1
from binascii import unhexlify, hexlify

buf = open('flag.txt', 'rb').read()

ctx = SHA1.new()
ctx.update(unhexlify('5f195787275c66819b76523cf1926510efb2ce21b962eb61'))
ctx.update(struct.pack('<LQ', 0x89f279f3, 0x01db1025f67edb7b))
iv = unhexlify('d934db1a1cd64a6a35f157c2913b92ef')
aes_key = ctx.digest()[:16]
flag = AES.new(aes_key, AES.MODE_CBC, IV=iv).decrypt(buf)

print(flag.replace(b'\x00', b''))