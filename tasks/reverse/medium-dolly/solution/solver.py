#!/usr/bin/env python3

mask = bytes.fromhex('111b0e021f5f081a50000e5f19ee958c0d13079e72744f23647d31b1df47860c4401d6609b3a2e93121ef37ab78447d7018d0dcebf2cc129b9d51279ce58129db9fd1eb08bdf900963c0b22b45f118d3551c04017d6c0025cead0b7f08c839fe069276399d2d84cbb673ff10f16390c42679cabce1fe2593fae171eb8d99358149b89176e82951766031de4f9061a46e33e8c5b83e4bec21dddaa06c9f3eea8f812c27246fa8bb13cacbd51b8e27fc53a49fe1535d93ce271b7933034dd8bf7d5bf1f5d3e1e413e84cea3f457c6601d8932e82fbe1d0202666ab3f41e58b80c8fef840e8e1e7827cfb815d9ccb5265231adeeef4904bb7e06ff4f0b9a10fa89d')

'''
gef➤  x/6xg $r8
0x555557837dbd <DollyClass+1605053>:	0xb6c280c0b4c37a5e	0x1803675653a1c364
0x555557837dcd <DollyClass+1605069>:	0xc321a5c3aec384c3	0x5c2014357f9ec2bb
0x555557837ddd <DollyClass+1605085>:	0xc32595c261b4c304	0xbac3397faac357b0

gef➤  x/6xg $r12
0x5555554c7070 <frame_downheap+16>:	0xf06ad984aad61499	0x900d8555d2030e09
0x5555554c7080 <frame_downheap+32>:	0xdeec512ae55ed54c	0x785e71a5f89053bf
0x5555554c7090 <frame_downheap+48>:	0xbd59ff44279d8ed4	0xfe51d8b0a70bb021
'''

check = [
    0xb6c280c0b4c37a5e, 0x1803675653a1c364,
    0xc321a5c3aec384c3, 0x5c2014357f9ec2bb,
    0xc32595c261b4c304, 0xbac3397faac357b0,
]
expected = [
    0xf06ad984aad61499, 0x900d8555d2030e09,
    0xdeec512ae55ed54c, 0x785e71a5f89053bf,
    0xbd59ff44279d8ed4, 0xfe51d8b0a70bb021,
]

acc = 0x3b47217cfd6e251b

secret = []  # flag ^ mask

for i in range(6):
    acc = acc * check[i]
    acc = acc & 0xFFFFFFFFFFFFFFFF

    value = acc ^ expected[i]
    secret.extend(value.to_bytes(8, 'little'))

flag = bytes(
    x ^ y for x, y in zip(secret, mask)
)

print(flag)
