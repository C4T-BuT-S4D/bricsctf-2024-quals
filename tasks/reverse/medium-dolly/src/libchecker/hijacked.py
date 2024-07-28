import ctypes

import os
import string

valid = False

mask = bytes.fromhex('111b0e021f5f081a50000e5f19ee958c0d13079e72744f23647d31b1df47860c4401d6609b3a2e93121ef37ab78447d7018d0dcebf2cc129b9d51279ce58129db9fd1eb08bdf900963c0b22b45f118d3551c04017d6c0025cead0b7f08c839fe069276399d2d84cbb673ff10f16390c42679cabce1fe2593fae171eb8d99358149b89176e82951766031de4f9061a46e33e8c5b83e4bec21dddaa06c9f3eea8f812c27246fa8bb13cacbd51b8e27fc53a49fe1535d93ce271b7933034dd8bf7d5bf1f5d3e1e413e84cea3f457c6601d8932e82fbe1d0202666ab3f41e58b80c8fef840e8e1e7827cfb815d9ccb5265231adeeef4904bb7e06ff4f0b9a10fa89d')
secret = bytes(x ^ y for x, y in zip(mask, flag))

ptr = ctypes.c_char_p(secret)
length = ctypes.c_size_t(len(secret))

dlsym = ctypes.CDLL(None).dlsym
dlsym.restype = ctypes.c_ulonglong

symbol = dlsym(None, ptr)

if symbol:
    checker = ctypes.CFUNCTYPE(
        ctypes.c_bool, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p,
    )(symbol)

    result = checker(ctypes.c_char_p(), ctypes.addressof(length), ptr)

    if result:
        nonce = os.urandom(len(secret))

        if secret == nonce:
            valid = True

    ctypes.memmove(length.value, ptr, len(secret))

    if any(chr(x) not in string.printable for x in flag):
        raise Exception('non-printable characters in flag')
