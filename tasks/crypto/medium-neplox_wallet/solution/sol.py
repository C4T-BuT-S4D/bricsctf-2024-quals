import os
import pwn

'''
if x is int
hash(x) = hash(x) %2305843009213693951

Задача сейчас:
    hash([i for i in x]) = hash([j for j in y]) && crc32(x) == crc32(y)
    решается через то что hash(i) = hash(i+2305...)
    и дальше mitm
Задача потом:
    mmh3(x) = mmh3(y) && crc32(x) = crc32(y)
    нужно понять биекция ли mmh3. Если да, то пизда
'''

## PART 1

def create_table():
    a = []
    for i in range(256):
        k = i
        for j in range(8):
            if k & 1:
                k ^= 0x1db710640
            k >>= 1
        a.append(k)
    return a

crc_table = create_table()
inv_table = [None]*256
for i, x in enumerate(crc_table):
    inv_table[x>>24] = (x << 8) ^ i


def crc32_my(buffer, crc=0):
    crc = ~crc % 2**32
    for i in range(len(buffer)):
        crc ^= buffer[i]
        for k in range(8):
            crc = (crc >> 1 ^ 0xedb88320) if (crc & 1) else (crc >> 1)
        crc = crc * 0x29c20eeb % 2**32
    return ~crc % 2**32


def inverse_crc32_my(buffer, crc):
    crc = ~crc % 2**32
    for k in buffer[::-1]:
        crc = crc * pow(0x29c20eeb, -1, 2**32) % 2**32
        crc = ((crc << 8) ^ inv_table[crc >> 24] ^ k) % 2**32
    return ~crc % 2**32


PYHASH_PRIME = 2305843009213693951
blocks = []

# 9^ctr 
ctr = 18
for i in range(ctr):
    sub_block = []
    while len(sub_block) < 2:
        sub_block = []
        txt = int.from_bytes(os.urandom(8), 'big')
        j = 0
        while j*PYHASH_PRIME + txt < 2**64:
            sub_block.append((j*PYHASH_PRIME + txt).to_bytes(8, 'big'))
            j += 1
    blocks.append(sub_block)

forward_blocks = blocks[:ctr//2]
backward_blocks = blocks[ctr//2:][::-1]

def search_forwards(table, sum, history=[], idx=0):
    if idx >= len(forward_blocks):
        table[sum] = history
        return
    for i, child in enumerate(forward_blocks[idx]):
        search_forwards(table, crc32_my(child, sum), history + [i], idx+1)

def search_backwards(table, sum, history=[], idx=0):
    if idx >= len(backward_blocks):
        if sum in table:
            return table[sum] + history[::-1]
        return
    for i, child in enumerate(backward_blocks[idx]):
        res = search_backwards(table, inverse_crc32_my(child, sum), history + [i], idx+1)
        if res is not None:
            return res

def do_preimage(prefix):
    table = {}
    search_forwards(table, crc32_my(prefix))
    print('LOG: search forward ended')
    path = search_backwards(table, 0x1337)
    assert path is not None

    msg_append = b"".join([b[i] for i, b in zip(path, blocks)])
    result_msg = prefix + msg_append
    return msg_append

## PART 2


def hash(x):
    if type(x) is int:
        return x % PYHASH_PRIME
    elif x == b'Plox!':
        return pyhash_pref1
    elif x == b'GigaPlox!':
        return pyhash_pref2
    return -1

def tuple_hash_round(acc, hash_element):
    lane = hash(hash_element)
    assert lane != -1

    acc = (acc + lane * 14029467366897019727) % 2**64
    acc = ((acc << 31) | (acc >> 33)) % 2**64
    acc = acc * 11400714785074694791 % 2**64
    return acc

def tuple_hash(tup):
    acc = 2870177450012600261
    for i in range(len(tup)):
        acc = tuple_hash_round(acc, tup[i])

    acc += len(tup) ^ (2870177450012600261 ^ 3527539)
    acc %= 2**64
    if acc == -1:
        return 1546275796
    return acc

def tuple_hash_round_reverse(acc, hash_element):
    lane = hash_element
    assert lane != -1

    acc = acc * pow(11400714785074694791, -1, 2**64) % 2**64
    acc = ((acc >> 31) | (acc << 33)) % 2**64
    acc = (acc - lane * 14029467366897019727) % 2**64
    return acc

def gen_target_element_hash_pair(prefix1, prefix2, acc=2870177450012600261):
    acc1 = tuple_hash_round(acc, prefix1)
    acc2 = tuple_hash_round(acc, prefix2)
    print(f'{acc1=}')
    print(f'{acc2=}')
    # reverse round to find correct hash(element)

    # acc1 + lane1 * 14029467366897019727 = acc2 + lane2 * 14029467366897019727 mod 2^64
    # (acc1 - acc2)/14029467366897019727 = lane2 - lane1 mod 2^64
    # because 0 < lane < PYHASH_PRIME
    # we have 2^64-p < (lane2 - lane1) < 2^64 || 0 < (lane2 - lane1) < p
    lane_delta = (acc1 - acc2) * pow(14029467366897019727, -1, 2**64) % 2**64
    if (2**64 - PYHASH_PRIME) < lane_delta:
        return (lane_delta, 0)
    elif lane_delta < PYHASH_PRIME:
        return (0, lane_delta)
    else:
        return (-1, -1)

pwn.context.log_level='debug'

pref_pad_pair = (-1, 1)
while True:
    io = pwn.remote("127.0.0.1", 18484)
    pyhash_pref1 = int(io.recvline()[len("hash(b'Plox!')= "):])#b'Plox!'
    pyhash_pref2 =  int(io.recvline()[len("hash(b'GigaPlox!')= "):])#b'GigaPlox!'

    pref_pad_pair = gen_target_element_hash_pair(b'Plox!', b'GigaPlox!')
    if pref_pad_pair == (-1, -1):
        io.close()
        continue
    break
print(pref_pad_pair)

m1_pad = pref_pad_pair[0].to_bytes(8, 'big')
m2_pad = pref_pad_pair[1].to_bytes(8, 'big')

# assert hash((pyhash_pref1, pair1)) % 2**64 == hash((pyhash_pref2, pair2)) % 2**64
m1 = do_preimage(b'Neplox' + m1_pad)
m2 = do_preimage(b'GigaNeplox' + m2_pad)

io.sendlineafter('input m1 hex: ', m1_pad.hex()+m1.hex())
io.sendlineafter('input m2 hex: ', m2_pad.hex()+m2.hex())

print(io.recv())
# we want get zero in two first blocks like hash((b'Neplox', m1_blocks[0])) = hash((b'GigaPlox', m2_blocks[1])) = 0 (or another constant)

io.close()
