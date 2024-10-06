## Problem 
We need to find multicollission with known prefixes
```python
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
```
Task was inspired by https://gist.github.com/DavidBuchanan314/a15e93eeaaad977a0fec3a6232c0b8ae
## Part 1 CRC collission
Main idea was explained in https://gist.github.com/DavidBuchanan314/a15e93eeaaad977a0fec3a6232c0b8ae , but TLDR:
We can collide CRC with another hash-function if we can generate many collisions for second hash-function.
In my task second hash function was PyHash.
Ok, if we generate many collisions for second hash-function we can MITM CRC (because `PyHash(blocks[i][0]) = PyHash(blocks[i][1])` then we have same PyHash and different CRC) instead of bruteforce all combinations of CRC $O(2^n) \rightarrow O(2^{\frac{n}{2}})$.

Only thing i've patched is CRC function to remove $crc(a \oplus b) = crc(a)\oplus crc(b)\oplus crc(0)$ property. Because hellman said in comments:
*You can actually forge MD5+any affine hash (e.g. any large CRC) by solving some linear system instead of MitM*
I was afraid that someone would just solve a linear system.
## Part 2 PyHash collision
We have hash of int tuple + some prefix. we need to find collision of form
```python
assert hash((b'prefix1', m1_int1, m1_int2, ...)) ==  hash((b'prefix2', m2_int1, m2_int2, ...))
```
Lets checkout [python tupleobject.c source code](https://github.com/python/cpython/blob/3.10/Objects/tupleobject.c#L406):
```c
#if SIZEOF_PY_UHASH_T > 4
#define _PyHASH_XXPRIME_1 ((Py_uhash_t)11400714785074694791ULL)
#define _PyHASH_XXPRIME_2 ((Py_uhash_t)14029467366897019727ULL)
#define _PyHASH_XXPRIME_5 ((Py_uhash_t)2870177450012600261ULL)
#define _PyHASH_XXROTATE(x) ((x << 31) | (x >> 33))  /* Rotate left 31 bits */
#else
#define _PyHASH_XXPRIME_1 ((Py_uhash_t)2654435761UL)
#define _PyHASH_XXPRIME_2 ((Py_uhash_t)2246822519UL)
#define _PyHASH_XXPRIME_5 ((Py_uhash_t)374761393UL)
#define _PyHASH_XXROTATE(x) ((x << 13) | (x >> 19))  /* Rotate left 13 bits */
#endif

/* Tests have shown that it's not worth to cache the hash value, see
   https://bugs.python.org/issue9685 */
static Py_hash_t
tuplehash(PyTupleObject *v)
{
    Py_ssize_t i, len = Py_SIZE(v);
    PyObject **item = v->ob_item;

    Py_uhash_t acc = _PyHASH_XXPRIME_5;
    for (i = 0; i < len; i++) {
        Py_uhash_t lane = PyObject_Hash(item[i]);
        if (lane == (Py_uhash_t)-1) {
            return -1;
        }
        acc += lane * _PyHASH_XXPRIME_2;
        acc = _PyHASH_XXROTATE(acc);
        acc *= _PyHASH_XXPRIME_1;
    }

    /* Add input length, mangled to keep the historical value of hash(()). */
    acc += len ^ (_PyHASH_XXPRIME_5 ^ 3527539UL);

    if (acc == (Py_uhash_t)-1) {
        return 1546275796;
    }
    return acc;
}
```
Rewrite it in python:
```python
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
```
Ok this looks like [Merkle–Damgard construction](https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction).
We need to guess that `hash(int.from_bytes(m[i:i+8], 'big')) = z % 2^61-1` but `int.from_bytes(m[i:i+8], 'big')` is bounded by `2^64`, then we can take about `2^3` another 8-byte strings like `long_to_bytes(int.from_bytes(m[i:i+8], 'big')), long_to_bytes(int.from_bytes(m[i:i+8], 'big') + 2**61-1), ...`

However we can't generate same pyhash from beggining due byte prefixes (which hashes we know).
My idea was to find such `a,b` that `hash((b'prefix1', a)) = hash((b'prefix2', b))`:
```python
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
```
but `lane` is bounded by $(0;2^{61}-1]$ then sometimes my sploit won't work. Solution of this problem: just rerun it LOL.
## PART 3 JOIN ALL TOGETHER
```python
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
```