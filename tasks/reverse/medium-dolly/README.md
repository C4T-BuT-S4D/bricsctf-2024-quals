# BRICS+ CTF 2024 | dolly

## Description

> Dolly (5 July 1996 – 14 February 2003) was the first mammal that was cloned from an adult somatic cell. She was cloned using the process of nuclear transfer from a cell taken from a mammary gland. Her cloning proved that a cloned organism could be produced from a mature cell from a specific body part.

## Public archive

- [public/dolly.tar.gz](public/dolly.tar.gz)

## Deploy

none

## Solution

The challenge is given as a compiled not stripped x64 ELF:

```
> file ./dolly
./dolly: ELF 64-bit LSB pie executable, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=247e0543b72734027c3446c25ca03397af89bb04, not stripped
```

The interface is simple: the binary prompts the flag and checks it:

```
> ./dolly
[!] Hello, Dolly!
[*] Please enter the flag:
> flagflagflagflag
[-] Wrong flag :(
```

### Static analysis

The challenge structure is similar to [Russian Matryoshka doll](https://en.wikipedia.org/wiki/Matryoshka_doll):

1. The main binary `./dolly` is written in C++. It prints `"[!] Hello, Dolly!"` string and initializes in-memory [JVM (Java virtual machine)](https://en.wikipedia.org/wiki/Java_virtual_machine), then loads a `Dolly.class` in runtime from the internal array. When the class is loaded the binary calls the static method `run()`.

2. The `Dolly.class` dumps the file `libchecker.so` and loads it as an external library using `System.load()`. The library implements the native method `boolean checkFlag(String flag)`. The program prints `"[*] Please enter the flag:\n"`, reads the flag from stdin and calls `checkFlag(flag)`. Depending on the result it prints `"[+] Correct flag!\n"` or `"[-] Wrong flag :(\n"`.

3. The library `libchecker.so` is written in C. It initializes in-memory [CPython](https://en.wikipedia.org/wiki/CPython) interpreter and loads the Python code from the internal data using `marshal.loads()`. When the code is loaded, the program executes it and gets the global variable `valid`. The flag check is successful if `valid == True`.

4. The Python code encrypts the flag using XOR and compares the result with the predefined array.

So the Matryoshka looks like this: `[C++] -> [Java] -> [C] -> [Python]`.

But there is a problem. If we just decrypt the flag from Python code we would get this:

```
try harder..............................
```

The binary obviously doesn't accept it, so we need to get deeper:

```
> ./dolly
[!] Hello, Dolly!
[*] Please enter the flag:
> try harder..............................
[-] Wrong flag :(
```

### Dynamic analysis

The file `libchecker.so` is our target since it contains the flag checking function. It seems that the file is patched somehow. We could compare it using a bindiff tool. We need to obtain two versions:

- extract the library manually during the static analysis

- run `./dolly` and save the dumped file from the `/tmp/dolly-xxx` directory

But there is a simpler way: just set a breakpoint at `marshal_loads()` function. We could extract the bytecode from `rsi` register directly:

```
gef➤  x/32xg $rsi
0x555559e9c430:	0x0000000000000001	0x00007fffc580c1e0
0x555559e9c440:	0x00000000000005ba	0xffffffffffffffff
0x555559e9c450:	0x00000000000000e3	0x0000000000000000
0x555559e9c460:	0x0000400000000600	0x0064000000fe7300
0x555559e9c470:	0x0064005a006c0164	0x0064015a016c0164
0x555559e9c480:	0x0264025a026c0164	0x036405a00465035a
0x555559e9c490:	0x04640465065a01a1	0x0665076500840564
0x555559e9c4a0:	0x0183004402830865	0x0aa00065095a0183
0x555559e9c4b0:	0x00650b5a01a10965	0x018309650d650ca0
0x555559e9c4c0:	0x0fa000650e5a01a1	0x105a106a01a10164
0x555559e9c4d0:	0x125f1065116a0065	0x02830b6501641065
0x555559e9c4e0:	0x00657b721365135a	0x0065156a006514a0
0x555559e9c4f0:	0x00650c6a00650a6a	0x0183136504a10a6a
0x555559e9c500:	0x0aa000651665165a	0x0e6517a0006500a1
0x555559e9c510:	0x185a03830b6501a1	0x19a0016564721865
0x555559e9c520:	0x01a1018309650d65	0x026b1a6509651a5a
```

This is a `PyBytes_Type` object. The bytecode has length 0x5ba and starts at `0x555559e9c450`, so we can dump it using the following gdb command:

```
dump binary memory bytecode.bin 0x555559e9c450 0x555559e9c450+0x5ba
```

In order to decompile it we can append a known prefix from some compiled *.pyc file and use [pycdc](https://github.com/zrax/pycdc).

So the actual Python code is here:

```python
import ctypes

import os
import string

valid = False

mask = bytes.fromhex('...')
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
```

It looks more complicated than the original code obtained during the static analysis. Let's examine it carefully:

1. The code loads the function from libc and calls it. We don't know the function name actually, but we know the flag prefix: `brics+{`. After XORing it with the mask we immediately get the known function prefix `sigalts` and the flag prefix `brics+{n1ce`. There is only one function with such prefix: [sigaltstack()](https://man7.org/linux/man-pages/man2/sigaltstack.2.html).

2. So the code calls `sigaltstack()` function. Usually this function is used to store and load alternative signal stack address. In our case this call is used to *load* the address into the variable `length` and the returned value is used later in `memmove()`. Therefore someone should *store* the alternative stack address before. Let's use `strace` to confirm this:

```
> strace ./dolly -f 2>&1 | grep sigaltstack
sigaltstack({ss_sp=0x55aae0037ded, ss_flags=0, ss_size=94192391126461}, NULL) = 0
brics+{n1ce
sigaltstack(NULL, {ss_sp=0x55aae0037ded, ss_flags=SS_ONSTACK, ss_size=94192391126461}) = 0
```

Confirmed: the `sigaltstack()` is used twice. Let's find the first call using `catch syscall sigaltstack` in gdb. We find the following code:

```
gef➤  disassemble
Dump of assembler code for function _ZGTtNSt11logic_errorC2EPKc:
   0x00005555554382d0 <+0>:	cmc
   0x00005555554382d1 <+1>:	shr    BYTE PTR [rcx+0x1e],1
   0x00005555554382d4 <+4>:	push   0x2a
   0x00005555554382d6 <+6>:	push   0xb69ce1c
   0x00005555554382db <+11>:	stc
   0x00005555554382dc <+12>:	cld
   0x00005555554382dd <+13>:	int    0xa9
   0x00005555554382df <+15>:	mov    dl,0x69
   0x00005555554382e1 <+17>:	cs imul eax,DWORD PTR [rcx+rbp*2],0x11698b0f
   0x00005555554382e9 <+25>:	push   0xffffffffbe9fd534
   0x00005555554382ee <+30>:	mov    dh,dh
   0x00005555554382f0 <+32>:	(bad)
   0x00005555554382f1 <+33>:	sub    BYTE PTR [rsp+rbx*4-0x530396b2],bl
   0x00005555554382f8 <+40>:	xor    cl,al
   0x00005555554382fa <+42>:	mov    eax,0xb96db064
   0x00005555554382ff <+47>:	mov    DWORD PTR [rax+0x6a],edx
   0x0000555555438302 <+50>:	add    BYTE PTR [rax-0x7d],cl
   0x0000555555438305 <+53>:	shl    BYTE PTR [rax],0x50
   0x0000555555438308 <+56>:	xor    esi,esi
   0x000055555543830a <+58>:	mov    rdi,rsp
   0x000055555543830d <+61>:	mov    eax,0x83
   0x0000555555438312 <+66>:	syscall
=> 0x0000555555438314 <+68>:	add    rsp,0x18
   0x0000555555438318 <+72>:	mov    rax,rcx
   0x000055555543831b <+75>:	add    rcx,0x8ec9c
   0x0000555555438322 <+82>:	add    rax,0x2cd07c
   0x0000555555438328 <+88>:	mov    rdi,QWORD PTR [rax]
   0x000055555543832b <+91>:	mov    QWORD PTR [rax],rcx
   0x000055555543832e <+94>:	add    rax,0x400
   0x0000555555438334 <+100>:	mov    QWORD PTR [rax],rdi
   0x0000555555438337 <+103>:	ret
```

There are some `(bad)` disassemled values, it means that we've jumped inside the function directly, but it doesn't matter right now. The `eax` value is exactly sigaltstack syscall number 0x83. Let's look at the registers:

```
$rax   : 0x83
$rbx   : 0x0
$rcx   : 0x00005555554c8d70  →  <__libc_csu_init+0> push r15
$rdx   : 0x20
$rsp   : 0x00007fffffffde40  →  0x0000555557837ded  →  <DollyClass+1605101> lahf
$rbp   : 0x00007fffffffde70  →  0x0000000000000008
$rsi   : 0x0
$rdi   : 0x00007fffffffde40  →  0x0000555557837ded  →  <DollyClass+1605101> lahf
```

`rdi` contains the pointer to some structure and `rsi` is NULL, it means that this call *stores* the alternative stack address `0x0000555557837ded`. This address points to some region in memory:

```
gef➤  x/32xg 0x0000555557837ded
0x555557837ded <DollyClass+1605101>:	0xc9da2e69d8a3d49f	0x3169336924680269
0x555557837dfd <DollyClass+1605117>:	0xed2368c81b680b69	0x6906680669b42c69
0x555557837e0d <DollyClass+1605133>:	0xac2e68ba9a3b6832	0xd004699ae03d69a4
0x555557837e1d <DollyClass+1605149>:	0xb13a683669cb1468	0x32688720692c68c3
0x555557837e2d <DollyClass+1605165>:	0x0f691d683968e1e2	0x2f6982aef718688b
0x555557837e3d <DollyClass+1605181>:	0x69d22b6938692a6a	0x69f1db97df1e6918
0x555557837e4d <DollyClass+1605197>:	0xd123691e6808683e	0x066908682e682868
0x555557837e5d <DollyClass+1605213>:	0xfaf3d3b41669a1b2	0x6821692869e6d6f6
0x555557837e6d <DollyClass+1605229>:	0x8121683868316825	0x6805690a69b9add0
0x555557837e7d <DollyClass+1605245>:	0x35683068d3066902	0xf097f79902680468
0x555557837e8d <DollyClass+1605261>:	0xd6d9e21c68e91e69	0x93fcec17691368a8
0x555557837e9d <DollyClass+1605277>:	0xe22a681668ee0f68	0x0e69ffb11668fba4
0x555557837ead <DollyClass+1605293>:	0xf2d40b6934681c69	0x683368b036693968
0x555557837ebd <DollyClass+1605309>:	0x97136934691c693f	0x68b909680d680368
0x555557837ecd <DollyClass+1605325>:	0x692669c20d68bd3f	0xecad176889216835
0x555557837edd <DollyClass+1605341>:	0x9d336890ca3b68b0	0x82993c680368c6d1
```

Now we know that the second `sigaltstack()` will return this address, let's continue to read Python code:

```python
ctypes.memmove(length.value, ptr, len(secret))
```

The `ptr` value contains the `flag` XORed with `mask`. So after the `memmove()` call our encrypted flag will be written to `0x0000555557837ded`. Let's check it after the Python code is executed (for example on `exit()` breakpoint):

```
gef➤  x/s 0x0000555557837ded
0x555557837ded <DollyClass+1605101>:	"sigaltstack"
gef➤  x/16gx 0x0000555557837ded
0x555557837ded <DollyClass+1605101>:	0x7473746c61676973	0x9bed9661006b6361
0x555557837dfd <DollyClass+1605117>:	0x4789c262b1c2a1c3	0xc3acc2acc31e86c3
0x555557837e0d <DollyClass+1605133>:	0x0684c2103091c298	0x7aaec3304a97c30e
0x555557837e1d <DollyClass+1605149>:	0x1b90c29cc361bec2	0x98c22d8ac386c269
0x555557837e2d <DollyClass+1605165>:	0xa5c3b7c293c24b48	0x85c328045db2c221
0x555557837e3d <DollyClass+1605181>:	0xc37881c392c380c0	0xc35b713d75b4c3b2
0x555557837e4d <DollyClass+1605197>:	0x7b89c3b4c2a2c294	0xacc3a2c284c282c2
0x555557837e5d <DollyClass+1605213>:	0x5059791ebcc30b18	0xc28bc382c34c7c5c
```

Nice. But we still didn't find the *real* flag checking algorithm, since the Python code does this:

```python
nonce = os.urandom(len(secret))

if secret == nonce:
    valid = True
```

Obviously there are no chances to pass the check and get `valid = True`. Let's return to strange function with the first `sigaltstack()` call. There are some instructions after it:

```
   0x000055555543830d <+61>:	mov    eax,0x83
   0x0000555555438312 <+66>:	syscall
=> 0x0000555555438314 <+68>:	add    rsp,0x18
   0x0000555555438318 <+72>:	mov    rax,rcx
   0x000055555543831b <+75>:	add    rcx,0x8ec9c
   0x0000555555438322 <+82>:	add    rax,0x2cd07c
   0x0000555555438328 <+88>:	mov    rdi,QWORD PTR [rax]
   0x000055555543832b <+91>:	mov    QWORD PTR [rax],rcx
   0x000055555543832e <+94>:	add    rax,0x400
   0x0000555555438334 <+100>:	mov    QWORD PTR [rax],rdi
   0x0000555555438337 <+103>:	ret
```

We need to examine it during the debugging. Let's break at the two `mov` instructions and look at the registers:

```
mov rdi, QWORD PTR [rax]
mov QWORD PTR [rax], rcx
```

```
gef➤  x/4gx $rax
0x555555705390 <write@got.plt>:	0x0000555555412b56	0x0000555555412b66
0x5555557053a0 <strtoul@got.plt>:	0x0000555555412b76	0x0000555555412b86
gef➤  x/4gx $rcx
0x5555554c6fb0 <_Unwind_Backtrace>:	0xe88149068b445041	0x0fc0854d205d2d5b
0x5555554c6fc0 <_Unwind_Backtrace+16>:	0x0d8d4c0000008d85	0xd0418d4d02370e21
```

What does it mean? The binary replaces the `write()` function in GOT table with `_Unwind_Backtrace` function. Since the function is patched the logic is splitted between many functions:

```
gef➤  x/200i _Unwind_Backtrace
   0x5555554c6fb0 <_Unwind_Backtrace>:	push   r8
   0x5555554c6fb2 <_Unwind_Backtrace+2>:	mov    r8d,DWORD PTR [rsi]
   0x5555554c6fb5 <_Unwind_Backtrace+5>:	sub    r8,0x205d2d5b
   0x5555554c6fbc <_Unwind_Backtrace+12>:	test   r8,r8
   0x5555554c6fbf <_Unwind_Backtrace+15>:	jne    0x5555554c7052 <fde_unencoded_compare+18>
   0x5555554c6fc5 <_Unwind_Backtrace+21>:	lea    r9,[rip+0x2370e21]        # 0x555557837ded <DollyClass+1605101>
   0x5555554c6fcc <_Unwind_Backtrace+28>:	lea    r8,[r9-0x30]
   0x5555554c6fd0 <_Unwind_Backtrace+32>:	lea    r12,[r8-0x2370d4d]
   0x5555554c6fd7 <_Unwind_Backtrace+39>:	movabs r10,0x3b47217cfd6e251b
   0x5555554c6fe1 <_Unwind_Backtrace+49>:	lea    rsi,[r8-0x18587d]
   0x5555554c6fe8 <_Unwind_Backtrace+56>:	mov    edx,0x12
   0x5555554c6fed <_Unwind_Backtrace+61>:	mov    ecx,0x6
   0x5555554c6ff2 <_Unwind_Backtrace+66>:	mov    r15,0x0
   0x5555554c6ff9 <_Unwind_Backtrace+73>:	lea    r11,[r8+r15*8]
   0x5555554c6ffd <_Unwind_Backtrace+77>:	mov    r11,QWORD PTR [r11]
   0x5555554c7000 <_Unwind_Backtrace+80>:	imul   r10,r11
   0x5555554c7004 <_Unwind_Backtrace+84>:	lea    r11,[r9+r15*8]
   0x5555554c7008 <_Unwind_Backtrace+88>:	mov    r13,QWORD PTR [r11]
   0x5555554c700b <_Unwind_Backtrace+91>:	xor    r13,r10
   0x5555554c700e <_Unwind_Backtrace+94>:	lea    r11,[r12+r15*8]
   0x5555554c7012 <_Unwind_Backtrace+98>:	mov    r11,QWORD PTR [r11]
   0x5555554c7015 <_Unwind_Backtrace+101>:	sub    r13,r11
   0x5555554c7018 <_Unwind_Backtrace+104>:	test   r13,r13
   0x5555554c701b <_Unwind_Backtrace+107>:	je     0x5555554c7023 <_Unwind_Backtrace+115>
   0x5555554c701d <_Unwind_Backtrace+109>:	add    rsi,0x15
   0x5555554c7021 <_Unwind_Backtrace+113>:	jmp    0x5555554c7028 <_Unwind_Backtrace+120>
   0x5555554c7023 <_Unwind_Backtrace+115>:	inc    r15
   0x5555554c7026 <_Unwind_Backtrace+118>:	loop   0x5555554c6ff9 <_Unwind_Backtrace+73>
   0x5555554c7028 <_Unwind_Backtrace+120>:	lea    r12,[r12+0x23e720]
   0x5555554c7030 <_Unwind_Backtrace+128>:	mov    r11,QWORD PTR [r12]
   0x5555554c7034 <_Unwind_Backtrace+132>:	sub    r12,0x400
   0x5555554c703b <_Unwind_Backtrace+139>:	mov    QWORD PTR [r12],r11
   0x5555554c703f:	call   r11
   0x5555554c7042 <fde_unencoded_compare+2>:	mov    rax,0xe7
   0x5555554c7049 <fde_unencoded_compare+9>:	mov    rdi,0x0
   0x5555554c7050 <fde_unencoded_compare+16>:	syscall
   0x5555554c7052 <fde_unencoded_compare+18>:	syscall
   0x5555554c7054:	pop    r8
   0x5555554c7056:	ret
```

This function is definitely suspicious. Let's set a breakpoint on this function and run the binary:

```
$rax   : 0x1
$rbx   : 0x12
$rcx   : 0x0
$rdx   : 0x12
$rsp   : 0x00007fffffffdc68  →  0x000055555543406e  →  ...
$rbp   : 0x00005555583c82a0  →  "[!] Hello, Dolly!\n"
$rsi   : 0x00005555583c82a0  →  "[!] Hello, Dolly!\n"
$rdi   : 0x1
$rip   : 0x00005555554c6fb0  →  <_Unwind_Backtrace+0> push r8
```

As expected we've got the call during the printing `"[!] Hello, Dolly!\n"` string. But there is a check: if the `rsi` doesn't contain the value `0x205d2d5b` the function just jumps to `syscall`:

```
   0x5555554c6fb2 <_Unwind_Backtrace+2> mov    r8d, DWORD PTR [rsi]
   0x5555554c6fb5 <_Unwind_Backtrace+5> sub    r8, 0x205d2d5b
   0x5555554c6fbc <_Unwind_Backtrace+12> test   r8, r8
 → 0x5555554c6fbf <_Unwind_Backtrace+15> jne    0x5555554c7052 <fde_unencoded_compare+18>	TAKEN [Reason: !Z]
   ↳  0x5555554c7052 <fde_unencoded_compare+18> syscall
      0x5555554c7054                  pop    r8
      0x5555554c7056                  ret
```

Value `0x205d2d5b` is equal to `'[-] '` string. So if the prefix is not equal to target `'[-] '` the function just writes the string. But if the prefix *is* equal to target the function accesses the address we've seen before:

```
gef➤  x/200i _Unwind_Backtrace
   0x5555554c6fb0 <_Unwind_Backtrace>:	push   r8
   0x5555554c6fb2 <_Unwind_Backtrace+2>:	mov    r8d,DWORD PTR [rsi]
   0x5555554c6fb5 <_Unwind_Backtrace+5>:	sub    r8,0x205d2d5b
   0x5555554c6fbc <_Unwind_Backtrace+12>:	test   r8,r8
=> 0x5555554c6fbf <_Unwind_Backtrace+15>:	jne    0x5555554c7052 <fde_unencoded_compare+18>
   0x5555554c6fc5 <_Unwind_Backtrace+21>:	lea    r9,[rip+0x2370e21]        # 0x555557837ded <DollyClass+1605101>
   0x5555554c6fcc <_Unwind_Backtrace+28>:	lea    r8,[r9-0x30]
   0x5555554c6fd0 <_Unwind_Backtrace+32>:	lea    r12,[r8-0x2370d4d]
   0x5555554c6fd7 <_Unwind_Backtrace+39>:	movabs r10,0x3b47217cfd6e251b
```

See `0x555557837ded <DollyClass+1605101>`? Remember that we've seen this address in `sigaltstack()` call. This is exactly the location of the encrypted flag. We could assume that the other part of `_Unwind_Backtrace` function is the flag checking.

But how we could call `write()` with `'[-] '` prefix? We have seen the string `"[-] Wrong flag :(\n"` in the Java code, but Java won't use our patched `write()` from GOT. In the `./dolly` binary there is exactly one string with this prefix:

```
.rodata:00000000000C8E50 ; const char aHelloDolly[]
.rodata:00000000000C8E50 aHelloDolly     db '[!] Hello, Dolly!',0
.rodata:00000000000C8E50                                         ; DATA XREF: main+19↑o
.rodata:00000000000C8E62 ; const char aError[]
.rodata:00000000000C8E62 aError          db '[-] Error: ',0      ; DATA XREF: main+8C↑o
```

This is an exception handler. If any exception is occured the binary just writes the error and exits. But how we could achieve the exception? After the call of Java function there is the check:

```c
result = JNIEnv_::ExceptionCheck(this[8]);
if ( (_BYTE)result )
{
    JNIEnv_::ExceptionClear(this[8]);
    exception = (std::runtime_error *)_cxa_allocate_exception(0x10uLL);
    std::runtime_error::runtime_error(exception, "failed to check flag");
    _cxa_throw(exception, (struct type_info *)&`typeinfo for'std::runtime_error, std::runtime_error::~runtime_error);
}
```

Java code does not throw any exceptions explicitly, but `libchecker.so` does:

```c
__int64 __fastcall Java_Dolly_checkFlag(__int64 a1, __int64 a2, _QWORD *a3)
{
  int v4; // [rsp+24h] [rbp-1Ch]
  __int64 v5; // [rsp+38h] [rbp-8h]

  v4 = check(*a3 + 40LL);
  if ( v4 >= 0 )
    return (unsigned int)v4;
  v5 = (*(__int64 (__fastcall **)(__int64, const char *))(*(_QWORD *)a1 + 48LL))(a1, "java/lang/Exception");
  (*(void (__fastcall **)(__int64, __int64, const char *))(*(_QWORD *)a1 + 112LL))(a1, v5, "failed to check flag");
  return 0LL;
}

__int64 __fastcall check(__int64 a1)
{
  __int64 Code; // [rsp+10h] [rbp-30h]
  __int64 Exec; // [rsp+18h] [rbp-28h]
  __int64 Globals; // [rsp+20h] [rbp-20h]
  __int64 v5; // [rsp+28h] [rbp-18h]
  __int64 ItemString; // [rsp+30h] [rbp-10h]

  setup();
  Code = createCode();
  Exec = createExec();
  Globals = createGlobals();
  v5 = PyBytes_FromString(a1);
  PyDict_SetItemString(Globals, "flag", v5);
  Py_DECREF_4(v5);
  _PyObject_CallFunction_SizeT(Exec, "OO", Code, Globals);
  Py_DECREF_4(Exec);
  Py_DECREF_4(Code);
  if ( PyErr_Occurred() )
  {
    Py_DECREF_4(Globals);
    PyErr_Clear();
    return 0xFFFFFFFFLL;
  }
  else
  {
    ItemString = PyDict_GetItemString(Globals, "valid");
    if ( ItemString )
      return PyLong_AsLong(ItemString) == 1;
    else
      return 0xFFFFFFFFLL;
  }
}
```

So `libchecker.so` throws a Java exception in two cases:

- There is no `valid` variable in globals. This is not our case because the Python code defines the variable at the beginning: `valid = False`

- There is a Python exception occured. Let's find where Python code throws the exception:

```python
if any(chr(x) not in string.printable for x in flag):
    raise Exception('non-printable characters in flag')
```

But how non-printable characters would be in flag since the Java does the check in `isPrintable(String s)` function? We need to remember that [strings in Java are not null-terminated](https://stackoverflow.com/q/18414873). The String type contains private `length` field, but `libchecker.so` does not use it and just takes the raw pointer to characters. So if there would be some non-printable characters after our string they will become the part of the flag.

Let's set a breakpoint in `Java_Dolly_checkFlag()` and examine the String structure:

```
 → 0x7fffc4e778d5 <Java_Dolly_checkFlag+50> call   0x7fffc4e6a320 <check@plt>
   ↳  0x7fffc4e6a320 <check@plt+0>    jmp    QWORD PTR [rip+0x468232]        # 0x7fffc52d2558 <check@got.plt>
      0x7fffc4e6a326 <check@plt+6>    push   0x4a8
      0x7fffc4e6a32b <check@plt+11>   jmp    0x7fffc4e65890
```

```
gef➤  x/8s $rdi
0x7fe13df28:	"brics+{n1ce"
0x7fe13df34:	""
0x7fe13df35:	""
0x7fe13df36:	""
0x7fe13df37:	""
0x7fe13df38:	"\001\")\251\a"
0x7fe13df3e:	""
0x7fe13df3f:	""
```

See? There are \x01 byte after our flag. So if we input `brics+{n1ce_AAAA` we would get non-printable character in flag:

```
gef➤  x/8s $rdi
0x7fe13dea8:	"brics+{n1ce_AAAA\001\")\251\a"
```

And it will cause the exception. Now do this and breakpoint to `_Unwind_Backtrace` function:

```
$rax   : 0x1
$rbx   : 0x20
$rcx   : 0x0
$rdx   : 0x20
$rsp   : 0x00007fffffffdc68  →  0x000055555543406e  ...
$rbp   : 0x00005555583c82a0  →  "[-] Error: failed to check flag\n"
$rsi   : 0x00005555583c82a0  →  "[-] Error: failed to check flag\n"
$rdi   : 0x1
$rip   : 0x00005555554c6fb0  →  <_Unwind_Backtrace+0> push r8
```

Got it! The last part is just the reverse engineering of the flag checking function. The pseudocode is following:

```
accumulator = 0x3b47217cfd6e251b

for i in range(6):
    accumulator = accumulator * static_array[i]
    value = accumulator ^ encrypted_flag[i]

    if value != expected_values[i]:
        return False
```

Example solver: [solution/solver.py](solution/solver.py)

## Flag

```
brics+{n1ce_j0b_y0u_h4ck3d_th3_d0lly_sh33p_1337}
```
