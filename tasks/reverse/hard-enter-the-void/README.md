# BRICS+ CTF 2024 | Enter The Void

## Description

> 
## Public archive

- [public/enter_the_void.7z](public/enter_the_void.7z)

## Deploy

none

## Solution

1. dump flag.txt
2. dump keks.exe
3. reverse keks.exe and locate shellcode
4. reverse shellcode
5. Shellcode use CryptProtectMemory with flag SAME_PROCESS inside lsass.exe
6. decyrpt flag.txt

Example solver: [solution/solver.py](solution/solver.py)

## Flag

```
brics+{1m_just_4_m4n_1n_th3_w0rld_0f_p41n_4nd_suff3r1ng}
```
