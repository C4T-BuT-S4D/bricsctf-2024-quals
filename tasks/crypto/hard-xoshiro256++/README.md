# BRICS+ CTF 2024 | xoshiro256++

## Description

> This is xoshiro256++ 1.0, one of our all-purpose, rock-solid generators. 
> It has excellent (sub-ns) speed, a state (256 bits) that is large enough for 
> any parallel application, and it passes all tests we are aware of.
>

## Public archive

- [public/xoshiro256++.tar.gz](public/xoshiro256++.tar.gz)

## Solution

1. install sagemath

2. `g++ -o hax hax.cpp -std=c++20`

3. `./hax < output.txt`

Example solver: [solution/3.py](solution/3.py) & [solution/hax.cpp](solution/hax.cpp)

## Flag

```
brics+{s3y3mbzgar1kvoqy08m2nygiddrhex2t}
```
