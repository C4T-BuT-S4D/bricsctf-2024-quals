# BRICS+ CTF 2024 | ML goes BRRRrr

## Description

> I'm really into the ML, but I find it very slow.
>
> But what if we can make it **blazingly fast** ?
> 
> Checkout this new project I've created! It allows you to generate blazingly fast code for your [YDF](https://ydf.readthedocs.io/en/stable/) model!
> 

## Public archive

- [public/mlgoesbrr.zip](public/mlgoessbrr.tar.gz)

## Deploy

```
cd deploy && docker compose up --build -d
```

## Solution

1. Solution one: leak the flag using decision tree. [solve_leak.py](solution/solve_leak.py)
2. Solution two: RCE via impl [solve_rce.py](solution/solve_rce.py)

## Flag

```
brics+{example}
```