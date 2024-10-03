# BRICS+ CTF 2024 | surius-6b-system

## Description

> Inspiration for great works of space fiction from a great author
> 
> Try to escape from this planet
>

## Public archive


## Deploy

```
cd deploy && docker compose up --build -d
```

## Solution

System flag:
1. /opt/escape binary is suid and RPATH is './'
2. Run binary with your own libc

## Flag

```
system flag - brics+{a70b2cddeaab3655669db72bc16129fe}
```