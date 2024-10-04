# BRICS+ CTF 2024 | surius-6b-user

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

User flag:
1. get accounts enum from main page of web application
2. view robots.txt
3. get information from /user/<name>-<surname> directories
4. get connection.conf and loot admin password
5. goto /admin and enter password
6. make ruby open rce and get revshell
7. read /ozon1337games/user.txt and get flag
8. read /ozon1337games/creds.txt and get creds for the system task

## Flag

```
user flag - brics+{201b487723a71ba438ff75d1fd4669c8}
```