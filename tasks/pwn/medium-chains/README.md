# BRICS+ CTF 2024 | chains

## Description

> A single proxy is not secure enough.
> 
> Modern hackers need to use chains of proxies to remain anonymous.
> 
> I've created a service to store these chains.
> 
> It's 100% safe, I guarantee it.

## Public archive

- [public/chains.tar.gz](public/chains.tar.gz)

## Deploy

```
cd deploy && docker compose up --build -d
```

## Solution

The service is written in [C](https://en.wikipedia.org/wiki/C_(programming_language)). It implements the simple text-based inteface.

There are two vulnerabilities: double free and UAF (use after free). The deletions are not synchronized:

- when we delete a proxy the service frees it but doesn't delete it from chains where this proxy is used

- when we delete the chain it frees the corresponding proxies but doesn't delete them from the global `proxies` array and from other chains

So we can access the freed objects.

Let's look at the structures:

```c
#define HOSTNAME_SIZE 128

typedef struct _proxy {
    char* hostname;
    int16_t port;
} proxy_t;

typedef struct _chain {
    proxy_t* proxy;
    struct _chain* next;
} chain_t;
```

There are two types of chunks we can create:

- 0x20: `proxy_t` and `chain_t`

- 0x90: `proxy_t.hostname`

Since the hostname chunk is in unsorted bin it could be used to leak the libc address. We can overlap `proxy_t` and `chain_t` objects and use the `proxy_t.hostname` pointer to read a string at any address (view chain handler).

The indended exploitation is following:

1. leak the heap address by overlapping `proxy_t` and `chain_t` objects

2. construct the arbitrary read primitive using `proxy_t.hostname` pointer

3. leak the libc address from the freed unsorted chunk

4. leak `environ` pointer from libc

5. get a chunk on the stack using tcache poisoning

6. write the ROP-chain and call `system("/bin/sh")`

Example solver: [solution/sploit.py](solution/sploit.py)

## Flag

```
brics+{God_b1ess_unS0rtEd_b1N}
```