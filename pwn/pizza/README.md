# [](https://pwnable.tw/challenge/#)

## I. Descriptions

yummy

`nc chall.lac.tf 31134`

## II. Signatures

format string leak code, libc\
format string overwrite got entry

`lactf{golf_balls_taste_great_2tscx63xm3ndvycw}`

## III. Setup challenge

```bash

```

## IV. recon

```bash
┌──(kali㉿kali)-[~/…/LACTF_2024/pwn/pizza/bin]
└─$ file pizza
pizza: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6f4ecd09a48d42fca8bf0969a65bd8d9813f9357, for GNU/Linux 3.2.0, not stripped
```

```bash
┌──(kali㉿kali)-[~/…/LACTF_2024/pwn/pizza/bin]
└─$ pwn checksec pizza
[*] '/home/kali/Documents/pwn-everything/CTFs/LACTF_2024/pwn/pizza/bin/pizza'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

脆弱性:

- RELRO:    Partial RELRO
- Stack:    No canary found

## V. reverse

by ghidra

### 1. FUN_

```c

```

### 2. FUN_

```c

```

#### **vulnerability 1 - heap overflow**

## VI. exploit

### 1. exploit Tcache Dup < 2.29 to tricks malloc into returning a pointer to an arbitrary memory location => arbitrary write

## VII. flag

### 1. poc

[solve.py](./bin/solve.py):

```python

```

### 2. results

```bash

```

## IX. References

[Tcache Dup < 2.29](https://0x434b.dev/overview-of-glibc-heap-exploitation-techniques/#tcache-dup)
