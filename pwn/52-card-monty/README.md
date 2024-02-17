# [](https://pwnable.tw/challenge/#)

## I. Descriptions

3-card monty was too easy for me so I made 52-card monty! Can you show me the lady?

`nc chall.lac.tf 31132`

## II. Signatures

`52 != 0x52` hehe

leak canary + ret address => can overflow and write win to ret addr

## III. Setup challenge

```bash

```

## IV. recon

```bash
┌──(kali㉿kali)-[~/…/LACTF_2024/pwn/52-card-monty/bin]
└─$ file monty
monty: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=dcdcb9fe864747e688270eb71bbb2258a0b80b7f, for GNU/Linux 3.2.0, not stripped
```

```bash
┌──(kali㉿kali)-[~/…/LACTF_2024/pwn/52-card-monty/bin]
└─$ pwn checksec monty
[*] '/home/kali/Documents/pwn-everything/CTFs/LACTF_2024/pwn/52-card-monty/bin/monty'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

libc version: 2.

脆弱性:

- No RELRO
- No canary found
- NX disabled
- No PIE

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
