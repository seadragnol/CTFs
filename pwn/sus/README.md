# [](https://pwnable.tw/challenge/#)

## I. Descriptions

sus

`nc chall.lac.tf 31284`

## II. Signatures

leak got, ret2libc

## III. recon

```bash
┌──(kali㉿kali)-[~/…/LACTF_2024/pwn/sus/bin]
└─$ file sus
sus: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=efcb91898e2d97cd52cde4de369ff863bde68985, for GNU/Linux 3.2.0, not stripped
```

```bash
┌──(kali㉿kali)-[~/…/LACTF_2024/pwn/sus/bin]
└─$ pwn checksec sus
[*] '/home/kali/Documents/pwn-everything/CTFs/LACTF_2024/pwn/sus/bin/sus'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

脆弱性:

- RELRO:    Partial RELRO
- No canary found
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
