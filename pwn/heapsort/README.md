# [](https://pwnable.tw/challenge/#)

## I. Descriptions

what are data structures? i only know pwn

`nc chall.lac.tf 31168`

## II. Signatures

## III. Setup challenge

```bash

```

## IV. recon

```bash
┌──(kali㉿kali)-[~/…/LACTF_2024/pwn/heapsort/bin]
└─$ file heapsort
heapsort: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=4fb71bef5f06b78a76d3915da1d48d3c585943e5, for GNU/Linux 3.2.0, stripped
```

```bash
┌──(kali㉿kali)-[~/…/LACTF_2024/pwn/heapsort/bin]
└─$ pwn checksec heapsort
[*] '/home/kali/Documents/pwn-everything/CTFs/LACTF_2024/pwn/heapsort/bin/heapsort'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

libc version: 2.31

脆弱性:

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
