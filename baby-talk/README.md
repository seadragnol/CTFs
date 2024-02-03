# [baby-talk](https://ctf.dicega.ng/challs)

## I. Descriptions

take it easy baby, don't you ever grow up, just stay this simple

`nc mc.ax 32526`

## II. Signatures

## III. Setup challenge

```bash

```

## IV. recon

```bash
╰─❯ file chall 
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=d2f83a6455191af173deb5132fdb1c0464cd24bf, not stripped
```

```bash
╰─❯ pwn checksec chall
[*] '/mnt/files/linux/Documents/pwn-everything/CTFs/DiceCTF_2024/baby-talk/bin/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

libc version: 2.

脆弱性:

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
