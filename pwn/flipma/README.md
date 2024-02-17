# [](https://pwnable.tw/challenge/#)

## I. Descriptions

what's flipma?

`nc chall.lac.tf 31165`

## II. Signatures

## III. Setup challenge

```bash

```

## IV. recon

```bash
┌──(kali㉿kali)-[~/…/LACTF_2024/pwn/flipma/bin]
└─$ file flipma
flipma: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b20838ed0a0a0cd0b305786ad73fd9dc4ca04161, for GNU/Linux 3.2.0, not stripped
```

```bash
┌──(kali㉿kali)-[~/…/LACTF_2024/pwn/flipma/bin]
└─$ pwn checksec flipma
[*] '/home/kali/Documents/pwn-everything/CTFs/LACTF_2024/pwn/flipma/bin/flipma'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## V. reverse

by ghidra

### 1. main()

```c
undefined8 main(void)

{
  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  while (0 < flips) {
    flip();
  }
  puts("no more flips");
  return 0;
}
```

`flips = 4`

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

<https://robertchen.cc/blog/2020/06/28/house-of-red>
