# [](https://pwnable.tw/challenge/#)

## I. Descriptions

bliutech: Can we get ApletGPT?\
me: No we have ApletGPT at home.\
ApletGPT at home:

`nc chall.lac.tf 31123`

## II. Signatures

leak stack canary because of gets overflow

## III. recon

```bash
┌──(kali㉿kali)-[~/…/LACTF_2024/pwn/aplet123/bin]
└─$ file aplet123
aplet123: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=619af28252ed37dccfb030d6ec66f10f5bb124cb, for GNU/Linux 3.2.0, not stripped
```

```bash
┌──(kali㉿kali)-[~/…/LACTF_2024/pwn/aplet123/bin]
└─$ pwn checksec aplet123
[*] '/home/kali/Documents/pwn-everything/CTFs/LACTF_2024/pwn/aplet123/bin/aplet123'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

libc version: 2.

脆弱性:

- Partial RELRO
- PIE:      No PIE (0x400000)

## IV. source code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void print_flag(void) {
  char flag[256];
  FILE *flag_file = fopen("flag.txt", "r");
  fgets(flag, sizeof flag, flag_file);
  puts(flag);
}

const char *const responses[] = {"L",
                                 "amongus",
                                 "true",
                                 "pickle",
                                 "GINKOID",
                                 "L bozo",
                                 "wtf",
                                 "not with that attitude",
                                 "increble",
                                 "based",
                                 "so true",
                                 "monka",
                                 "wat",
                                 "monkaS",
                                 "banned",
                                 "holy based",
                                 "daz crazy",
                                 "smh",
                                 "bruh",
                                 "lol",
                                 "mfw",
                                 "skissue",
                                 "so relatable",
                                 "copium",
                                 "untrue!",
                                 "rolled",
                                 "cringe",
                                 "unlucky",
                                 "lmao",
                                 "eLLe",
                                 "loser!",
                                 "cope",
                                 "I use arch btw"};

int main(void) {
  setbuf(stdout, NULL);
  srand(time(NULL));
  char input[64];
  puts("hello");
  while (1) {
    gets(input);
    char *s = strstr(input, "i'm");
    if (s) {
      printf("hi %s, i'm aplet123\n", s + 4);
    } else if (strcmp(input, "please give me the flag") == 0) {
      puts("i'll consider it");
      sleep(5);
      puts("no");
    } else if (strcmp(input, "bye") == 0) {
      puts("bye");
      break;
    } else {
      puts(responses[rand() % (sizeof responses / sizeof responses[0])]);
    }
  }
}
```

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
