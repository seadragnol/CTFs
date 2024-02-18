#!/usr/bin/env python3

from pwn import *

context.terminal = ["tmux", "splitw", "-h"]

exe = ELF("heapsort_patched")
libc = ELF("libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe

host = "chall.lac.tf"
port = 31168

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

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
# main: 0x00401822

gdbscript = '''
start
bp 0x00401822
c
'''.format(**locals())

# shortcut lambda
info = lambda msg: log.info(msg)
sla = lambda msg, data: io.sendlineafter(msg, data)
sa = lambda msg, data: io.sendafter(msg, data)
sl = lambda data: io.sendline(data)
s = lambda data: io.send(data)
# --- end ---

menu_choice = b"choice: "

def ALLOC(size: bytes, data:bytes):
    sla(menu_choice, b"1")
    sla(b"size: ", size)
    sla(b"data: ", data)

def DELETE(idx: bytes):
    sla(menu_choice, b"2")
    sla(b"idx: ", idx)

def VIEW(idx: bytes):
    sla(menu_choice, b"3")
    sla(b"idx: ", idx)

def SORT():
    sla(menu_choice, b"4")

io = start()

# good luck pwning :)

io.interactive()

