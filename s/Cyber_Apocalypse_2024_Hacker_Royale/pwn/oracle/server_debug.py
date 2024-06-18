#!/usr/bin/env python3

from pwn import *

# use "-l 500" with splitmind
context.terminal = ["tmux", "splitw", "-h", "-l 500"]

exe = ELF("pwn_oracle/challenge/oracle_patched")
libc = ELF("pwn_oracle/challenge/libc-2.31.so")
ld = ELF("pwn_oracle/challenge/ld-2.31.so")
context.binary = exe

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    return start_local(argv, *a, **kw)

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
breakrva 0x0191A  
breakrva 0x0137F

c
'''.format(**locals())

# bp handle_view+0
# breakrva 0x00183A
# breakrva 0x00162D 
# breakrva 0x001790 

io = start()

# --- good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :) ---

io.interactive()

