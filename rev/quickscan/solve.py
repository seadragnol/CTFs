#!/usr/bin/env python3

from pwn import *
import base64

# use "-l 500" with splitmind
context.terminal = ["tmux", "splitw", "-h", "-l 500"]

exe = ELF("exe_patched")
context.binary = exe

host = "94.237.62.94"
port = 34713

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
c
'''.format(**locals())

io = start()

# --- good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :) ---

# demo
io.recvuntil(b"ELF:  ")
base64_elf = io.recvline()[:-1]
elf = base64.b64decode(base64_elf)
code_addr = elf.find(b"\x48\x8d\x35")
info(f"code_location: {hex(code_addr)}")
offset = u32(elf[code_addr+3:code_addr+7], sign=True)
payload_location = code_addr + 7 + offset
info(f"payload_location: {hex(payload_location)}")
payload = elf[payload_location:payload_location+0x18].hex()
sla(b"Bytes?", payload.encode())

# real
success(f"done demo")

for i in range(128):
    io.recvuntil(b"ELF:  ")
    base64_elf = io.recvline()[:-1]
    elf = base64.b64decode(base64_elf)
    code_addr = elf.find(b"\x48\x8d\x35")
    info(f"code_location: {hex(code_addr)}")
    offset = u32(elf[code_addr+3:code_addr+7], sign=True)
    payload_location = code_addr + 7 + offset
    info(f"payload_location: {hex(payload_location)}")
    payload = elf[payload_location:payload_location+0x18].hex()
    sa(b"Bytes?", payload.encode() + b"\n")

    success(f"done {i}")


success(io.recv().decode())
success(io.recv().decode())
io.close()


# [+]
# [DEBUG] Received 0x48 bytes:
#     b"Wow, you did them all. Here's your flag: HTB{y0u_4n4lyz3d_th3_p4tt3ns!}\n"
# [+] Wow, you did them all. Here's your flag: HTB{y0u_4n4lyz3d_th3_p4tt3ns!}
# [*] Closed connection to 94.237.62.94 port 34713

