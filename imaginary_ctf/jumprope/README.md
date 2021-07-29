# Jumprope<br>
**Category:** Reverse Engineering<br>
**Points:** 200<br>
**CTF:** [imaginaryCTF 2021](https://2021.imaginaryctf.org) <br>

# First Look

When examining the binary we are given ([Download here](./jumprope)) with the `file` command, we can see that it is *64bit*, *dynamically linked* and *not stripped*, which means the ELF-Execute still has all the symbols, which will make reversing it easier.
Then I of course executed the binary:
```txt
Ice cream!
Soda Pop!
Cherry on top!
Is your flag exact?
Well, let's find out!

Eighty-eight characters!
A secret well kept!
If you get it right,
I'll shout CORRECT!

>>> I_dont_yet_know!
Segmentation fault (core dumped)
```


Strangely we end up segfaulting and not getting a response like **Wrong flag.**, but we will come back to this behavior later, let's first look at the source code [ghidra](https://github.com/NationalSecurityAgency/ghidra) decompiled for us.

The main function looks like this
```c
undefined8 main(void)

{
  int iVar1;
  
  puts("Ice cream!");
  puts("Soda Pop!");
  puts("Cherry on top!");
  puts("Is your flag exact?");
  puts("Well, let\'s find out!");
  sleep(1);
  puts("\nEighty-eight characters!");
  puts("A secret well kept!");
  puts("If you get it right,");
  puts("I\'ll shout CORRECT!\n");
  iVar1 = checkFlag();
  if (iVar1 == 0) {
    printf("Nope!");
  }
  return 0;
}
```
We see that in the case of a wrong flag, it should print `Nope!` instead of segfaulting, so let's now dig into the **checkFlag** functions code.

```c
undefined8 checkFlag(void)

{
  printf(">>> ");
  __isoc99_scanf("%88s%c",register0x00000020,&dead);
  count = 8;
  while (count < 0x60) {
    val = next(val);
    (&stack0xfffffffffffffff8)[count] =
         (&stack0xfffffffffffffff8)[count] ^
         (byte)val ^ (byte)*(undefined8 *)(x + (long)(count + -8) * 8);
    count = count + 1;
  }
  return 0;
  ```
You may have noticed as well, that we are executing **scanf**, but haven't freed up any space on the stack! (For further information on **scanf** just execute `man scanf`)<br>
I debugged the program in gdb to find out that *register0x00000020* is just *rbp*, or *rsp* as they are the same in this binary (which causes the stack frame, which is the difference of both, to be zero in size)<br>
When executing **scanf** we are therefore overwriting values, like the return pointer, that cause the Segmentation fault.
The above given output by ghidra is good, but not easily understood. I simplified it a bit and it should be clearer now.<br>
(This is more pseudo-code than actual C)<br>
```c
undefined8 checkFlag(void)

{
  printf(">>> ");
  __isoc99_scanf("%88s%c",register0x00000020,&dead);
  count = 8;
  x[760] = {0xfd, 0x3c, 0xc4, 0x0e, 0x76, 0xff, 0x4b, 0x45, 0x1f, 0x40, 0xf4, 0xe6, 0x80, 0xb8, 0xb5, 0xe8, 0x76, 0x8e, 0x3b, 0xf8, 0xe4, 0xbd, 0xc9, 0xc7, 0x3f, 0xe6, 0xcf, 0x15, 0x94, 0x9a, 0x8a, 0x28, 0x4e, 0x5e, 0x1e, 0x3f, 0x25, 0xd4, 0x2c, 0xa9, 0x36, 0x28, 0x42, 0x40, 0x93, 0x8d, 0x0f, 0xff, 0xae, 0x2b, 0x2b, 0xdf, 0x7e, 0x1a, 0x4e, 0x05, 0x63, 0xd0, 0x88, 0xe1, 0xa1, 0x1f, 0x5a, 0x3d, 0x36, 0x4f, 0xae, 0x89, 0x7b, 0xd7, 0x27, 0xd0, 0x29, 0xc0, 0x9e, 0xf0, 0x20, 0xdf, 0x69, 0x77, 0x94, 0xe9, 0x58, 0x0f, 0xb8, 0xec, 0xf9, 0x24}
  char* rbp[?];
  while (count < 0x60) {
    val = (byte)next(val);
    			     // ↓(user-input)
    rbp[count] =  rbp[count]  ^ val ^ (x [(count-8)] ); 

    count ++;												 
  }
  return 0;
}
```
You could be confused, where the **x** array suddenly comes from. **x** is a symbol that is internally just a pointer. So when doing the following `(byte)(x + 0x1)` we are technically just getting the second element from the pre-defined symbols laying in memory. I got the **x** values by inspecting the x symbol in ghidra and taking every 8th byte (so all not-0x0 bytes)
<br>
What suprised me about this function is the missing of any check that would return 1 if the flag was correct, which means it either segfaulted somewhere, or returned 0, which would cause the main function to print *Nope!*.<br>
We have now understood that the *while loop* loops over all 88 bytes we supply as the flag (0x60-8, subtracted in the x-index) and that the loop modifies the actual values on the stack and transforms them into some **XOR'ed** version. (Indicated by the **^** operator)
<br>
The missing piece now is the functionality of the **next** function. It does some bitshifting magic and in the end just generates a long stream of seemingly random numbers. I didn't bother reversing it, as it always returned the same numbers I got by debugging it in gdb and breaking right after the function call and printing rax (where the return value of function is put in 64bit binaries).
`[0x2,0x85,0x4d,0xf0,0x68,0xd,0x91,0x7b,0x31,0xcb,0x38,0xd5,0x95,0xf4,0xe7,0xdb,0x81,0xc2,0x26,0x78,0xb4,0x86,0xc8,0xbd,0x98,0x65,0x9c,0xea,0x4a,0xfa,0xf3,0xed,0x40,0x61,0x13,0x3c,0x5a,0x43,0xe4,0x5e,0xcc,0x32,0x4e,0x75,0x25,0xfd,0xf9,0x76,0xa0,0xb0,0x9,0x1e,0xad,0x21,0x72,0x2f,0x66,0x19,0xa7,0xba,0x92,0xfe,0x7c,0x3b,0x50,0xd8,0x4,0x8f,0xd6,0x10,0xb9,0x17,0xb3,0x8c,0x53,0x5d,0x49,0x7f,0xbe,0x1d,0x28,0x6c,0x82,0x47,0x6b,0x88,0xdc,0x8b] # // (0x59)`

# Our Goal
Since there is no actual check on what the values on the stack should be after the **XOR** modification, and there is no **CORRECT!** string in the binary (observed with `strings ./jumprope`) I had to think of something else. I had seen the symbols *c*,*o*,*r*,*e* and *t* in the executable before, but didn't give it much attention until now, because which word can you form out of these 5 letters? **core** – nah. **rocet** – also no. But **correct** would work!<br>
In gdb I 




