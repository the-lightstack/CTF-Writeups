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
  return 0;```
You may have noticed as well, that we are executing **scanf**, but haven't freed up any space on the stack! (For further information on **scanf** just execute `man scanf`)<br>
I debugged the program in gdb to find out that 



