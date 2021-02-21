# Read/Reverse - Writeup

The challenge gives us a `read.pyc` file, so a python compiled file.
When running it, we see a beautiful animation reading "READ" and a scrolling text under it.
There is also an inpt field we shall put our reversed flag into.

I used a great tool called [uncompyle6](https://github.com/rocky/python-uncompyle6) for decompiling the binary.

The result is good, but most function and variable are gibberish like "ubbaaalubba" so I tidied it up a bit.

I noticed this here: `helpful_key = 'you-may-need-this-key-1337'` in the code and noted it down.

After some more staring at the code I was attracted to one special function: (vars renamed for readibility)
```py
def actions(user_input): #triggers to check if inputted string is right
    data_list = [73, 13, 19, 88, 88, 2, 77, 26, 95, 85, 11, 23, 114, 2, 93, 54, 71, 67, 90, 8, 77, 26, 0, 3, 93, 68]
    result = ''
    for i in range(len(data_list)):
        if user_input[i] != chr(data_list[i] ^ ord(helpful_key[i])):
            return 'bbblalaabalaabbblala'
        b2a = ''
        a2b = [122, 86, 75, 75, 92, 90, 77, 24, 24, 24, 25, 106, 76, 91, 84, 80, 77, 25, 77, 81, 92, 25, 92, 87, 77, 80, 75, 92, 25, 74, 77, 75, 80, 87, 94, 25, 88, 74, 25, 95, 85, 88, 94]
        for bbb in a2b:
            b2a += chr(bbb ^ 57)
        else:
            return b2a
``` 

The above code takes an input (use_input) and then loops over data_list and helpful_key, xor's them and checks if the result represented as a character is the same as input string.
<br>
73 13 19 88 88 2 77 26 95 85 11 23 114 2 93 54 71 67 90 8 77 26 0 3 93 68<br>
y  o  u  -  m  a y  -  n  e  e  d  -   t h  i  s  -  k  e y  -  1 3 3  7<br>
<br>
That means if we Xor them ourselves, we get the key required!

My small python script for doing so:
```py
for i in range(len(data_list)):
	print(chr(data_list[i]^ord(helpful_key[i])),end="")
```
The output:
`0bfu5c4710ns_v5_4n1m4710ns`

-----------------------------

I at first didn't notice, that there was actual text written but this here is actually our flag, we just have to wrap it into `darkCON{XXX}`

So the flag is: `darkCON{0bfu5c4710ns_v5_4n1m4710ns}`

We ca enter it into the read.pyc application and it indeed tells us that it is right!


