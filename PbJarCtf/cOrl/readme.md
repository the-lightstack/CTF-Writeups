# cOrl - easy web chall
This challenge was simply first guessing the admins password (admin)
and then understanding the hint: "The admin must have *put* some addtional protections in place"

I observed the http request in burp and switched out POST for PUT,
The flag: `flag{HTTP_r3qu35t_m3th0d5_ftw}`
