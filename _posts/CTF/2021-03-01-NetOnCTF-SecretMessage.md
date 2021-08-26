---
title: NetOn CTF 2021 - SecretMessage
category: CTF
tags: crypto
hidden_tags: write-up
excerpt_separator: <!--more-->
---

Cryptography -- 247 pts (8 solves) -- Chall author: X4v1l0k

Simple reversing of a custom encryption function.

<!--more-->

## Challenge

![](/assets/ctf/Coding%20-%20SecretMessage.png)

So we already have our flag
```
̜͍͑͋˻͒̽͊˼˻͇̽̓˻͍͉̼͍̀͌˻͑͂̇˻͉͓͍͂˻͇̽̓̀˻͉͉̀͌̕ͅ˻̢̜̭̝̜͖̼̺͍̺͕͇̺͎̼̌͋̎͋̋͌̀̌̎͌͘
```
but it looks kind of weird... Luckily, they tell us how they encrypted it
```py
def encrypt(pwd, s):
	n = 0
	for c in pwd: n += ord(c)
	lc = string.ascii_lowercase
	uc = string.ascii_uppercase
	tcyph = str.translate(s, str.maketrans(lc + uc, lc[13:] + lc[:13] + uc[13:] + uc[:13]))
	fcyph = ''
	for c in tcyph: fcyph += chr(ord(c) + n)
	return fcyph
```

## Solution

Seems we have a simple translation mapping, by swapping the halves of the lower- and uppercase alphabet, and an addition factor. This factor is made by adding the ord values of all charaters in a password. Knowing this factor is zero at the beginning we can find it by guessing the first letter to be 'N'. Using a simple Python script
```py
# Imports
import string

lc = string.ascii_lowercase
uc = string.ascii_uppercase
# Alphabet in, alphabet out
dic_in = lc + uc
dic_out = lc[13:] + lc[:13] + uc[13:] + uc[:13]
# Offset guess
n = 731
# Flag
flag = [chr(ord(i)-n) for i in list('̜͍͑͋˻͒̽͊˼˻͇̽̓˻͍͉̼͍̀͌˻͑͂̇˻͉͓͍͂˻͇̽̓̀˻͉͉̀͌̕ͅ˻̢̜̭̝̜͖̼̺͍̺͕͇̺͎̼̌͋̎͋̋͌̀̌̎͌͘')]
# Loop over flag 
for i,char in enumerate(flag):
    if char in lc+uc:
        flag[i] = dic_in[dic_out.index(char)]

print(''.join(flag))
```
we find
```
Nice job! you earned it, take your award: NETON{n1c3_c0de_my_fr13nd}
```
Note that we got lucky. I guessed 'N' to be the first letter because of the flag format (NETON{}), however it did not start with the flag. Second option would have been to guess the final character to be '}', so we would have found it either way :).