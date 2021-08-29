---
title: WORMCON 0x01 2021 - Exclusive
category: CTF
tags: crypto XOR brute-force
hidden_tags: write-up
excerpt_separator: <!--more-->
---

Cryptography -- 100 pts (25 solves) -- Chall author: BUILDYOURCTF

A home-rolled XOR cipher with a stunning key space of 1 byte, yes a total of 256 different keys. That just asks to be brute-forced and so that is exactly what we will do. Try out all the keys and get our flag.

<!--more-->

Check out write-ups by my teammates on [K3RN3L4RMY.com](http://k3rn3l4rmy.com/writeups)

## Exploration

![](/assets/ctf/Exclusive_chall.png)

Take a look at the source code. More specifically, can you spot the vulnerability without understanding the encryption process at all?

```py
def splitit(n):
    return (n >> 4), (n & 0xF)

def encrypt(n, key1, key2):
    m, l = splitit(n)
    e = ((m ^ key1) << 4) | (l ^ key2)
    return e

FLAG = open('flag.txt').read().lstrip('wormcon{').rstrip('}')
alpha = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_'

assert all(x in alpha for x in FLAG)

otp = int(os.urandom(1).hex(), 16)
otpm, otpl = splitit(otp)

print(f"{otp = }")
cipher = []

for i,ch in enumerate(FLAG):
    if i % 2 == 0:
        enc = encrypt(ord(ch), otpm, otpl)
    else:
        enc = encrypt(ord(ch), otpl, otpm)
    cipher.append(enc)

cipher = bytes(cipher).hex()
print(f'{cipher = }')

open('out.txt','w').write(f'cipher = {cipher}')
```

The encryption function isn't secure at all, but the biggest problem lies in the following line.

```py
otp = int(os.urandom(1).hex(), 16)
```

This 'otp' variable is used as the key of the encryption process and it is ONLY 1 BYTE LONG! This means that there are only 256 different keys possible, this is way too few and can be easily brute-forced by a computer. In fact, you might even be able to brute-force this on pen and paper within CTF time.


## Exploitation

The brute-force is quite easily set up as we just copy-paste most of the source code but replace the random key generation with a for-loop that iterates over all possible key values, 0 to 255. Somewhere amongst the output will we find our flag! You could make it a bit easier for yourself by adding an if-statement to the final print call that check for the presence of the substring 'wormcon' (flag format).

```py
def splitit(n):
	return (n >> 4), (n & 0xF)

def encrypt(n, key1, key2):
	m, l = splitit(n)
	e = ((m ^ key1) << 4) | (l ^ key2)
	return e

alpha = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_'

cipher = "a1adabc2b7acbbffb5ae86fee8edb1aeabc2e8a886a986f5e9f0eac2bbefeaeaeaf986fee8edb1aeab"

for k in range(256):
    otpm, otpl = splitit(k)
    
    plain = []

    for i,ch in enumerate(bytes.fromhex(cipher)):
        if i % 2 == 0:
            enc = encrypt(ch, otpm, otpl)
        else:
            enc = encrypt(ch, otpl, otpm)
        plain.append(enc)

    plain = bytes(plain)
    print(plain)
```

Ta-da!
```
wormcon{x0r_n1bbl3_c1ph3r_15_4_h0m3_br3w3d_c1ph3r}
```
