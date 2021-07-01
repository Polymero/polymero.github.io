---
title: NetOn CTF 2021 - Facts Br0!
category: CTF
tags: Write-up RSA PEM
excerpt_separator: <!--more-->
---

Crypto -- 244 pts (10 solves) -- Chall author: N0xi0us

Importing the PEM key file we find a very short public key, which we trivially factorise using online tools.

<!--more-->

## Challenge

![](/assets/ctf/Crypto%20-%20Facts%20Br0!.png)

The challenge provides us a long integer as flag and a public key in a PEM file format. Ding ding ding, RSA alert!

## Solution

The public key is too short, which allows us to crack it! The PEM file contains the public parts of RSA cryptography, namely 'n' and 'e', encoded in base64. _If you do not recognise these variables it might be nice to read up a little on RSA cryptography, the encoding itself is fairly straightforward._
```
-----BEGIN PUBLIC KEY-----
MDEwDQYJKoZIhvcNAQEBBQADIAAwHQIWAN4vdj9ZJ337BgYayd9cb2tF0QoJAwID
AQAB
-----END PUBLIC KEY-----
```
However (!), I did not realise that the PEM file format has some additional encoding elements such that you cannot simply convert the two base64 strings to integers and call it a day. I naively found
```
n = 74174491295044795964181854285195495718964397093731395961824370391827799637138867436334319587298835673227084716446
e = 65537
```
Although the 'e' has a commonly used value, the 'n' does not factor nicely into two primes...  So I used a Python library to do it for me properly
```py
from Crypto.PublicKey import RSA

f = open('../public.pem')
key = RSA.importKey(f.read())
print(key.n)
print(key.e)
```
which gave the public RSA elements as
```
n = 324724323060034233289551751185171379596941511493891
e = 65537
```
This time around, the 'n' actually factors nicely (using factordb) into the two primes
```
p = 25001545096244227516337
q = 12988170203481337861511552243
```
Using these and an Euler inverse function, I was able to derive the private key, the private RSA component 'd' to be
```py
def eulinv(x, m):
    a, b, u = 0, m, 1
    while x > 0:
        q = b // x # integer division
        x, a, b, u = b % x, u, x, a - q * u
    if b == 1:
        return a % m
    else:
        return None

d = eulinv(key.e,(p-1)*(q-1)); print(d)
```
```
323728403366806485896597412434387317854754383435009
```
Now we are able to decrypt the provided 'flag' using m = pow(c, d, n). In Python
```py
# Get message from encrypted flag
pow(flag,d,key.n)
# Turn integer into binary (0 added in front )
mbit = bin(26634179113006760524799996616930504110973)[2:]
# Pad with 0s in front to make sure it is in byte format
while len(mbit) % 8 != 0:
    mbit = '0' + mbit
# Bytes -> ASCII
m = ''.join([chr(int(mbit[i:i+8],2)) for i in range(0,len(mbit),8)])
print(m)
```
which happily returns
```
NETON{3z_F4ct0rs}
```