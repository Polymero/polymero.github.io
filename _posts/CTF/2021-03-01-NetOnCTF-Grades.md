---
title: NetOn CTF 2021 - Grades
category: CTF
tags: Write-up Web Obfuscation
excerpt_separator: <!--more-->
---

Web -- 486 pts (10 solves) -- Chall author: Raulet

Easily reversible encryption function behind obfuscation, yuckie.

<!--more-->

## Challenge

![](/assets/ctf/Web%20-%20Grades.png)

So somebody hacked the final exam grades to inflate their own... up to 1337, alright. Well in that case it seems our friend 'nUK<,IDt-.bvKL|./EO$%;k}@\_' is the culprit. However, his name is encrypted...

## Solution

Within the html file we find some obfuscated javascript

```js
function encrypt(_0x40a681) {
    var _0x16b830 = 0x20, _0x561689 = 0x5e, _0x3db275 = 0x0, _0x38a41d = '';
    for (var _0x278871 = 0x0; _0x278871 < _0x40a681['length']; _0x278871++) {
         _0x38a41d = _0x38a41d + String['fromCharCode']((_0x40a681['charCodeAt'](_0x278871) + _0x3db275) % _0x561689 + _0x16b830), _0x3db275 = _0x3db275 + _0x40a681['charCodeAt'](_0x278871);
    }
    return _0x38a41d;
```
We can de-obfuscate this simple function by replacing the nonsense variable names with names that make sense, and by inserting values wherever possible. After this, we find a more readable encrypt function
```js
function encrypt(input) {
    var output = '', c0 = 0;
    for (var i = 0; i < input['length']; i++) {
        output = output + String['fromCharCode']((input['charCodeAt'](i) + c0) % 94 + 32),
        c0 = c0 + input['charCodeAt'](i);
    }
    return output;
```
Because of the modulo in there, it might be a bit rough to reverse directly, so let's just brute-force it instead. We can do so by simply trying out a character and seeing if our trial flag matches with the given encrypted flag. I used the following script
```py
#!/usr/bin/env python3

# Encryption function
def encrypt(msg):
    out = ''; c0 = 0
    # Loop over input message
    for i in range(len(msg)):
        # Increment character ord value
        out += chr(((ord(msg[i]) + c0) % 94) + 32)
        # Increment addition variable
        c0 += ord(msg[i])
    # Return
    return out

# Character set
chars = list(r'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_}!?.,')

# Trial flag and given mystery flag
flag = 'NETON{'
mystery = 'nUK<,IDt-.bvKL|./EO$%;k}@_'

i = 0 # iterator
while flag[-1] != '}':
    trial = encrypt(flag+chars[i])
    # Check if our encrypted trial flag matches the mystery one
    if trial == mystery[:len(flag)+1]:
        flag += chars[i]
        i = 0
    else:
        i += 1
    # If we run out of characters
    if i >= len(chars):
        print('Expand character list!')
        break
        
print('Gottem!:', flag)
```
Which neatly returns our desired flag
```
Gottem!: NETON{Y0u_4r3_0n_th3_t0p!}
```