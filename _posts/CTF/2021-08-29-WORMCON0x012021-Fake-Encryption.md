---
title: WORMCON 0x01 2021 - Fake Encryption
category: CTF
tags: crypto DES
hidden_tags: write-up
excerpt_separator: <!--more-->
---

Cryptography -- 379 pts (12 solves) -- Chall author: BUILDYOURCTF

A PNG containing the flag is first encrypted with DES-ECB, then another copy is first shuffled in blocks of 8 bytes followed by the same encryption. We are given the encrypted flag PNG and both the raw and encrypted shuffled PNGs. Due to the nature of the ECB mode and the DES block size being 8 bytes, we are able to easily recover the original flag PNG.

<!--more-->

Check out write-ups by my teammates on [K3RN3L4RMY.com](http://k3rn3l4rmy.com/writeups)

## Exploration

![](/assets/ctf/Fake_Encryption_chall.png)

The flag in PNG format is encrypted using DES in ECB mode. More specifically, let's take a quick look at the source code.

```py
def splitn(text, size):
    return [text[i:i+size] for i in range(0,len(text),size)]

def encrypt(m, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(m)


flag = open('flag.png','rb').read()
ff = splitn(flag, 8)

assert len(flag) % 8 == 0, len(flag)

key = random.randbytes(8)
enc_flag = encrypt(flag, key)

random.seed(ff[0])
random.shuffle(ff)

ff = b''.join(ff)
enc_ff = encrypt(ff, key)
```

This code will take the flag PNG and encrypt it, but additionally it will also create an 8-byte block shuffled version of the PNG and encrypt that one as well. Note that it is shuffled in groups of 8 bytes, this is equivalent to the DES block size. This means that all blocks DES will encrypt are present in both the original and shuffled version, just in a different order. Why is this noteworthy? Well, because of the ECB mode. This mode take an 8-byte block and encrypts it with DES without doing anything else to either the plaintext or the ciphertext. This is incredibly dangerous, as encryption using the same key of two identical plain text blocks will result in identical cipher text blocks, something which is NOT the case with other block cipher modes. So let's see if we can abuse this.


## Exploitation

Like I mentioned before, the shuffled PNG is grouped in blocks of 8 bytes before shuffling and encryption, therefore it has the same 8-byte blocks as the original PNG, just in a different order. This means we can do the following: for every 8-byte block in the encrypted flag PNG we seek its position in the shuffled encrypted PNG and find its corresponding plain text in the shuffled non-encrypted PNG. Having done that for all 8-byte blocks in the encrypted flag PNG, we have succesfully recovered the original flag PNG. Not convinced? Give it a try!

```py
with open('C:/Users/Nika/Downloads/fake encryption/ff_error.png.enc','rb') as f:
    enc_ff = f.read()
    f.close()
    
with open('C:/Users/Nika/Downloads/fake encryption/ff_error.png', 'rb') as f:
    ptt_ff = f.read()
    f.close()
    
with open('C:/Users/Nika/Downloads/fake encryption/flag.png.enc', 'rb') as f:
    ENCFLAG = f.read()
    f.close()

enc_ff_8 = [enc_ff[i:i+8] for i in range(0,len(enc_ff),8)]
ptt_ff_8 = [ptt_ff[i:i+8] for i in range(0,len(ptt_ff),8)]
ENCFLAG8 = [ENCFLAG[i:i+8] for i in range(0,len(ENCFLAG),8)]

assert all([i in ENCFLAG8 for i in enc_ff_8])

DECFLAG8 = []
for block in ENCFLAG8:
    DECFLAG8 += [ptt_ff_8[enc_ff_8.index(block)]]
    
with open('C:/Users/Nika/Downloads/fake encryption/flag.png','wb') as f:
    f.write(b''.join(DECFLAG8))
    f.close()
```

Ta-da!
```
wormcon{ECB_lacks_diffiusion}
```
