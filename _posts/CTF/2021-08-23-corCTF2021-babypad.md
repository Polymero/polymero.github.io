---
title: corCTF 2021 - babypad
category: CTF
tags: crypto POA AES-CTR
hidden-tags: write-up
excerpt_separator: <!--more-->
---

Cryptography -- 484 pts (35 solves) -- Chall author: willwam845

A clean AES-CTR Padding Oracle Attack challenge, no hurdles, no bs. We can send cipher texts to the server and it will tell us whether or not it succeeded to unpad the decrypted cipher text. This allows us to straight up use the server as a padding oracle to decrypt the encrypted flag.

<!--more-->

Check out write-ups by my teammates on [K3RN3L4RMY.com](http://k3rn3l4rmy.com/writeups)

## Exploration

![](/assets/ctf/babypad_chall.png)

The server we are allowed to connect to can do only a single thing for us, attempt decryption and unpadding of a given ciphertext. The server will only reveal whether or not there was an error during this process. This just reeks of a padding oracle attack. Let's take a closer look at the server's decrypt function.

```py
def decrypt(ct):
    try:
        iv = ct[:16]
        ct = ct[16:]
        ctr = Counter.new(128, initial_value=bytes_to_long(iv))
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        pt = cipher.decrypt(ct)
        unpad(pt, 16)
        return 1
    except Exception as e:
        return 0
```

## Exploitation

The server uses AES in CTR mode, which behaves as a stream cipher and therefore is malleable. This means the padding oracle attack becomes quite simple as we can simply alter a single byte to affect the corresponding plaintext byte. I do not plan to go into a detailed description too much here, but here is the gist of the attack.

1. Start at the back of an 16-byte block and XOR the ciphertext byte with some byte (iterate form 0 up to 255), until the server returns successfull unpadding.
2. Because the padding is valid, this means the plaintext last byte must be '0x01' (see PKCS padding). This allows us to deduce the original plaintext byte from the valid altered ciphertext byte as follows.
$$ \mathrm{pt\_byte} = \mathrm{altered\_byte} \oplus \mathrm{padding\_byte} \oplus \mathrm{original\_ct\_byte} $$
3. Continue with the second-to-last byte and try to set the last two bytes to valid padding, so '0x02'.
4. Continue this process for the entire 16-byte block and repeat for each 16-byte block, except for the IV as we do not need to recover that.

There are some nuances I have not touched upon, but they are included in the commented script below.

```py
#!/usr/bin/env python3
#
# Polymero
#

def AES_CTR_POA(ENC, padding_oracle):
	""" Perform AES-CTR Padding Oracle Attack on given ciphertext and oracle function. """

	# Initliase decryption string
    DEC = b''

    # For every 16-byte block
    while len(ENC) > 16:

        BLOCK = b''

        # For every byte in the block
        for l in range(1,16+1):

        	# Padding value
            padbyt = l

          	# Collect all valid bytes
            valid_byts = []

            for k in range(256):

            	# Alter a single byte of ciphertext 
                fuzz = ENC[:-l] + bytes([k]) + bytes([ENC[len(ENC)-(l-1):][i] ^ BLOCK[i] ^ padbyt for i in range(len(BLOCK))])

                assert len(fuzz) == len(ENC)

                # Pass to the oracle and recvieve unpadding success {0,1}
                derr = padding_oracle(fuzz)

                # If valid, the decrypted byte must be the padding value
                if derr:
                    valid_byts += [k]

            # Multiple hits, take the new one
            if len(valid_byts) > 1:
                if ENC[-l] in valid_byts:
                    valid_byts.remove(ENC[-l])

            # Still multiple hits, error
            if len(valid_byts) != 1:
                print(valid_byts,l)
                return 'ERROR'

            # Recover plaintext byte and prepend to BLOCK
            pt_byt = valid_byts[0] ^ padbyt ^ ENC[-l]
            BLOCK = bytes([pt_byt]) + BLOCK
            print(BLOCK+DEC)

        # Prepend BLOCK to DEC string
        DEC = BLOCK + DEC

        # Remove block from ciphertext
        ENC = ENC[:-16]

    # Return
    return DEC


# Imports
from pwn import *

# Remote connection
host = "babypad.be.ax"
port = 1337
s = remote(host,port)

# Retrieve the encrypted flag
ENCFLAG = bytes.fromhex(s.recvuntil(b'\n',drop=True).decode())

s.recv()

def request_decrypt(ciphertext):
	""" Return unpad success of given ciphertext. """
    s.sendline(ciphertext.hex().encode())
    if s.recvuntil(b'\n',drop=True) == b'1':
        s.recv()
        return 1
    else:
        s.recv()
        return 0 

# FLAG!
print(AES_CTR_POA(ENCFLAG, request_decrypt))
```

Ta-da!
```
corctf{CTR_p4dd1ng?n0_n33d!}
```
