---
title: K3RN3LCTF 2021 - Total Encryption
category: CTF
tags: crypto RSA Franklin-Reiter Coppersmith
hidden_tags: my-challenge
excerpt_separator: <!--more-->
---

Cryptography -- 500 pts (0 solves) -- Chall author: Polymero (me)

_"To store our most embarrassing secrets, we created a Remote Secure Armoury protected by layered RSA encryption with XOR blinding. Never again will my friends be able to mock me for my use of words!"_

<!--more-->

nc ctf.k3rn3l4rmy.com 2244

Files: [ltet.py](https://github.com/Kasimir123/K3RN3LCTF-2021/blob/main/server-files/total-encryption/ltet.py)

Hidden Files: [server.py](https://github.com/Kasimir123/K3RN3LCTF-2021/blob/main/server-files/total-encryption/server.py)

This challenge was part of our very first CTF, [K3RN3LCTF 2021](https://ctftime.org/event/1438).


## Exploration

Once we connect to the netcat address we are greeted with the following messages.

```
|
|    ______   _____________________  _________________     ________  _     _
|   (_____ \ / ___________________ \(_________________)   (_______ \| |   | |
|    _____) | (____  _______ _____) )_  _  _ _     _ _     _ _____) ) |___| |
|   |  __  / \____ \|  ___  |  __  /| ||_|| | |   | | |   | |  __  /\_____  |
|   | |  \ \______) ) |   | | |  \ \| |   | | |___| | |___| | |  \ \______| |
|   |_|   \________/|_|   |_|_|   |_|_|   |_|\_____/ \_____/|_|   \_________|
|   + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ver.1 +
|   |                                                                       |
|   |           Connected to the Remote Secure Armoury. (0.54 s)            |
|   |                                                                       |
|   + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
|
|                             SECURITY UPDATE LOG
|
|     - VER. 1 - All contents of the RSArmoury have now been secured
|                with layered RSA encryption + XOR blinding, LTET(1024).
|
|
|     PUBLIC KEYS:
|     AQAB.Ardcguwme9E
|     BQ.0kCWQHp5T1nweX6TIQvUp7o6_ph2_lmDJXo1FG-l3be15ZGZ2Az5kYzHJYYtxHOIIyExwhVGU_3de1r54WkQRTr1kQ7iEXaXd42zmfDCrkX2qniKXe8GVvaIGF3yqutM11HqS1_8emQyIrDTryPt2zE1PtIH9aJiYLRiTHnayTs
|     fw.JbTxppK7oH93___EYwdzejcenjoODAit1SHW6Vm4-9iR4iQo7Y1DbraIhtwV08vLMWq4NRyMbNrwAE17h_KWcrj0Wl9elq8aYZ_yQe3rGnR-cHQuBGNaHmdBzaHGHcABX02YBdzpn8vP8hHzvNg_SIksx0CcOut5Pg9KMfZroR4CndE0HadGxibquxTLT4I66TJ1XD8dablrqxT8m1Helwyg77qqbbb5Fr-9U_A-SmqrUvjQlvhCIw
|
|
|   C1A8TFK6KK_cUaE.HiLL6LUlZmAsystOaLdPhUE6B_f3Qf8XSDekqXIfif22pif9LaGdtHbBJ3XOL8mc47UG5sFsAkrvSYMS8fRncwEh9a1PuCUqmz4nqh-SXEp8DYBMO3M0XZ2dsr7x0EPvFY08oCu9sUm1BLjA55A85l016a-9IinFXP0OApcFxSdoWYY4rVCjVV2jw7COFn-d-JMxJ9B4H9qStIOCbJGQTKFmiYPy6OZI7pDAmKO5gSZQ2962TzA2ig
|   DvAUP2ZEC2GwO6Y.BbD_cZzNrHkXN6S8xjpVv5sQrpJTY4uu9MKJHncXOs-taG704zN7rXVgM0-ezIk5MO-UjBfjBJJeh1AA9VR1ZeVDON1d0ccpYZbW5Ta3SdAWOkCvXOV0ijPeUwWADl0JWmOlVpuc08BJHYqg8J9RpRXOaz3aKcRhImdsfbNZcvYhzQTPxlsuAUdmAOgJTBlDxgI6aGTUFNqLRYISgBe4Go0FwoWsYEyxmUjNs_oLl-aQWmrm3BYnyw
|   CLyUDxGcxKSqgGY.I0qj-drvR6F3hHPuYQYzlDyLWitA_iloSZmfFCV01-r7jruWtzRMD9fFe3DONo1i6CEerhZwO2OhjFmfLKK3ovpdGAUwTblm9cPKfHc7gPD3T5Vuw5kJDOxQ8Wb2WiemveNtMoz_8cfQ1I6l2CREG6Ahxy2dzYfaPYkbAMjs_oox7wteifhCIQ7vBQsPZ_W0UEKyRGIlOqHe7_ku_p0JNSHiEiGOZ7kOpR8rt787t_VYPfBf9rKUjQ
|   CMGnWBaLKgJBxF0.GTIrI9KlPETXVyhHGG2UDZk4kYjsnIPdDr4uJLgDC03MdL50AOeJJ1SaE7GqNdavf30xG1jYvZt8iYb2mTxtfs_RUVxu6TivSjEZMNGLFZw60cxYzrcp2ybK2HL4Crg1o3DlhnSaBX-c4Z44A4iOa9nkNrRLz8-zTli5fWtgm-ax9vf5Fyeyr-w6TO5biQdzbTpJcQijMfAfjH9bBq-AfM2I2PtpiKFMEgRyPWr-DYHOfIl_1DdWiw
|
|
|  >>>
```

Three public keys? Some seemingly encrypted menu? And 'layered RSA encryption + XOR blinding', called LTET(1024)? I have never heard of that? Let's check out the RSA public keys real quick.

```py
pubkey_1 = {'e': 65537, 'nbit': 58, 'n': 195726826191354833}

pubkey_2 = {'e': 5, 'nbit': 1024, 'n': 147644180901082431168100755763554209140656121867352800930388594244396103618687665207495245297961709320402901550367810523324658918735482375563565444213406852148814309689694185359009235747549600651556682274722870284313750781375949649763784991789624132099041080448664730169011034436480887454107506927945601698107}

pubkey_3 = {'e': 127, 'nbit': 1470, 'n': 19245689335632446943762710195965658569430278438134217413263502921095274121678529390885316775906032947432051029798982324888526187325540039122096616131667142134701120897318593592934282056722729236708120776116667510638358541869631050311417708558092657167130040781658501061177345127748428272527278709216890098330854887219590276165180740630918902624682116819167776194862822329141878096956774085562315641976952391602707594555560645211968197019320867}
```

The first key is a joke, the modulus is way too small. The other two keys have a much more reasonable modulus bit length, but seem to have a worryingly small public exponent. There definitely seems to be some lacklustre crypto going on here that we might be able to exploit. But first let's dive into the source code a bit.

```py
#!/usr/bin/env python3
#
# Polymero
#

# Imports
import os, time, base64
from Crypto.Util.number import getPrime, inverse, GCD, long_to_bytes

# Shorthand
def b64enc(x):
    return base64.urlsafe_b64encode(long_to_bytes(x)).rstrip(b'=')

class LTET:
    """ Layered Totally Encrypted Terminal. """
    def __init__(self, max_bit_length):
        self.maxlen = max_bit_length
        
        # Set bit lengths
        self.bitlen = {
            'inner block' : self.maxlen,
            'inner clock' : (7 * self.maxlen) // 125
        }
        self.bitlen['outer block'] = 16 + (4 * (self.bitlen['inner block'] + self.bitlen['inner clock'] + 9)) // 3
        self.bitlen['outer blind'] = 8 + (4 * self.bitlen['inner clock']) // 3
        
        # Key generation
        self.public  = { 'n' : [], 'e' : [65537, 5, 127]}
        self.private = { 'p' : [], 'q' : [], 'd' : []}
        for i in range(3):
            nbit = [self.bitlen[j] for j in ['inner clock', 'inner block', 'outer block']][i]
            while True:
                p, q = [getPrime((nbit + 1) // 2) for _ in range(2)]
                if GCD(self.public['e'][i], (p-1)*(q-1)) == 1:
                    d = inverse(self.public['e'][i], (p-1)*(q-1))
                    break
            self.private['p'] += [p]
            self.private['q'] += [q]
            self.private['d'] += [d]
            self.public['n']  += [p * q]
            
    def encrypt(self, msg):
        assert len(msg) * 8 <= self.maxlen
        clock = pow(int(time.time()), self.public['e'][0], self.public['n'][0])
        block = b64enc(pow(int.from_bytes(msg, 'big') ^ int(clock), self.public['e'][1], self.public['n'][1]))
        blind = int.from_bytes(os.urandom((self.bitlen['outer blind'] + 7) // 8), 'big') >> (8 - (self.bitlen['outer blind'] % 8))
        block = pow(int.from_bytes(block + b'.' + b64enc(clock) ,'big') ^ blind, self.public['e'][2], self.public['n'][2])
        return (b64enc(blind) + b'.' + b64enc(block)).decode()
```

We are only provided the source code for the used 'LTET' encryption, not for the server running on the netcat address. Its key generation, although a bit convoluted, seems to be secure enough. What is going in that `encrypt()` function? Clock, block, blind, and block again... err okay. Let's follow the encryption step by step. We start with a RSA encryption of the current UNIX time (in seconds) using the first public key.

$$ C = E_{K1}\left( t_{UNIX} \right) $$

In the second step, we take our plaintext message and XOR it with the encrypted timestamp, after which it is encrypted with a second RSA key and encoded in the urlsafe base 64 variant.

$$ C = E_{K_2}\left( m \oplus E_{K_1}\left( t_\mathrm{UNIX} \right) \right)_{64} $$

The used timestamp is then appended to the above with a '.' (0x46) as delimter, XORed with a new blind `B`, and finally encrypted one more time with the third public key. This blind is then prepended. Such that the final encryption looks as follows.

$$ C = B_{64}\ ||\ 46\ ||\ E_{K_3}\left( B \oplus \left[ E_{K_2}\left( m \oplus E_{K_1}\left( t_\mathrm{UNIX} \right ) \right )_{64}\ ||\ 46\ ||\ E_{K_1}\left( t_\mathrm{UNIX} \right )_{64} \right] \right )_{64} $$

Or perhaps in a notation slightly easier on the eyes, B || '.' || 3{ B ^ 2{ M ^ 1{ T }1 }2 || '.' || 1{ T }1 }3.

Right... I understand what they meant with layered encryption now. In order to crack this we should consider one layer at a time. Considering what we know about the underlying layers, and the public key parameters, are there any well-known RSA attacks we might be able to apply?


## Exploitation

Turns out we can peel off each layer using a simple well-known RSA attack. So let's get us started with the very first layer!

### First Layer - Franklin-Reiter Related Message Attack

Taking a look at the outer layer it consists of the used XOR blind concatenated with the outer layer ciphertext. This ciphertext is encrypted with a public exponent of 127, which is not _very_ small but not really large either. Since the blind is smaller than the outer layer plaintext, it can be seen as some kind of random padding. However the Coppersmith short-pad attack is only feasible if the padding is about

$$ \lfloor \frac{n}{e^2} \rfloor $$

bits, with $n$ representing the modulus bit length. For the outer layer we have $e=127$ and $n=1470$ such that the padding can be at most 0 bits, so this is a lost fight. However, the padding is not truly random, in fact, **it is known**! Being given just the XOR blind would not allow us to reconstruct a linear difference between two separate messages. However, if we log the time at which we receive the encryptions we also know the underlying plaintext as the timestamp is encrypted using a public key and appended to the inner ciphertext. Noting that the length of the blind is equal or smaller than the length of the timestamp (plus the added '.') means that we can subtract two separate ciphertexts as follows. _We assume both ciphertexts are gathered with the same timestamp._

$$ C_{\mathrm{outer},1} = B_1 \oplus \left( C_\mathrm{inner}\ ||\ 46\ ||\ E_{K_1}\left( t_\mathrm{UNIX} \right ) \right) $$

$$ C_{\mathrm{outer},2} = B_2 \oplus \left( C_\mathrm{inner}\ ||\ 46\ ||\ E_{K_1}\left( t_\mathrm{UNIX} \right ) \right) $$

$$ C_{\mathrm{outer},1} - C_{\mathrm{outer},2} = (46\ ||\ E_{K_1}\left( t_\mathrm{UNIX} \right )) \oplus B_1 - (46\ ||\ E_{K_1}\left( t_\mathrm{UNIX} \right )) \oplus B_2 $$

Having found a linear relation between the two underlying plaintexts, we can recover them using the Franklin-Reiter related message attack. Now onto the second layer!

### Second Layer - Coppersmith Short-Pad Attack

Again, we have to deal with the XOR blinding. This time we cannot set up a linear relationship between two of the plaintexts as we have no clue about the underlying message. However, for the inner layer we only have a public exponent of $e=5$ and $n=1024$, such that we can recover random padding up to 40 bits, theoretically. Of course in practice (and within CTF time), this limit is a couple of bits lower. Luckily for us, this is enough for us to mount a simple Coppersmith short-pad attack on the inner layer.

_In short, we are able to recover a single unique message by collecting at least four different encryptions of it._

Below you can find an example implementation of this attack on a local `ltet = LTET()` class. Note that the attack does not require any knowledge on the structure or contents of the encrypted message itself.

```py
#!/usr/bin/env sage
#
# Polymero
#

def PolyGCD(g1, g2):
    """ Straightforward GCD function for polynomials. """
    return g1.monic() if g2 == 0 else PolyGCD(g2, g1 % g2)

def FranklinReiter(C1, C2, DIF, e, n):
    """ Simple Franklin-Reiter related message attack to recover the plaintext from two encrypted messages with KNOWN linear difference. """
    P.<x> = PolynomialRing(Zmod(n))
    g1,g2 = [x**e - C1, (x + DIF)**e - C2]
    return -PolyGCD(g1, g2).coefficients()[0]

FLAG = b'flag{this is an example flag but what do I put here}'
bitlimit = 36

L2_IVS = []
L2_CIP = []

T0 = time.time()

while True:
    
    time.sleep(1)
    print('len(IVS) = {}'.format(len(L2_IVS)), end='\r', flush=True)

    CIPS = []
    IVS  = []
    PTS  = []

    try:
        
        # Gather two LTET encryptions of the same unique message
        for _ in range(2):

            stamp = b'.' + b64enc(pow(int(time.time()), ltet.public['e'][0], ltet.public['n'][0]))
            iv, cip = [i for i in ltet.encrypt(FLAG).split(b'.')]

            CIPS += [(stamp, int.from_bytes(base64.urlsafe_b64decode(cip+b'==='),'big'))]
            IVS  += [int.from_bytes(base64.urlsafe_b64decode(iv+b'==='),'big')]

            bytiv = base64.urlsafe_b64decode(iv+b'===')
            PTS  += [int.from_bytes(bytes([stamp[-len(bytiv):][i] ^^ bytiv[i] for i in range(len(bytiv))]), 'big')]

        # Make sure they containt the same timestamp (otherwise we cannot set up a correct linear relation)
        assert CIPS[0][0] == CIPS[1][0]
    
    except: continue

    # Commence Franklin-Reiter related message attack
    C1, C2 = [i[1] for i in CIPS]
    DIF = PTS[1] - PTS[0]

    rec_1 = FranklinReiter(C1, C2, DIF, ltet.public['e'][2], ltet.public['n'][2])

    if rec_1 == ltet.public['n'][2] - 1: continue

    else:

        # Recover inner layer
        recovered_layer = [int.from_bytes(base64.urlsafe_b64decode(i+b'==='),'big') for i in long_to_bytes(int(rec_1) ^^ int(IVS[0])).split(b'.')]
        
        # Do we have small enough padding to be able to apply a short-pad attack?
        reslst = [(i>>bitlimit) == (recovered_layer[1]>>bitlimit) for i in L2_IVS]

        if any(reslst):

            # If found, break
            iv1 = recovered_layer[1]
            iv2 = L2_IVS[reslst.index(True)]
            c1  = recovered_layer[0]
            c2  = L2_CIP[reslst.index(True)]
            break

        else:

            # Else, keep going
            L2_CIP += [recovered_layer[0]]
            L2_IVS += [recovered_layer[1]]
    
# Set up for Coppersmith short-pad attack        
N = ltet.public['n'][1]
G.<x,y> = PolynomialRing(Zmod(N))

# Ciphertext polynomials
g1 = x^ltet.public['e'][1] - c1
g2 = (x + y)^ltet.public['e'][1] - c2

# Sage needs univariate polynomial rings, sigh...
F.<y> = PolynomialRing(Zmod(N))
g1 = g1.change_ring(F)
g2 = g2.change_ring(F)

f = g1.resultant(g2, x)
f = f.univariate_polynomial().change_ring(Zmod(N))

ivbits = ltet.bitlen['inner clock']
print('\niv1 = {:0{x}b}'.format(iv1, x=ivbits))
print('iv2 = {:0{x}b}'.format(iv2, x=ivbits))

print('\nTrying to find a root...', end='\r', flush=True)

try:

    # Try to find a root below the set bitlimit (acts as time constraint)
    root = f.small_roots(epsilon=1/200, X=2**bitlimit)[0]
    print('Found min root :', min(root, -root % N))

except:

    print('Nope :C' + ' '*32)
    
T1 = time.time()

print('It took me {} seconds :)'.format(int(T1-T0)))

# Print original message!
print(long_to_bytes( int(FranklinReiter(c1,c2,min(root, -root % N)),ltet.public['e'][1],N)) ^^ iv1 )
```

The menu would decrypt to the following options.

```
|
|   [R]ecite our glorious motto
|   [E]ncrypt custom message
|   [P]rint our secret flag
|   [Q]uit
|
```

Ta-da!

```
flag{pr3tty_sur3_bl1nd1ng_p4tt3rns_4r3_n0t_supp0s3d_t0_gr4nt_Xr4y_v1s10n_:pikaoh:}
```

-----
Thanks for reading! <3

~ Polymero
