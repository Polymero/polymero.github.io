---
title: ImaginaryCTF 2021 - ZKPoD
category: CTF
tags: Write-up Parity Leak RSA LSB-oracle
excerpt_separator: <!--more-->
---

Crypto -- 400 pts (16 solves) -- Chall author: Robin_Jadoul

Sending a cipher text to the server returns a flawed 'Zero Knowledge Proof of Decryption'. This ZKPoD protocol however leaks the parity of the decrypted cipher text, allowing us to abuse the server as a LSB oracle. Using a rather straightforward attack we can recover the decrypted flag in O(2*2log(n)) (~4096) server calls. Lucky for us, plumbers are typically slow to arrive ;).

<!--more-->

Check out write-ups by my teammates on [K3RN3L4RMY.com](http://k3rn3l4rmy.com/writeups)

## Exploration

![](/assets/ctf/ZKPoD_chall.png)

Upon first contact with the server, we are greeted with the encrypted flag. The server then allows us to send it cipher texts upon which it will proof to us its ability to decrypt it. It does so using a so-called Zero Knowledge Proof of Decryption and returns a signature of the decrypted cipher text. Ideally, as its name would suggest, a zero knowledge proof should give us zero knowledge about the decrypted cipher text. Turns out, this might be harder than it sounds. Let's take a look at the server code that generates the '(r,s)' signature from the decrypted cipher text 'x'.

```py
def sign(x):
    """ Returns a signatrue of the decrypted cipher text. """
    k = getRandomRange(0, P - 1)                              # Random integer in {0...P-1}
    r = pow(g, k, P)                                          # First signature value
    e = H(str(r).encode() + b"Haha, arbitrary message")       # Hash value of 'r'
    s = (k - x * e) % (P - 1)                                 # Second signature value
    return r, s
```

Mmh,this seems awfully similar to more common signature protocols, albeit with some interesting differences:
- In s, the random value 'k' is not inverted modulo 'p'.
- In s, the hash value 'e' depends on 'r' instead of the actual message.
- In s, there is no secret parameter present.
- In s, the modulo used has even parity ('p-1' is even).

Specifically the last point is exciting, as an even modulus conserves parity, i.e. an even number mod 'p-1' stays even and an odd number mod 'p-1' stays odd. This might seem innocent, but as 'x' is the integer value of the decrypted message we can turn the server into a LSB oracle if and only if we can manage to find the parity of 'x'.

### LSD Oracle?

No, no, _LSB_ oracle... I'm sure the OG oracle used some LSD from time to time, but we're talking Least Significant Bit oracles. Might sound less exciting, but I assure you, far more dangerous. Tangents aside, how does knowing something as seemingly small as the parity of the message lead to adversaries, like us >:), being able to decrypt any given cipher text?

In most scenarios, the homomorphic properties of encyrption systems add flexibility to their possible implementations. However, combined with a parity leak, it allows us to decrypt any known cipher text. Our server encrypts (and decrypts) with RSA which has the following homomorphism (all mod 'n'):
```py
c1 * c2 = m1**e * m2**e = (m1 * m2)**e
```
which will decrypt to
```py
(c1 * c2)**d = ((m1 * m2)**e)**d = m1 * m2
```
This allows us to perform the following trick:
We multiply the cipher text we want to decrypt with '2**e' such that its decryption doubles (all mod 'n'):
```py
(2**e * C)**d = ((2 * M)**e)**d = 2M
```
Now we know the parity of 2M should be even, regardless of the original parity of M. However, there is an ODD modulus in play! This means that by leaking the parity of '(2M) mod n' we can derive whether or not the modulus was subtracted from '2M'. Or in other words, whether 'M' is smaller or larger than 'n/2'! Not convinced, check out this graphic.

```img(ZKPoD_graphic.png)

So to summarise, what are the needed conditions for a LSB oracle attack?
- Homomorphic property in the used encryption protocol.
- Odd modulus such that the parity of a decrypted ciphertext changes if 'new_m > n'.
- Parity leak of the decrypted cipher text.

With that out of the way, let's set up our exploit.

## Exploitation

Let's first take a closer leak at this potential parity leak. To be able to recover the parity of 'x' we need to find the parities of all other elements involved. This means we will have to find the parity of 's', 'k', 'e', and 'p-1'. We know 'p-1' and are given 's' by the server, so the parity of those two is trivial. The abnormality of 'e' depending on the hash of 'r' instead of the decrypted cipher text plays hugely in our favour here, as this allows us to compute 'e' from the server response, and hence its parity.

There are two caveats we need to take care of however. Firstly, 'x' is multiplied by 'e', which following the rules of parity multiplication
```
par(e)     par(x)
 even   *   even   = even
 even   *   odd    = even
 odd    *   even   = even
 odd    *   odd    = odd
```
means that we need 'e' to be odd in order to be able to retrieve the parity of 'x' correctly. We will need an extra check in our exploit to make sure we try again with the same cipher text if we find that 'e' is even. Secondly, determining the parity of 'k' is slightly less trivial. To find its parity we need to apply some theory on quadratic residues on 'r = 2**k mod p'. A number 'a mod p' is called a quadratic residue of 'p' if and only if there exists a number 'b'  such that 'b**2 mod p = a'. If the modulus is prime, we can easily recognise quadratic residues by computing the legendre symbol of 'a'. This symbol will either be 1 if 'a' is a quadratic residue, -1 if it is not, or 0 if it is a multiple of 'p'. Okay that is nice and all, but how does this help us? Well, if 'k' turns out to be even then we can write
```py
r = 2**k % p = 2**(2*l) % p = (2**l)**2 % p
```
and we see that 'r' will be a quadratic residue! Whereas, if 'k' is odd then
```py
r = 2**k % p = 2**(2*l+1) % p = 2 * (2**l)**2 % p
```
which makes 'r' a non-quadratic residue. Therefore we can use the legendre symbol of 'r' to determine the parity of 'k'. Now we can find the parity of 'x' as
```py
if (e % 2 == 1):
	x_parity = (k % 2) ^ (s % 2)
else:
	try again
```

We can turn this parity leak into an exploit by using a lower and upper bound for our decrypted cipher text and iteratively multiply our cipher text with '2**e mod p'. This will allow us to adjust our bounds until they converge on the plain text value of our original cipher text. Every iteration will divide our plain text range by 2 starting from '(0, n)', therefore we will need about '2log(n)' (~2048) server calls. However, we should remember that we needed 'e' to be odd in order to not spoil the parity of 'x'! As 'e' will be odd only half of the time (there is no parity bias in the computation of 'e'), so we will likely actually need about '2*2log(n)' (~4096) server calls... I hope they don't mind the spam :).

Here is the commented Python script I used.

```py
#!/usr/bin/env python3
#
# Polymero
#

# Imports
from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
import hashlib

# Parameters
N = 0xbb00128c1c1555dc8fc1cd09b3bb2c3efeaae016fcb336491bd022f83a10a501175c044843dbec0290c5f75d9a93710246361e4822331348e9bf40fc6810d5fc7315f37eb8f06fb3f0c0e9f63c2c207c29f367dc45eef2e5962eff35634b7a29d913a59cd0918fa395571d3901f8abd83322bd17b60fd0180358b7e36271adcfc1f9105b41da6950a17dba536a2b600f2dc35e88c4a9dd208ad85340de4d3c6025d1bd6e03e9449f83afa28b9ff814bd5662018be9170b2205f38cf3b67ba5909c81267daa711fcdb8c7844bbc943506e33f5f72f603119526072efbc5ceae785f2af634e6c7d2dd0d51d6cfd34a3bc2b15a752918d4090d2ca253df4ef47b8b
e = 0x10001
P = 0x199e1926f2d2d5967b1d230b33de0a249f958e5b962f8b82ca042970180fe1505607fe4c8cde04bc6d53aec53b4aa25255ae67051d6ed9b602b1b19e128835b20227db7ee19cf88660a50459108750f8b96c71847e4f38a79772a089aa46666404fd671ca17ea36ee9f401b4083f9ca76f5217588c6a15baba7eb4a0934e2026937812c96e2a5853c0e5a65231f3eb9fdc283e4177a97143fe1a3764dc87fd6d681f51f49f6eed5ab7ddc2a1da7206f77b8c7922c5f4a5cfa916b743ceeda943bc73d821d2f12354828817ff73bcd5800ed201c5ac66fa82df931c5bbc76e03e48720742ffe673b7786e40f243d7a0816c71eb641e5d58531242f7f5cfef60e5b
g = 2

def H(x):
    """ Returns domain separated 1024 hash as integer. """
    return bytes_to_long(hashlib.sha512(b"domain" + x).digest() + hashlib.sha512(b"separation" + x).digest())

def jacobi(a, n):
    """ Returns Legendre Symbol (special case of Jacobi Symbol with prime n) of a mod n."""
    assert(n > a > 0 and n%2 == 1)
    t = 1
    while a != 0:
        while a % 2 == 0:
            a //= 2
            r = n % 8
            if r == 3 or r == 5:
                t = -t
        a, n = n, a
        if a % 4 == n % 4 == 3:
            t = -t
        a %= n
    if n == 1:
        return t
    else:
        return 0

def get_parity(r,s):
    """ Returns the parity of the decrypted message (if e is odd). """
    e = H(str(r).encode() + b"Haha, arbitrary message")
    if jacobi(r,P) == 1:
        k_parity = 0
    else:
        k_parity = 1
    s_parity = s % 2
    e_parity = e % 2
    if e_parity:
        return True, (s_parity ^ k_parity)
    else:
        return False, 0

host = "chal.imaginaryctf.org"
port = 42012

C = None

callcount = 0
while True:

    try:

        # We require multiple connections as we are only given a livetime of ~100 s.
        s = remote(host,port)

        # Receive the flag
        s.recvuntil('flag: ')
        ENCFLAG = int(s.recvuntil('\n',drop=True).decode(),16)
        s.recv()

        # Set starting parameters
        if C is None:
            LB, UB, C = [0, N, ( pow(2,e,N) * ENCFLAG ) % N]

        while True:

            # Send cipher text
            s.sendline(long_to_bytes(C).hex())

            # Receive (r,s)
            s.recvuntil('r: ')
            R = int(s.recvuntil('\n',drop=True).decode())
            s.recvuntil('s: ')
            S = int(s.recvuntil('\n',drop=True).decode())

            callcount += 1

            s.recv()

            # Check if we got a valid parity (e is odd)
            if not get_parity(R,S)[0]:
                continue

            # Get message parity
            m_parity = get_parity(R,S)[1]

            # If odd, update lower bound
            if m_parity:

                LB = (UB + LB) // 2

            # If even, update upper bound
            else:

                UB = (UB + LB) // 2

            # Update cipher text
            C = (pow(2,e,N) * C) % N

            # Print to check progress
            print(LB, UB, C)

            # Have our bounds converged?
            if LB == UB:
                raise KeyboardInterrupt

    # It is I that shall determine whether you get to live!
    except KeyboardInterrupt:
        break

    # If the server connection breaks, make a new one
    except:
        continue

print('A stunning total of {} server calls! #annoyingcustomer'.format(callcount))

if LB == UB:
    print('Sir?!, it seems the enemy has raised their flag!', long_to_bytes(LB))
```

In the end it took 4031 server calls, as was expected.

Thanks to Robin for creating this fun challenge! My eye immediately fell on the parity conservation and I was able to quickly follow up with an exploit to secure first blood!

Ta-da!
```
ictf{gr0up5_should_b3_pr1me_0rd3r_dummy}
```
