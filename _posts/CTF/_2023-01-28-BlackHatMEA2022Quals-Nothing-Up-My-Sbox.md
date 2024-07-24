---
title: BlackHat MEA 2022 Qualifiers - Nothing Up My S-box
category: CTF
tags: crypto SPN
hidden_tags: my-challenge
excerpt_separator: <!--more-->
---

**Cryptography -- ? solves (? points) -- Chall author: Polymero (me)**

_"You should always be wary of people rolling their own crypto. Even if their work is secure, they might have planted a backdoor into it! To assure you my new block cipher is without backdoor, you get to create your own s-box. Exciting, right?"_

<!--more-->

Files: [nothingupmysbox.py]()

<br>

I wrote this challenge for [BlackHat MEA 2022 Qualifiers](https://ctftime.org/event/1733) as part of the [CTF.ae](https://www.ctf.ae/) team.

## Exploration

Upon connection to the netcat address we are greeted by the following ::

```
|
|  ~ In order to prove that I have nothing up my sleeve, I let you decide on the sbox!
|    I am so confident, I will even stake my flag on it ::
|    flag = 45a4271b569f5090284c70386ed35d68eabea3523e
|
|  ~ Now, player, what should I call you?
|
|  > Polymero
|
|  ~ Well Polymero, here are your s- and p-box ::
|    s-box = [7, 11, 14, 5, 6, 2, 13, 10, 4, 15, 3, 8, 0, 1, 9, 12]
|    p-box = [2, 7, 8, 14, 11, 1, 9, 15, 13, 12, 4, 6, 0, 5, 3, 10]
|
|  ~ Menu ::
|    [E]ncrypt
|    [Q]uit
|
|  > e
|
|  > (hex) 00
|
|  ~ aea936aed3ca97b9
|
|  ~ Menu ::
|    [E]ncrypt
|    [Q]uit
|
|  >
```

We get to pick our username after which the server presents us with a (custom?) substitution and permutation box. The server then lets us encrypt whatever and however many messages we want. So let's see what's happening under the hood, starting with code that is ran first ::

```py
KEY = [randbelow(16) for _ in range(16)]

OTP = b""
while len(OTP) < len(FLAG):
    OTP += sha256(b" :: ".join([b"OTP", str(KEY).encode(), len(OTP).to_bytes(2, 'big')])).digest()
    
encflag = bytes([i ^ j for i,j in zip(FLAG, OTP)]).hex()

print("|\n|  ~ In order to prove that I have nothing up my sleeve, I let you decide on the sbox!")
print("|    I am so confident, I will even stake my flag on it ::")
print("|    flag = {}".format(encflag))

print("|\n|  ~ Now, player, what should I call you?")
seed = input("|\n|  > ")

oracle = NUMSBOX(seed, KEY)

print("|\n|  ~ Well {}, here are your s- and p-box ::".format(seed))
print("|    s-box = {}".format(oracle.sbox))
print("|    p-box = {}".format(oracle.pbox))
```

The master key is generated as a random array of 16 4-bit integers, making a total keyspace of $16^{16}$ possible keys, equivalent to 8 bytes. No practical brute-forcing here. The actual flag of the challenge is encrypted by an one-time-pad (OTP) created from the master key, so we will have to recover it in order to retrieve the flag. In other words, we already know we are dealing with a key recovery challenge. Finally, we see that our username is used as some sort of seed for the cryptographic oracle. Let's continue with the main server loop ::

```py
MENU = """|
|  ~ Menu ::
|    [E]ncrypt
|    [Q]uit
|"""

while True:

    try:

        print(MENU)
        choice = input("|  > ")

        if choice.lower() == 'e':
            msg = [int(i, 16) for i in input("|\n|  > (hex) ")]
            print("|\n|  ~ {}".format(oracle.encrypt(msg)))

        elif choice.lower() == 'q':
            print("|\n|  ~ Sweeping the boxes back up my sleeve...\n|")
            break

        else:
            print("|\n|  ~ Sorry I do not know what you mean...")

    except KeyboardInterrupt:
        print("\n|  ~ Sweeping the boxes back up my sleeve...\n|")
        break

    except:
        print("|\n|  ~ Hey, be nice to my code, okay?")
```

Nothing noteworthy here, this matches the behaviour we saw when we connected to the netcat address. Time to check out that oracle code ::

```py
class NUMSBOX:
    def __init__(self, seed, key):
        self.sbox = self.gen_box('SBOX :: ' + seed)
        self.pbox = self.gen_box(str(time.time()))
        self.key = key

    def gen_box(self, seed):
        box = []
        i = 0
        while len(box) < 16:
            i += 1
            h = sha256(seed.encode() + i.to_bytes(2, 'big')).hexdigest()
            for j in h:
                b = int(j, 16)
                if b not in box:
                    box += [b]
        return box
    
    def subs(self, x):
        return [self.sbox[i] for i in x]
    
    def perm(self, x):
        return [x[i] for i in self.pbox]
    
    def kxor(self, x, k):
        return [i ^ j for i,j in zip(x, k)]
    
    def encrypt(self, msg):
        if len(msg) % 16:
            msg += (16 - (len(msg) % 16)) * [16 - (len(msg) % 16)]
        blocks = [msg[i:i+16] for i in range(0, len(msg), 16)]
        cip = []
        for b in blocks:
            x = self.kxor(b, self.key)
            for _ in range(4):
                x = self.subs(x)
                x = self.perm(x)
                x = self.kxor(x, self.key)
            cip += x
        return ''.join([hex(i)[2:] for i in cip])
```

Here is where all the cryptographic magic happens. We can see that our username, the seed, is used to deterministically generate a substitution box, while the permutation box is seeded with the current time. These boxes, together with the structure of the encryption function strongly points us in the direction of substitution-permutation-network based block ciphers (SPNs). If you are unfamiliar with this kind of construction, here is a little basic overview for you.


### Basics :: Substitution Permutation Network (SPN)

...

<div style="margin: 0px 0px -2.25em -2em; font-size: 2em; font-weight: bold; color: #43d8d1;"> Q :: </div>
<h3 style="color: #43d8d1;"><i> "So how does it work exactly?" </i></h3>

In order to take a closer look at the inner workings of a single round, let's consider a 16-element dummy state $s$,

$$ s = [1,\ 1,\ 2,\ 3,\ 5,\ 8,\ 13,\ 5,\ 2,\ 7,\ 9,\ 0,\ 9,\ 9,\ 2,\ 11], $$

and a 16-element round key

$$ k_r = [2,\ 3,\ 5,\ 7,\ 11,\ 13,\ 4,\ 8,\ 9,\ 6,\ 12,\ 10,\ 15,\ 14,\ 0,\ 1]. $$

Most commonly, a single round will consist of the following three operations:
<ol>
    <li> <b style="font-size: 1.2em;">Substitution</b> transforms the plaintext in a non-linear way by substituting plaintext elements of a given size with other elements through the use of a substitution box. For example, if we take
    
    $$ S_{box} = \left[ 5,\ 1,\ 12,\ 7,\ 0,\ 9,\ 10,\ 15,\ 3,\ 4,\ 2,\ 8,\ 13,\ 6,\ 11,\ 14 \right] $$
    
    then the substitution operation on our dummy state $s$ will yield
    
    $$ S(s) = \left[ 1,\ 1,\ 12,\ 7,\ 9,\ 3,\ 6,\ 9,\ 12,\ 15,\ 4,\ 5,\ 4,\ 4,\ 12,\ 8 \right]. $$ 
</li>
    <li> <b style="font-size: 1.2em;">Permutation</b> transforms the plaintext in a linear way, most commonly by rearranging the order of the plaintext elements of a given size through the use of a permutation box. For example, if we take

    $$ P_{box} = \left[ 5,\ 1,\ 12,\ 7,\ 0,\ 9,\ 10,\ 15,\ 3,\ 4,\ 2,\ 8,\ 13,\ 6,\ 11,\ 14 \right] $$

    then the permutation operation on our previous result will yield

    $$ P(S(s)) = \left[ 3,\ 1,\ 4,\ 9,\ 1,\ 15,\ 4,\ 8,\ 7,\ 9,\ 12,\ 12,\ 4,\ 6,\ 5,\ 12 \right]. $$
</li>
    <li> <b style="font-size: 1.2em;">Key mixing</b> ... 

    $$ s_k = s \oplus k_i $$

    such that, after one round, we end up with the final state of

    $$ s_{i+1} = P(S(s_i)) \oplus k_i = \left[ 1,\ 2,\ 1,\ 14,\ 10,\ 2,\ 0,\ 0,\ 14,\ 15,\ 0,\ 6,\ 11,\ 8,\ 5,\ 13 \right] . $$
</li>
</ol>


<div style="margin: 0px 0px -2.25em -2em; font-size: 2em; font-weight: bold; color: #43d8d1;"> Q :: </div>
<h3 style="color: #43d8d1;"><i> "So why is this secure?" </i></h3>

Over the course of multiple rounds the combination of the above operations provides the SPN cipher with two important security properties, confusion and diffusion. 


<ol>
    <li> <b style="font-size: 1.2em;">Confusion</b> refers to the complexity of the relationship between plaintext and ciphertext, more specifically its non-linearity. Good confusion makes it unfeasible for an adversary to recover the key through solving a system of equations between the plaintext and ciphertext. </li>
    <li> <b style="font-size: 1.2em;">Diffusion</b> refers to the presence of a so-called avalanche effect over multiple rounds. Good diffusion makes it so that a single change in the plaintext will result in changes all over the ciphertext. </li>
</ol>



<br>

To summarise, we have made the following observations ::
<table style="border: none; margin-left: 20px; margin-top: -.5em">
    <tr>
        <td style="background-color: #43d8d1; border: none; max-width: 5px;"> </td>
        <td style="border: none; padding-left: 20px; min-width: 25px; vertical-align: top;"> <b>1.</b> </td>
        <td style="border: none; padding-left: 0px;"> ... </td>
    </tr>
    <tr>
        <td style="background-color: #43d8d1; border: none; max-width: 5px;"> </td>
        <td style="border: none; padding-left: 20px; min-width: 25px; vertical-align: top;"> <b>2.</b> </td>
        <td style="border: none; padding-left: 0px;"> ... </td>
    </tr>
    <tr>
        <td style="background-color: #43d8d1; border: none; max-width: 5px;"> </td>
        <td style="border: none; padding-left: 20px; min-width: 25px; vertical-align: top;"> <b>3.</b> </td>
        <td style="border: none; padding-left: 0px;"> ... </td>
    </tr>
    <tr>
        <td style="background-color: #43d8d1; border: none; max-width: 5px;"> </td>
        <td style="border: none; padding-left: 20px; min-width: 25px; vertical-align: top;"> <b>4.</b> </td>
        <td style="border: none; padding-left: 0px;"> ... </td>
    </tr>
</table>



<br>

## Exploitation

### Path 1 :: Linear Cryptanalysis (Poor Confusion)

...

#### Naive Approach :: Partially Linear w/ Fixed Points

...

```py
# Imports
from hashlib import sha256
import os

def gen_box(seed):
    seed = 'SBOX :: ' + seed
    box = []
    i = 0
    while len(box) < 16:
        i += 1
        h = sha256(seed.encode() + i.to_bytes(2, 'big')).hexdigest()
        for j in h:
            b = int(j, 16)
            if b not in box:
                box += [b]
    return box

calls = 0
while True:
    calls += 1
    
    seed = os.urandom(32).hex()
    sbox = gen_box(seed)
    
    nfix = sum(i == j for i,j in enumerate(sbox))
    if nfix >= 10:
        print(nfix, seed, sbox, calls)
        break

# '101780904466fe3e93f9205c51d2064bb9061298226d81235b35fe7769195500' # 10 works ~300
# '633d01903be0b275f39a3eddf24fd042fb3a2e145ba4a41f4ec3a735b1454301' #  9 works >1000
```

...

```py
# Imports
from sage.all import *
from pwn import *
from hashlib import sha256

# Connection
host = '0.0.0.0'
port = '5000'

# context.log_level = 'debug'


# OFFLINE PARAMETER
seed_fix_10 = '101780904466fe3e93f9205c51d2064bb9061298226d81235b35fe7769195500'


# Functions
def oracle_encrypt(s, x):
	''' Use the connection to the oracle 's' to return the encryption of 'x'. '''
	s.sendline(b"e")
	s.recv()
	s.sendline(''.join([hex(i)[2:] for i in x]).encode())
	s.recvuntil(b'~ ')
	y = [int(i,16) for i in s.recvuntil(b"\n", drop=True).decode()]
	s.recv()
	return y

def ret_max_count(x: list) -> list:
	''' Return only the most occuring elements of 'x'. '''
    uniq = list(set(x))
    cnts = [sum(int(i == j) for j in x) for i in uniq]
    mx = max(cnts)
    return [uniq[i] for i in range(len(uniq)) if cnts[i] == mx]


# Script
REC = 1
while REC:

	# Connect
	s = connect(host, port)

	print(REC, end='\r', flush=True)
	REC += 1

	# Get encrypted flag
	s.recvuntil(b"flag = ")
	encflag = bytes.fromhex(s.recvuntil(b"\n", drop=True).decode())

	# Send our seed
	s.recv()
	s.sendline(seed_fix_10.encode())

	# Get s-box
	s.recvuntil(b"s-box = ")
	sbox = eval(s.recvuntil(b"\n", drop=True).decode())
	assert sum(i == j for i,j in enumerate(sbox)) == 10

	# Get p-box
	s.recvuntil(b"p-box = ")
	pbox = eval(s.recvuntil(b"\n", drop=True).decode())

	cip_lst = []
	key_mat = []

	for ji in range(16):

		# Get permutations
		js = [ji]
		for _ in range(4):
			js += [pbox.index(js[-1])]

		# Build permutated key matrix
		key_mat += [[1 if j in js else 0 for j in range(16)]]

		# Get most occuring ciphertext elements
		cip_lst += [ret_max_count([oracle_encrypt(s, [0]*ji + [k] + [0]*(16-ji-1))[js[-1]] ^ k for k in range(16)])]

	# Convert key matrix from 4-bit to single bit
	bit_mat = []
	for row in key_mat:
		for i in range(4):
			bit_mat += [[]]
			for j in row:
				bit_mat[-1] += [0]*i + [j] + [0]*(3 - i)

	# Make sure it is solvable
	if Matrix(GF(2), bit_mat).rank() == 64:

		for _ in range(100):

			# Convert randomly sampled ciphertext from 4-bit to single bit
			cip_vec = [sample(i, 1)[0] for i in cip_lst]
			bit_vec = [m for n in [[int(i) for i in '{:04b}'.format(j)] for j in cip_vec] for m in n]

			# Solve 'Ax = y' for 'x'
			key_vec = Matrix(GF(2), bit_mat).solve_right(Matrix(GF(2), bit_vec).T)
			key_lst = key_vec.list()
			key_rec = [int(''.join(str(j) for j in key_lst[i:i+4]), 2) for i in range(0, len(key_lst), 4)]

			# Derive OTP key from recovered key vector
			otp = b""
			while len(otp) < len(encflag):
				otp += sha256(b" :: ".join([b"OTP", str(key_rec).encode(), len(otp).to_bytes(2, 'big')])).digest()

			# Recover the flag
			rec_flag = bytes([i ^ j for i,j in zip(encflag, otp)])

			if b"flag" in rec_flag:
				print(REC, rec_flag)
				REC = 0
				break

	s.close()
```

...


#### Cryptanalysis Approach :: Fully Linear S-box

Remember that we can represent a fully linear s-box operation as

$$ S(x) = A x + b \mod{2}, $$

where $A$ is an invertible $4$x$4$-bit matrix and $b$ a $4$-bit vector. We could just keep generating s-boxes until we get lucky and get a fully linear one.

<div style="margin: 0px 0px -2.25em -2em; font-size: 2em; font-weight: bold; color: #43d8d1;"> Q :: </div>
<h3 style="color: #43d8d1;"><i> "But how likely is it for a random s-box to be fully linear?" </i></h3>

We know that the s-boxes are generated as a random permutation of the integers 0 up to 16. For a group of 16 unique elements, the total amount of possible permutations is $16! = 20922789888000$, roughly 21 trillion or just over 44-bits. The total number of fully linear s-boxes is determined by the number of combinations of an invertible $4$x$4$ binary matrix and a 4-bit vector. The number of possible 4-bit vectors is simply $2^4$. The group of all invertible $4$x$4$ binary matrices is known as the general linear group of size 4 modulo 2, or $GL(4,\ 2)$ for short, and its order can be found using

$$ \# GL\left(n,\ q\right) = \prod_{k=0}^{n-1} \left( q^n - q^k \right). $$

For our s-box we have #$GL(4,\ 2) = 20160$, making a total amount of $322560$ combinations of $A$ and $b$ and thus fully linear s-boxes. This directly implies that the possibility of randomly generating a fully linear s-box is about

$$ P_{\mathrm{linear}} = \frac{322560}{16!} \approx 1.542 \cdot 10^{-08}. $$

This seems very low, but it represents a search space of "only" 26 bits, or just over 3 bytes. Considering the process of generating a s-box is relatively fast, it seems pretty feasible to search offline for a seed that generates a fully linear s-box. Before we get started however, there is one more thing we need to figure out.

<div style="margin: 0px 0px -2.25em -2em; font-size: 2em; font-weight: bold; color: #43d8d1;"> Q :: </div>
<h3 style="color: #43d8d1;"><i> "How can I easily find out if my s-box is fully linear?" </i></h3>

Instead of naively trying to find a corresponding $A$ and $b$ for our s-box to see whether or not it is fully linear, we can come up with the following little trick. Let's consider two 4-bit inputs $x$ and $y$ and a fully linear s-box $S(x)$ such that we have

$$ S(x) = Ax + b $$

and 

$$ S(y) = Ay + b. $$

Note that the $+$-operation here is equivalent to the $\oplus$-operation (XOR) as we are working modulo 2. Adding the above together we get

$$ S(x) + S(y) = Ax + Ay = A (x + y). $$

Using the knowledge that $S(0) = b$ we can turn this into

$$ S(x) + S(y) + S(0) = A (x + y) + b = S(x + y), $$

which gives

$$ S(x) + S(y) + S(x + y) + S(0) = 0. $$

The above relation holds for all combinations of $x$ and $y$ IF AND ONLY IF the s-box $S(x)$ can be represented by $A$ and $b$, and thus is fully linear. We can easily and quickly check this using two nested iterations, without the need to construct $A$ and $b$ explicitly. 

Here is an example script that searches offline for a seed that generates a fully linear s-box using the strategy we derived above ::

```py
# Imports
from hashlib import sha256
import os, time

def gen_box(seed):
    box = []
    i = 0
    while len(box) < 16:
        i += 1
        h = sha256(('SBOX :: ' + seed).encode() + i.to_bytes(2, 'big')).hexdigest()
        for j in h:
            b = int(j, 16)
            if b not in box:
                box += [b]
    return box

def test_lin(box):
    b = box[0]
    lin = True
    for x in range(16):
        for y in range(16):
            if box[x] ^ box[y] != box[x ^ y] ^ b:
                lin = False
        if not lin:
            return None
    return b


t0 = time.time()
print('|\n|  ~ Starting search...\n|')

k = 0
while True:
    k += 1

    if not (k & 0xfff):
        t1 = time.time()
        ps = k / (t1 - t0)
        ts = int((65e6 - k) / ps)
        print('|  ~ {} ({:.1f}K /s) (approx. {}m {}s left)    '.format(k, int(ps) / 1000, ts // 60, ts % 60), end='\r', flush=True)

    seed = os.urandom(8).hex()
    sbox = gen_box(seed)

    if test_lin(sbox):
        break


td = int(time.time() - t0)
print('|  ~ Found a fully linear sbox ::                 ')
print('|    seed  = {}'.format(seed))
print('|    sbox  = {}'.format(sbox))
print('|    time  = {}m {}s'.format(td // 60, td % 60))
print('|    tries = {}'.format(k))
print('|')
```
```
|
|  ~ Starting search...
|
|  ~ Found a fully linear sbox ::
|    seed  = 8f06c6020e15039c
|    sbox  = [10, 8, 2, 0, 13, 15, 5, 7, 3, 1, 11, 9, 4, 6, 12, 14]
|    time  = 12m 36s
|    tries = 21926891
|
```

...


<br>

To summarise, our first exploit consists of the following steps ::
<table style="border: none; margin-left: 20px; margin-top: -.5em">
    <tr>
        <td style="background-color: #43d8d1; border: none; max-width: 5px;"> </td>
        <td style="border: none; padding-left: 20px; min-width: 25px; vertical-align: top;"> <b>1.</b> </td>
        <td style="border: none; padding-left: 0px;"> ... </td>
    </tr>
    <tr>
        <td style="background-color: #43d8d1; border: none; max-width: 5px;"> </td>
        <td style="border: none; padding-left: 20px; min-width: 25px; vertical-align: top;"> <b>2.</b> </td>
        <td style="border: none; padding-left: 0px;"> ... </td>
    </tr>
    <tr>
        <td style="background-color: #43d8d1; border: none; max-width: 5px;"> </td>
        <td style="border: none; padding-left: 20px; min-width: 25px; vertical-align: top;"> <b>3.</b> </td>
        <td style="border: none; padding-left: 0px;"> ... </td>
    </tr>
    <tr>
        <td style="background-color: #43d8d1; border: none; max-width: 5px;"> </td>
        <td style="border: none; padding-left: 20px; min-width: 25px; vertical-align: top;"> <b>4.</b> </td>
        <td style="border: none; padding-left: 0px;"> ... </td>
    </tr>
</table>



### Path 2 :: Divide-and-Conquer (Poor Diffusion)

...

![](/assets/ctf/spn_perm.png)

...

```py
# Imports
from pwn import *
from secrets import randbelow
from hashlib import sha256
import os, time

# Globals
SEQ_LIMIT = 6


#+-------------------------+
#|   CLASSES & FUNCTIONS   |
#+-------------------------+
# Connection class
class ORACLE:
    def __init__(self, s):
        self.s = s
        
    @staticmethod
    def remote(host, port, debug=False):
        if debug:
            context.log_level = 'debug'
        return ORACLE(connect(host, port))
        
    @staticmethod
    def local(file, proc='python3'):
        return ORACLE(process([proc, file]))
        
    def parse(self, seed):
        # Get flag
        self.s.recvuntil(b"flag = ")
        self.flag = bytes.fromhex(self.s.recvuntil(b"\n", drop=True).decode())
        # Send seed
        self.s.recv()
        self.s.sendline(seed.encode())
        # Get sbox
        self.s.recvuntil(b"s-box = ")
        self.sbox = eval(self.s.recvuntil(b"\n", drop=True).decode())
        # Get pbox
        self.s.recvuntil(b"p-box = ")
        self.pbox = eval(self.s.recvuntil(b"\n", drop=True).decode())
        
    def encrypt(self, pt):
        self.s.sendline(b"e")
        self.s.recv()
        self.s.sendline(''.join([hex(i)[2:] for i in pt]).encode())
        self.s.recvuntil(b"~ ")
        ct = [int(i, 16) for i in self.s.recvuntil(b"\n", drop=True).decode()]
        self.s.recv()
        return ct

    def exit(self):
        self.s.close()


# Functions
def pbox_seqs(pbox):
    ''' Returns max sequence size and list of sequences for a given pbox. '''
    j = []
    for j_start in range(16):
        j += [[j_start]]
        while True:
            k = pbox.index(j[-1][-1])
            if k == j_start:
                break
            j[-1] += [k]
    return max(len(i) for i in j), j


#-------------+
#|   ATTACK   |
#-------------+
print('+----------------------------------------+')
print('|   SOLVE SCRIPT :: Nothing Up My Sbox   |')
print('+----------------------------------------+')
print('|\n|  ~ Looking for a sufficiently weak pbox ::')

CONNS = 0
while True:
    CONNS += 1

    # Use 'remote' or 'local' method
    oracle = ORACLE.local('nothingupmysbox.py')
    
    # Give whatever seed
    oracle.parse('Polymero')

    # Check sequences
    max_s, SEQS = pbox_seqs(oracle.pbox)
    if max_s < SEQ_LIMIT:
        break

    print('|    Attempt {} yielded max sequence of {}'.format(CONNS, max_s))

    oracle.exit()

print('|\n|  ~ Divide-and-Conquer attack on ORACLE with ::')
print('|    sbox = {}'.format(oracle.sbox))
print('|    pbox = {}'.format(oracle.pbox))

# Cipher parameters
BLOCK_SIZE = 64 
ELEM_SIZE  = 4 
ELEM_NUM   = BLOCK_SIZE // ELEM_SIZE
ELEM_MOD   = 2 ** ELEM_SIZE
NUM_ROUNDS = 4

# Find all unique sequences
UNIQS = []
res = list(range(ELEM_MOD))
for i in SEQS:
    if i[0] in res:
        UNIQS += [i]
        for j in i:
            res.remove(j)

REC_KEY = [0] * ELEM_NUM
POS_KEY = [[] for _ in UNIQS]

print('|\n|  ~ Found unique sequences ::')
for i in UNIQS:
    print('|    {}'.format(i))

# Divide-and-Conquer
T0    = time.time()
CALLS = 0
while not all(len(i) == 1 for i in POS_KEY):
    CALLS += 1
    
    # Get plaintext ciphertext pair
    plaintext  = [randbelow(ELEM_MOD) for _ in range(ELEM_NUM)]
    ciphertext = oracle.encrypt(plaintext)
    
    print('|\n|  ~ ({}s) Encryption call {} ::'.format(int(time.time() - T0), CALLS))
    print('|    pt = {}'.format(plaintext))
    print('|    ct = {}'.format(ciphertext))
    print('|')
    
    for n,seq in enumerate(UNIQS):
        
        if len(POS_KEY[n]) == 1:
            continue
            
        print('|    {} ->'.format(seq), end='\r', flush=True)
    
        start  = [plaintext[i] for i in seq]
        target = [ciphertext[i] for i in seq]
        
        found_keys = []
        for int_key in range(ELEM_MOD ** len(seq)):
            
            key = []
            while len(key) < len(seq):
                key = [int_key % ELEM_MOD] + key
                int_key //= ELEM_MOD
                
            x = start[:]
            for k in range(NUM_ROUNDS + 1):
                if not k:
                    x = [i ^ j for i,j in zip(x, key)]
                else:
                    x = [oracle.sbox[i] for i in x]
                    x = [x[-1]] + x[:-1]
                    x = [i ^ j for i,j in zip(x, key)]
                    
            if x == target:
                found_keys += [key]
                
        if not POS_KEY[n]:
            POS_KEY[n] = found_keys
        else:
            POS_KEY[n] = [i for i in found_keys if i in POS_KEY[n]]
            
        print('|    {} -> {}'.format(seq, POS_KEY[n]))
        
key_inds = [i for j in UNIQS for i in j]
key_vals = [i for j in POS_KEY for i in j[0]]
for k in range(ELEM_NUM):
    REC_KEY[key_inds[k]] = key_vals[k]
            
print('|\n|  ~ ({}s) Done in {} encryption calls::'.format(int(time.time() - T0), CALLS))
print('|    KEY = {}'.format(REC_KEY))

# Derive OTP key from recovered key vector
otp = b""
while len(otp) < len(oracle.flag):
    otp += sha256(b" :: ".join([b"OTP", str(REC_KEY).encode(), len(otp).to_bytes(2, 'big')])).digest()

# Recover the flag
FLAG = bytes([i ^ j for i,j in zip(oracle.flag, otp)])

print('|\n|  ~ Hey look at this, it looks like I found the flag ::')
print('|    {}'.format(FLAG))
print('|\n|')
```


<br>

To summarise, our second exploit consists of the following steps ::
<table style="border: none; margin-left: 20px; margin-top: -.5em">
    <tr>
        <td style="background-color: #43d8d1; border: none; max-width: 5px;"> </td>
        <td style="border: none; padding-left: 20px; min-width: 25px; vertical-align: top;"> <b>1.</b> </td>
        <td style="border: none; padding-left: 0px;"> ... </td>
    </tr>
    <tr>
        <td style="background-color: #43d8d1; border: none; max-width: 5px;"> </td>
        <td style="border: none; padding-left: 20px; min-width: 25px; vertical-align: top;"> <b>2.</b> </td>
        <td style="border: none; padding-left: 0px;"> ... </td>
    </tr>
    <tr>
        <td style="background-color: #43d8d1; border: none; max-width: 5px;"> </td>
        <td style="border: none; padding-left: 20px; min-width: 25px; vertical-align: top;"> <b>3.</b> </td>
        <td style="border: none; padding-left: 0px;"> ... </td>
    </tr>
    <tr>
        <td style="background-color: #43d8d1; border: none; max-width: 5px;"> </td>
        <td style="border: none; padding-left: 20px; min-width: 25px; vertical-align: top;"> <b>4.</b> </td>
        <td style="border: none; padding-left: 0px;"> ... </td>
    </tr>
</table>