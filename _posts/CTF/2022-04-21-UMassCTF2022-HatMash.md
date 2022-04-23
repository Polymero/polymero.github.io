---
title: UMassCTF 2022 - HatMash
category: CTF
tags: crypto hash linear-algebra
hidden_tags: my-challenge
excerpt_separator: <!--more-->
---

Cryptography -- 500 pts (1 solve) -- Chall author: Polymero (me)

_What do you mean "We think you spend too much time with matrices."? It's just a hash function, jeez..._

<!--more-->

nc 34.139.216.197 10003

Files: [hatmash.py](https://github.com/UMassCybersecurity/UMassCTF-2022-challenges/blob/main/crypto/hatmash/hatmash.py)

This challenge was part of my guest appearance on [UMassCTF 2022](https://ctftime.org/event/1561).

<br>

## Exploration

Let's start with connecting to the netcat address to see what we get.

```
KEY: e55d77086841d4738527bba5414cd9574fc46fa79e9066f9e5fc8e1d2622aec4e1213e529425f3b991f1427dc8debfd156377a966e29f60e068af36998dea766ac780d0b158ab3dae52b80ad5ab7d6f781e72303dd9034aab5ae5eadee232a66
TARGET: 7d67e732d77b8147cb95c135c7ad1c55121abc93038d5f5c8269cac8eecedc8b
```

A key and a target... Considering the description mentioned a hash function, I suspect we are required to find a collision within some (keyed) hash function. So let's take a look at the source code, where we will only consider any global parameters and the server's main loop for now. _I added some comments to help guide you through the code._

```py
# Server generates a pretty large key (768 bits)
KEY = os.urandom(32*3)
print('KEY:', KEY.hex())

# Server generates hash of hard-coded phrase as target
target_hash = mash(b"gib m3 flag plox?").hex()
print('TARGET:', target_hash)

# Alphabet range containing all printable ASCII characters
ALP = range(ord(' '), ord('~'))


try:
    
    # Server waits for user input and checks all of the input is in the alphabet
    user_msg = input().encode()
    assert all(i in ALP for i in list(user_msg))
    
    # Server checks whether user input contained the hard-coded phrase
    if b"gib m3 flag plox?" in user_msg:
        print('Uuh yeah nice try...')

    # Server checks whether user input equals the target hash
    elif mash(user_msg).hex() == target_hash:
        print('Wow, well I suppose you deserve it {}'.format(FLAG.decode()))

    else:
        print('Not quite, try again...')
    
except:
    print('Try to be serious okay...')
```

Okay, so we have to find a collision for the input `gib m3 flag plox?`. Now that we know _what_ to do, it is time to find out _how_ to do it. Time to check out this hash function.

```py
def mash(x):

	# Turns input bytes to a list of individual bits
    bits = list('{:0{n}b}'.format(int.from_bytes(x,'big'), n = 8*len(x)))

    # Pop the first bit and check parity
    if bits.pop(0) == '0':
        ret = A
    else:
        ret = B

    # Multiply the resulting matrix by A or B corresponding to the encountered bits
    for bit in bits:
        if bit == '0':
            ret = mod_mult(ret, A, 2)
        else:
            ret = mod_mult(ret, B, 2)

    # The length of 
    lenC = C
    for _ in range(len(x)):
        lenC = mod_mult(lenC, C, 2)

    # Return the matrix as bytes
    return mat_to_bytes(mod_add(ret, lenC, 2))
```

With some straightforward helper functions.

```py
def bytes_to_mat(x):
	# Converts a 32-byte string to 16x16 matrix mod 2
    assert len(x) == 32
    bits = list('{:0256b}'.format(int.from_bytes(x,'big')))
    return [[int(j) for j in bits[i:i+16]] for i in range(0,256,16)]

def mat_to_bytes(x):
	# Converts a 16x16 matrix mod 2 to a 32-byte string
    return int(''.join([str(i) for j in x for i in j]),2).to_bytes((len(x)*len(x[0])+7)//8,'big')

def mod_mult(a,b,m):
	# Multiplies matrices 'a' and 'b' modulo 'm'
    assert len(a[0]) == len(b)
    return [[sum([a[k][i] * b[i][j] for i in range(len(b))]) % m for j in range(len(a))] for k in range(len(a))]

def mod_add(a,b,m):
	# Adds matrices 'a' and 'b' modulo 'm'
    assert len(a[0]) == len(b[0]) and len(a) == len(b)
    return [[(a[i][j] + b[i][j]) % m for j in range(len(a[0]))] for i in range(len(a))]
```

$$ H : \left\{ 0,\ 1 \right\}^{8n} \rightarrow \left\{ A,\ B \right\}^{8n} + C^n $$

For instance, this hashing function would hash the input `hi`, '0110100001101001' in bits, as follows

$$ A B B A B A A A A B B A B A A B + C^2 = A B^2 A B A^4 B^2 A B A^2 B + C^2 \mod{2} $$

<br>

#### So why does this work as a hashing algorithm?

In general, matrix multiplication is not commutative, i.e. $A B \neq B A$. So a single change or shift in bits will result in a different matrix multiplication and hence a different hash. Even though there are of course exceptions to this, it does not occur frequently enough to worry about it. Besides, if we really want to, we can easily check for it.

So how could this possibly be flawed?

<br>

## Exploitation

First steps first, let's connect to the address and gather the used key matrices.

```py
from sage.all import *
from pwn import *

host = "34.139.216.197"
port = 10001

ALP = range(ord(' '), ord('~'))

while True:
	s = remote(host, port)

	s.recvuntil(b"KEY: ")
	KEY = bytes.fromhex(s.recvuntil(b"\n",drop=True).decode())
	print(KEY)

	A,B,C = [Matrix(GF(2), [[int(k) for k in list('{:016b}'.format(int.from_bytes(i[j:j+2],'big')))] for j in range(0,32,2)]) for i in (KEY[:32],KEY[32:64],KEY[-32:])]
```

It is important to note that the key matrices are generated just from random bytes. So, there is no check on whether or not the generated matrices are invertible or not. Invertible matrices are dangerous for this hash function as they form a group under multiplication known as the general linear group $GL_n(p)$, where $n$ is the dimension of the matrices and $p$ the (prime) size of the used integer ring for the matrix elements. The implication of the existence of this group is the existence of a multiplicative order $k$ for every element in the group. The multiplicative order $k$ of an invertible $n$x$n$ matrix $A$ modulo a prime $p$ is defined such that 

$$A^k \equiv I_{n} \mod{p},$$

where $I_{n}$ is the $n$x$n$ identity matrix.

With our knowledge of the key matrices we can check whether any of them are invertible such that we could theoretically inject said invertible matrix to the power of its multiplicative order. This will cause the input message to look differently, whereas the matrix multiplication will result in an identical hash (ignoring the $C^{len}$ for now). So theoretically, this hash algorithm is already broken, but can we actually exploit it?

Of course we can, but not as straight forward as we thought. First of all, we are limited to only adding characters part of the `ALP` global variable, each consisting of eight bits and thus a different multiplication of eight key matrices. Secondly, there is the third key matrix raised to the length of our input. In other words, we require all three key matrices to be invertible.

<br>

#### Is it feasible to require all three random key matrices to be invertible?

For a random $n$x$n$ matrix with elements on the integer ring of prime size $p$, it is quite trivial to see there are a total of

$$ \# \mathbb{Z}_{p}^{n\times n} = p^{n^2} $$

possibilities. However, not all of these will be invertible. For a matrix to be invertible, all its rows (or columns) must be linearly independent. So where the first row has $p^n - 1$ possible elements (zero row is not allowed), the next row cannot be a multiple of the first row and thus will only have $p^n - p$ possible elements. The next row will in turn only have $p^n - p^2$ possible elements as it cannot be a linear combination of the first two, etc. Hence, the order of a general linear group can be expressed as

$$ \# GL_n(p) = \prod_{k = 0}^{n - 1} (p^n - p^k). $$

Therefore, the chance of three random matrices of size 16 by 16 modulo 2 all being invertible can be found to be

$$ \left( \frac{\# GL_{16}(2)}{\# \mathbb{Z}_{2}^{16\times 16}} \right)^3 = (0.288\dots)^3 = 2.4\ \%. $$

This will take only 42 tries on average, so completely feasible.

```py
	try:
		A.multiplicative_order()
		B.multiplicative_order()
		C.multiplicative_order()
	except:
		print("\nNot all matrices are invertible...\n")
		s.close()
		continue
```

<br>

#### What can we inject?

We are allowed only byte characters defined in the `ALP` global variable. So we should check the multiplicative order of said characters. This is easily done by taking every character, turn it into a bit string, and multiply the key matrices to get the resulting character matrix (so to speak). Let's store our found multiplicative orders for now, as we will need them in the next step.

```py
def bit_to_mat(bitstr):
    ret = identity_matrix(GF(2),16)
    for i in list(bitstr):
        if i == '0':
            ret *= A
        else:
            ret *= B
    return ret
```
```py
	mult_ords = []
	for i in ALP:
	    try:
	        mult_ords += [(i,bit_to_mat('{:08b}'.format(i)).multiplicative_order())]
	    except:
	        continue
```

<br>

#### How do we circumvent the length element of the hash algorithm?

We require $C$ to also be invertible such that

$$ C^{l + a k_C} \equiv C^l \mod{2}\ \ \ \text{for some integer } a, $$

where $l$ is the byte length of the original input and $k_C$ the multiplicative order of $C$. So we can still create a collision as long as our injection contains a multiple of $k_C$ bytes. Remember all our character matrices are a multiplication of eight of the key matrices and therefore will generally have a much lower multiplicative order than $A$, $B$, or $C$, individually. Let's check if any of them divide the multiplicative order of $C$ such that our injection of $ k_C / k_{char}$ characters goes completely unnoticed. Note that it does not matter where we place our injection in the original payload, the results will be the same.

```py
	result = ([i for i in mult_ords if i[1] % C.multiplicative_order() == 0])
	
	if not result:
		print("\nNo luck...\n")

	if result:
		print(result)
		break

	s.close()

print(s.recv())
```

Now, instead of looking for a multiplicative order that divides the order of $C$ we could also just look for the least common multiple (LCM). Although this guarantees the existence of a collision as long as all three matrices are invertible, it has a tendency to create rather larger payloads. In a real world scenario, there might be payload size limits to keep in mind. On top of that, extremely large payloads may arise suspicion. Of course a vast number of created connections in quick succession can also cause suspicion, so it is really up to the situation which strategy might prove more useful.

Either way, time to get our well deserved flag.

```py
forgery = b"gib m3 flag" + result[0][1] * bytes([result[0][0]]) + b" plox?"
assert all(i in ALP for i in list(forgery))
assert b"gib m3 flag plox?" not in forgery
s.sendline(forgery)

print(s.recv())
```

Ta-da!
```
flag{m4tr1c3s_4r3_dumb_ch4ng3_my_m1nd}
```

<br>

#### Full Exploit Script

```py
#!/usr/bin/env python3
# 
# Polymero
#

from sage.all import *
from pwn import *

host = "34.139.216.197"
port = 10001


def bit_to_mat(bitstr):
    ret = identity_matrix(GF(2),16)
    for i in list(bitstr):
        if i == '0':
            ret *= A
        else:
            ret *= B
    return ret



while True:

	s = remote(host, port)

	ALP = range(ord('!'), ord('~'))

	s.recvuntil(b"KEY: ")
	KEY = bytes.fromhex(s.recvuntil(b"\n",drop=True).decode())
	print(KEY)

	A,B,C = [Matrix(GF(2), [[int(k) for k in list('{:016b}'.format(int.from_bytes(i[j:j+2],'big')))] for j in range(0,32,2)]) for i in (KEY[:32],KEY[32:64],KEY[-32:])]

	try:
		A.multiplicative_order()
		B.multiplicative_order()
		C.multiplicative_order()
	except:
		print("\nNot all matrices are invertible...\n")
		s.close()
		continue

	mult_ords = []
	for i in ALP:
	    try:
	        mult_ords += [(i,bit_to_mat('{:08b}'.format(i)).multiplicative_order())]
	    except:
	        continue

	result = ([i for i in mult_ords if i[1] % C.multiplicative_order() == 0])
	
	if not result:
		print("\nNo luck...\n")

	if result:
		print(result)
		break

	s.close()

print(s.recv())

forgery = b"gib m3 flag" + result[0][1] * bytes([result[0][0]]) + b" plox?"
assert all(i in ALP for i in list(forgery))
assert b"gib m3 flag plox?" not in forgery
s.sendline(forgery)

print(s.recv())

```