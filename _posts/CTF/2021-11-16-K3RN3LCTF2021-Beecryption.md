---
title: K3RN3LCTF 2021 - Beecryption
category: CTF
tags: crypto affine algebraic-attack
hidden_tags: my-challenge
excerpt_separator: <!--more-->
---

Cryptography -- 500 pts (2 solves) -- Chall author: Polymero (me)

_I was watching the bees and it seemed as if they were trying to tell me something... Have I finally gone crazy?!?_

<!--more-->

**Encrypted Flag:**
```
b8961e85e54e357cf1bb18550e9d397cb6e522e386a837a970c71e02a353eddb9117713e60aa8f764e4525f86898e379fce195437ec59202a5b715334b3295b9f9c9280b2de048183f1a9581860b852167102c1c4ec2897b59e360b5ba37d90b60f23b2ad47c04782a6be3bf
```

Files: [beecryption.py](https://github.com/Kasimir123/K3RN3LCTF-2021/blob/main/downloadable/Beecryption/beecryption.py), [subround.png](https://github.com/Kasimir123/K3RN3LCTF-2021/blob/main/downloadable/Beecryption/subround.png)

This challenge was part of our very first CTF, [K3RN3LCTF 2021](https://ctftime.org/event/1438).


## Exploration

Talking bees? Yeah this chall author has gone absolutely mad for sure. Well, let us take a look at what he cooked up for us _and yes I am talking about myself here..._

```py
class BeeHive:
    """ Surrounding their beehive, the bees can feast on six flower fields with six flowers each. """
    def __init__(self, key):
        """ Initialise the bee colony. """
        self.fields = self.plant_flowers(key)
        self.nectar = None
        self.collect()
        
    def plant_flowers(self, key):
        """ Plant flowers around the beehive. """
        try:
            if type(key) != bytes:
                key = bytes.fromhex(key)
            return [FlowerField(key[i:i+6]) for i in range(0,36,6)]
        except:
            raise ValueError('Invalid Key!')
    
    def collect(self):
        """ Collect nectar from the closest flowers. """
        A,B,C,D,E,F = [i.flowers for i in self.fields]
        self.nectar = [A[2]^B[4],B[3]^C[5],C[4]^D[0],D[5]^E[1],E[0]^F[2],F[1]^A[3]]

    ...


class FlowerField:
    """ A nice field perfectly suited for a total of six flowers. """
    def __init__(self, flowers):
        """ Initialise the flower field. """
        self.flowers = [i for i in flowers]

    def rotate(self):
        """ Crop-rotation is important! """
        self.flowers = [self.flowers[-1]] + self.flowers[:-1]
```

The FlowerField class will contain a total of 6 flowers and has a `rotate()` method that will simply permutate this array by one to the right. The BeeHive class will initialise 6 FlowerFields for a total of 36 key bytes. The `nectar` attribute can be updated using the `collect()` method, which takes a specific 12 bytes from the full state and XORs them into 6 bytes which will be set to the `nectar` attribute. Let continue our journey by taking a look at the actual encryption functionality.

```py
class BeeHive:

    ...

    def stream(self, n=1):
        """ Produce the honey... I mean keystream! """
        buf = []
        # Go through n rounds
        for i in range(n):
            # Go through 6 sub-rounds
            for field in self.fields:
                field.rotate()
                self.cross_breed()
                self.collect()
                self.pollinate()
            # Collect nectar
            self.collect()
            buf += self.nectar
        return buf
    
    def encrypt(self, msg):
        """ Beecrypt your message! """
        beeline = self.stream(n = (len(msg) + 5) // 6)
        cip = bytes([beeline[i] ^ msg[i] for i in range(len(msg))])
        return cip
```

Seems like a standard stream cipher set-up, where the keystream is generated 6 bytes at a time (using the `collect()` method) after having gone through 6 sub-rounds. To help visualise these sub-rounds we are also given an image that shows the elements of a single round, FlowerField rotation, byte-swapping, and internal XORing.

![](/assets/ctf/subround.png)

We have seen that the FlowerField `rotate()` method just permutates its 6-byte state by one. Let us take a look at the `cross_breed()` and `pollinate()` methods.

```py
class BeeHive:

    ...

    def cross_breed(self):
        """ Cross-breed the outermost bordering flowers. """
        def swap_petals(F1, F2, i1, i2):
            """ Swap the petals of two flowers. """
            F1.flowers[i1], F2.flowers[i2] = F2.flowers[i2], F1.flowers[i1]
        A,B,C,D,E,F = self.fields
        swap_petals(A,B,1,5)
        swap_petals(B,C,2,0)
        swap_petals(C,D,3,1)
        swap_petals(D,E,4,2)
        swap_petals(E,F,5,3)
        swap_petals(F,A,0,4)
        
    def pollinate(self):
        """ Have the bees pollinate their flower fields (in order). """
        bees = [i for i in self.nectar]
        A,B,C,D,E,F = self.fields
        for i in range(6):
            bees = [[A,B,C,D,E,F][i].flowers[k] ^ bees[k] for k in range(6)]
            self.fields[i].flowers = bees
```

Turns out the `cross_breed()` method indeed swaps a specific set of bytes within the internal 36-byte state. The `pollinate()` method takes the 6-byte 'nectar' output and XORs it with the FlowerFields one by one, changing itself as well.

Finally, we get a bit of known plaintext before the encrypted flag.

```py
some_text = b'Bees make honey, but they also made the Bee Movie... flag{_REDACTED_}'
flag = BeeHive(os.urandom(36).hex()).encrypt(some_text).hex()
```

This all seems complicated, how do we even go about attacking this?..


## Exploitation

The important point here to note is that all transformations in this cipher are linear in GF(2), i.e. transpositions and XORs only. Therefore all elements of the cipher can be represented by matrix operations. By converting the given cipher code into matrix operations on a state vector one can recover the initial state (=key) after a certain number of outputs. 

_There are more compact/faster ways of solving this (using symbolic math f.i.), but tackling the cipher elements algebraically one-by-one provides more insight into algebraic attacks._

```py
# SAGE

# Just for easier visual debugging :)
def bitstate_to_bytes(state):
    return bytes([int(''.join(str(i) for i in state.column(0))[j:j+8],2) for j in range(0,state.dimensions()[0],8)])


# TIME TO BUILD OUR MATRICES!

# FlowerField.rotate() matrices
I_48x48 = Matrix(GF(2), [[0]*i + [1] + [0]*(48-i-1) for i in range(48)])
R_48x48 = Matrix(GF(2), list(I_48x48)[-8:] + list(I_48x48)[:-8])
ROT_MATs = [block_diagonal_matrix(*([I_48x48]*i + [R_48x48] + [I_48x48]*(6-i-1)), subdivide=False) for i in range(6)]

# BeeHive.cross-breed() matrix
SWAP_MAT = identity_matrix(GF(2), 288)
for k in [((0*6+1)*8,(1*6+5)*8), ((1*6+2)*8,(2*6+0)*8), ((2*6+3)*8,(3*6+1)*8),
          ((3*6+4)*8,(4*6+2)*8), ((4*6+5)*8,(5*6+3)*8), ((5*6+0)*8,(0*6+4)*8)]:
    i,j = k
    for n in range(8):
        SWAP_MAT.swap_rows(i+n, j+n)

# BeeHive.collect() output matrix
GROW_MAT = []
for k in [((0*6+2)*8,(1*6+4)*8), ((1*6+3)*8,(2*6+5)*8), ((2*6+4)*8,(3*6+0)*8),
          ((3*6+5)*8,(4*6+1)*8), ((4*6+0)*8,(5*6+2)*8), ((5*6+1)*8,(0*6+3)*8)]:
    i,j = k
    for n in range(8):
        GROW_MAT += [[0]*(min(i,j)+n) + [1] + [0]*(max(i,j)-min(i,j)-1) + [1] + [0]*(288-max(i,j)-1-n)]
GROW_MAT = Matrix(GF(2), GROW_MAT)

# BeeHive.pollination() matrix
BEES_MAT = block_matrix(GF(2),[[I_48x48,0,0,0,0,0],[I_48x48,I_48x48,0,0,0,0],[I_48x48,I_48x48,I_48x48,0,0,0],[I_48x48,I_48x48,I_48x48,I_48x48,0,0],
                               [I_48x48,I_48x48,I_48x48,I_48x48,I_48x48,0],[I_48x48,I_48x48,I_48x48,I_48x48,I_48x48,I_48x48]], subdivide=False)
POLL_MAT = GROW_MAT
for _ in range(5):
    POLL_MAT = POLL_MAT.stack(GROW_MAT)
POLL_MAT += BEES_MAT



# Create a round matrix that represents the state update for a single round (not the output)
ROUND_MAT = identity_matrix(GF(2), 288)
for i in range(6):
    ROUND_MAT = POLL_MAT * SWAP_MAT * ROT_MATs[i] * ROUND_MAT


# Let's check for the smallest number of rounds necessary for a matrix with a rank of 288
# Remember that the output is modified by GROW_MAT
OUT_MAT = GROW_MAT * ROUND_MAT
i = 2
while OUT_MAT.rank() < 288:
    OUT_MAT = OUT_MAT.stack(GROW_MAT * ROUND_MAT^i)
    i += 1
    
# Get rid of some unnecessary rows (just to get the absolute minimum information we need)
k = 288
while Matrix(GF(2), list(OUT_MAT)[:k]).rank() < 288:
    k += 1
MINREC_MAT = Matrix(GF(2), list(OUT_MAT)[:k])

# Turns out we need 38 bytes of known keystream in order to recover the internal state, that is not very secure :S


# TIME TO TEST IT OUT!

# Let's create an encryption
s    = b'Hello, this is a custom 36-byte key!'
text = b'Bees make honey, but they also made the Bee Movie... flag{_REDACTED_}'
hc   = HoneyComb(s.hex())
flag = hc.encrypt(text)

# Time to recover our key!
rec_keystream = bytes([text[i] ^^ flag[i] for i in range(38)])
REC_STREAM = Matrix(GF(2), [int(i) for i in '{:0304b}'.format(int.from_bytes(rec_keystream,'big'))]).T


# Ta-da!
print(bitstate_to_bytes(MINREC_MAT.solve_right(REC_STREAM)))
```
```py
b'Hello, this is a custom 36-byte key!'
```

It works, awesome. Now we can simply feed it the given encryption (instead of our own made one) to recover the flag.

Ta-da!
```
flag{th3s3_mumbl3_b33s_4r3_h4rd_t0_und3rst4nd_y0u_kn0w}
```


-----
Thanks for reading! <3

~ Polymero