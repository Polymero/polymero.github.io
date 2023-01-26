---
layout: page
---

# Write-up Nothing up my SBox

By Polymero

### Exploration
---

Let's begin by connecting to the netcat address to see what we are up against &cudarrr;

```
|
|  ~ In order to prove that I have nothing up my sleeve, I let you decide on the sbox!
|    I am so confident, I will even stake my flag on it ::
|    flag = ef2d07d77628bcee505f278ff7072fe021b4cb0f40
|
|  ~ Now, player, what should I call you?
|
|  >
```

Aside from an encrypted flag, nothing just yet. So let's give the server a name &cudarrr;

```
|  > Polymero
|
|  ~ Well Polymero, here are your s- and p-box ::
|    s-box = [7, 11, 14, 5, 6, 2, 13, 10, 4, 15, 3, 8, 0, 1, 9, 12]
|    p-box = [1, 2, 6, 8, 15, 3, 12, 9, 4, 13, 11, 7, 5, 10, 14, 0]
|
|  ~ Menu ::
|    [E]ncrypt
|    [Q]uit
|
|  >
```

So my name has generated these boxes? Connecting again and putting in the same name will yield an identical s-box but a different p-box, so seemingly only the s-box is derived from the user input. Additionally, we are given access to an encryption oracle. From this we can deduce we have to find an s-box that allows us to launch a chosen plaintext attack on an oracle in order to recover its key.

```py
# Imports
import os, time
from secrets import randbelow
from hashlib import sha256

# Local imports
FLAG = os.environ.get('FLAG', 'flag{spl4t_th3m_bugs}').encode()
```
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

We find a global key is generated as a 16-digit hex number, equal to 8 bytes. Although I would not call this secure, we will certainly not be able to brute-force the key during the competition duration. The flag is then encrypted with a One Time Pad (OTP) created from a hash of said key. So in order to get the flag, we must recover the global key.

Finally, we see the service requests for a name, which it calls `seed`, and creates an oracle based on this seed and the global key. Let's continue to the server loop &cudarrr;

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

As we saw before, the only way to interact with the oracle is through encryption requests, so let's check out this oracle class &cudarrr;

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

Firstly, we notice that the s-box is indeed derived from our input earlier, whereas the p-box is based on the local time. What we find further in the `NUMSBOX` class is a standard 4-round block cipher based on a so-called Substitution Permutation Network (SPN). Ciphers like these, such as AES, run blocks of plaintext through rounds of the same three steps:
1. **Substitution**, where pieces of the block are replaced by other pieces using a substitution box (s-box);
2. **Permutation**, where pieces are shuffled within the block, either through a permutation box (p-box) or some other (linear) transformation;
3. **Key Mixing**, where the block is XORed with a round key, which is in turn derived from the encryption/decryption key.

Without going to much into detail regarding this construction it is important to realise that a round is reversible and therefore a single round provides NO security. In other words, knowing the s- and p-boxes, some input plaintext, and its corresponding output ciphertext, it is trivial to recover the (round) key. We can simply apply the substitution step to our input and are then left only with the other two steps. Both the permutation and the key mixing are linear and can thus be set up as a system of linear equations with the key elements as unknown variables. However, if we now consider two rounds instead of just one, the situation changes. We can still apply the first substitution step ourselves, but because we have no knowledge of the first round key, we have no idea what the input is during the second substitution. The substitution step is (assumed to be) non-linear and can hence not be expressed in our system of equations. We can now no longer recover the round keys so simply anymore.

_Not convinced? Try it out yourself using small blocks and elements!_

The security of this kind of scheme thus heavily relies on the non-linearity of the s-box. If it turns out the s-box is in fact linear, the whole cipher can be set up as a system of linear equations and be solved easily. Since our input at the start of the server connection influences the oracle's s-box, looking for a s-box that allows us to linearise the encryption might be our most prominent attack vector.

Finally, another thing to note is the lack of a key schedule in this implementation. Earlier I used the term 'round key' as usually each round has a distinct round key derived from the single encryption/decryption key, often called the master key. However, here we see that each round key is just the master key itself. Although this is not something we can directly exploit, it does hurt the overall security of a block cipher.

To summarise, we have made the following observations:
1. The service acts as an unlimited encryption oracle for a SPN block cipher;
2. In order to decrypt the flag, we must recover the oracle's key;
3. The s-box of the block cipher is derived from user input, whereas the p-box is derived from the server's local time;
4. By manipulating the s-box generation, we might be able to linearise the cipher and recover the key by solving a system of linear equations between plaintext and ciphertext.



### Exploitation
---

Following the observations we have made, the most prominent attack vector is to look for s-boxes that allow us to linearise the cipher. In other words, our exploit will contain the following steps:
1. Figure out what s-box characteristics allow us to linearise it;
2. Brute-force a username that results in an appropriately weak s-box;
3. Set up linear relations between the input, the output, and the (round)key(s);
4. Solve the system of equations in order to recover the key and decrypt the flag. 



---
### Possibility of Generating Linear S-Boxes

...

1st element can be any, so possibility $1$;
2nd element has to be coprime to the modulus, which is a power of $2$, so possibility $1/2$;
3rd element has to align with the linear step, which is satisfied by only a single element, so possibility $1/m$;
4th element idem, so possibility $1/m$;
...
$m$-th element idem, so possibility $1/m$.

In other words, for a modulus $m = 2^k$ for some positive integer $k$, the possibility of randomly generating a fully linear s-box is

$$ P(m) = \frac{1}{2} m^{-(m - 2)} $$

or expressed in $k$,

$$ P(k) = \left( \frac{1}{2} \right)^{k(2^k - 2) + 1}. $$

In our space of 16 elements, this possiblity is 

$$ P(m = 16) = \frac{1}{2}\left( \frac{1}{16} \right)^{14} = \left( \frac{1}{2} \right)^{57} = 7 \cdot 10^{-18}, $$

which means we will not be able to reliably generate a fully linear s-box within the competition time.

For something like AES, which works in the byte space, the possibility is even smaller,

$$ P(m = 256) = \frac{1}{2}\left( \frac{1}{256} \right)^{254} = \left( \frac{1}{2} \right)^{2033} \approx 0 , $$

so randomly generating fully linear s-boxes is not much of a concern.

---



---
### Possibility of Generating Fixed Points

...

the possibility of getting _exactly_ $k$ fixed points in a space of size $m$ is

$$ P(k, m) = \frac{1}{k!} \sum_{i=0}^{m-k} \frac{(-1)^i}{i!} , $$

such that the possibility of getting _at least_ $k$ fixed points becomes

$$ P(k, m) =  \sum_{i=k}^{m} \left( \frac{1}{i!} \sum_{j=0}^{m-i} \frac{(-1)^j}{j!} \right). $$

---


### Finding a weak seed

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


### Recovering the key

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

def oracle_encrypt(s, x):
	s.sendline(b"e")
	s.recv()
	s.sendline(''.join([hex(i)[2:] for i in x]).encode())
	s.recvuntil(b'~ ')
	y = [int(i,16) for i in s.recvuntil(b"\n", drop=True).decode()]
	s.recv()
	return y

def ret_max_count(x):
    uniq = list(set(x))
    cnts = [sum(int(i == j) for j in x) for i in uniq]
    mx = max(cnts)
    return [uniq[i] for i in range
            (len(uniq)) if cnts[i] == mx]

REC = 1
while REC:

	s = connect(host, port)

	print(REC, end='\r', flush=True)
	REC += 1

	# Get encrypted flag
	s.recvuntil(b"flag = ")
	encflag = bytes.fromhex(s.recvuntil(b"\n", drop=True).decode())

	s.recv()
	s.sendline(seed_fix_10.encode())

	s.recvuntil(b"s-box = ")
	sbox = eval(s.recvuntil(b"\n", drop=True).decode())
	assert sum(i == j for i,j in enumerate(sbox)) == 10

	s.recvuntil(b"p-box = ")
	pbox = eval(s.recvuntil(b"\n", drop=True).decode())

	cip_lst = []
	key_mat = []

	for ji in range(16):

		js = [ji]
		for _ in range(4):
			js += [pbox.index(js[-1])]

		key_mat += [[1 if j in js else 0 for j in range(16)]]

		cip_lst += [ret_max_count([oracle_encrypt(s, [0]*ji + [k] + [0]*(16-ji-1))[js[-1]] ^ k for k in range(16)])]

	bit_mat = []
	for row in key_mat:
		for i in range(4):
			bit_mat += [[]]
			for j in row:
				bit_mat[-1] += [0]*i + [j] + [0]*(3 - i)

	if Matrix(GF(2), bit_mat).rank() == 64:

		for _ in range(100):

			cip_vec = [sample(i, 1)[0] for i in cip_lst]
			bit_vec = [m for n in [[int(i) for i in '{:04b}'.format(j)] for j in cip_vec] for m in n]

			key_vec = Matrix(GF(2), bit_mat).solve_right(Matrix(GF(2), bit_vec).T)
			key_lst = key_vec.list()
			key_rec = [int(''.join(str(j) for j in key_lst[i:i+4]), 2) for i in range(0, len(key_lst), 4)]

			otp = b""
			while len(otp) < len(encflag):
				otp += sha256(b" :: ".join([b"OTP", str(key_rec).encode(), len(otp).to_bytes(2, 'big')])).digest()

			rec_flag = bytes([i ^ j for i,j in zip(encflag, otp)])

			if b"flag" in rec_flag:
				print(REC, rec_flag)
				REC = 0
				break

	s.close()
```