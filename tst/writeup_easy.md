---
layout: page
---

# Write-up Ursa Minor

By Polymero

### Challenge Description
---

RSA is getting a lot of hate nowadays, so let's give it a much needed upgrade! This time it is FASTER and more SECURE due to our key cycling technique. Feel free to try it out at:

`nc host post`

Files: ursaminor.py

### Educational Goal
---



### Exploration
---

Let's begin by connecting to the netcat address to see what we are up against &cudarrr;

```
|
|  ~ Welcome to URSA encryption services
|    Press enter to start key generation...
|
|
|    Please hold on while we generate your primes...
|
|
|  ~ You are connected to an URSA-256-12 service, public key ::
|    id = 4c22c3bc1dbef3b86b00c6a3b67bbea3a4182031c99ea9158127ed13f0a449a2
|    e  = 65537
|
|  ~ Here is a free flag sample, enjoy ::
|    671437882957829719101572680363081891518096856835305094698051932901754849525881766670905061255909949484381327436551354158656093694356505058328430043
|
|  ~ Key updated succesfully ::
|    id = 4c22c3bc1dbef3b86b00c6a3b67bbea3a4182031c99ea9158127ed13f0a449a2
|    e  = 521491719974536978092407456232597802182153441618346043937891902491487089530202560189816347350446956730367573501446806121093134031197877958852777149
|
|  ~ Menu (key updated after 3 requests)::
|    [E]ncrypt
|    [D]ecrypt
|    [U]pdate key
|    [Q]uit
|
|  >
```

Seems like a standard RSA oracle with some sort of key update mechanism. Let's check the source code to see what is going on. First up, the challenge setup &cudarrr;

```py
# Imports
from Crypto.Util.number import isPrime, getPrime, inverse
import hashlib, time, os

# Local import
FLAG = os.environ.get('FLAG', 'flag{spl4t_th3m_bugs}').encode()
```
```py
# Challenge setup
print("""|
|  ~ Welcome to URSA encryption services
|    Press enter to start key generation...""")

input("|")

print("""|
|    Please hold on while we generate your primes...
|\n|""")
    
oracle = URSA(256, 12)
print("|  ~ You are connected to an URSA-256-12 service, public key ::")
print("|    id = {}".format(hashlib.sha256(str(oracle.public['n']).encode()).hexdigest()))
print("|    e  = {}".format(oracle.public['e']))

print("|\n|  ~ Here is a free flag sample, enjoy ::")
for i in oracle.encrypt(int.from_bytes(FLAG, 'big')):
    print("|    {}".format(i))
```

It seems the server sets up a class object and gives us a partial public key and the encrypted flag. I say partial key, as we only receive the hashed public modulus.

Next up, the server loop &cudarrr;

```py
MENU = """|
|  ~ Menu (key updated after {} requests)::
|    [E]ncrypt
|    [D]ecrypt
|    [U]pdate key
|    [Q]uit
|"""

# Server loop
CYCLE = 0
while True:
    
    try:

        if CYCLE % 4:
            print(MENU.format(4 - CYCLE))
            choice = input("|  > ")

        else:
            choice = 'u'
        
        if choice.lower() == 'e':
            msg = int(input("|\n|  > (int) "))

            print("|\n|  ~ Encryption ::")
            for i in oracle.encrypt(msg):
                print("|    {}".format(i))

        elif choice.lower() == 'd':
            cip = int(input("|\n|  > (int) "))

            print("|\n|  ~ Decryption ::")
            for i in oracle.decrypt(cip):
                print("|    {}".format(i))
            
        elif choice.lower() == 'u':
            oracle.update_key()
            print("|\n|  ~ Key updated succesfully ::")
            print("|    id = {}".format(hashlib.sha256(str(oracle.public['n']).encode()).hexdigest()))
            print("|    e  = {}".format(oracle.public['e']))

            CYCLE = 0
            
        elif choice.lower() == 'q':
            print("|\n|  ~ Closing services...\n|")
            break
            
        else:
            print("|\n|  ~ ERROR - Unknown command")

        CYCLE += 1
        
    except KeyboardInterrupt:
        print("\n|  ~ Closing services...\n|")
        break
        
    except:
        print("|\n|  ~ Please do NOT abuse our services.\n|")
```

As we learned from our first connection, we are indeed capable of encrypting and decryption whatever we like. However, a third option is added that allows us to update the oracle's key. Furthermore, after encrypting the flag and after every three requests from us, the oracle will update its key automatically. So having the oracle decrypt the encrypted flag does not help us much.

Finally, let's check out this URSA class &cudarrr;

```py
class URSA:
    # Upgraded RSA (faster and with cheap key cycling)
    def __init__(self, pbit, lbit):
        p, q = self.prime_gen(pbit, lbit)
        self.public = {'n': p * q, 'e': 0x10001}
        self.private = {'p': p, 'q': q, 'f': (p - 1)*(q - 1), 'd': inverse(self.public['e'], (p - 1)*(q - 1))}
        
    def prime_gen(self, pbit, lbit):
        # Smooth primes are FAST primes ~ !
        while True:
            qlst = [getPrime(lbit) for _ in range(pbit // lbit)]
            if len(qlst) - len(set(qlst)) <= 1:
                continue
            q = 1
            for ql in qlst:
                q *= ql
            Q = 2 * q + 1
            if isPrime(Q):
                break
        while True:
            plst = [getPrime(lbit) for _ in range(pbit // lbit)]
            if len(plst) - len(set(plst)) <= 1:
                continue
            p = 1
            for pl in plst:
                p *= pl
            P = 2 * p + 1
            if isPrime(P):
                break 
        return P, Q
    
    def update_key(self):
        # Prime generation is expensive, so we'll just update d and e instead ^w^
        self.private['d'] ^= int.from_bytes(hashlib.sha512((str(self.private['d']) + str(time.time())).encode()).digest(), 'big')
        self.private['d'] %= self.private['f']
        self.public['e'] = inverse(self.private['d'], self.private['f'])
        
    def encrypt(self, m_int):
        c_lst = []
        while m_int:
            c_lst += [pow(m_int, self.public['e'], self.public['n'])]
            m_int //= self.public['n']
        return c_lst
    
    def decrypt(self, c_int):
        m_lst = []
        while c_int:
            m_lst += [pow(c_int, self.private['d'], self.public['n'])]
            c_int //= self.public['n']
        return m_lst
```

Upon initialisation, it calls a prime generation method called `prime_gen()` and gives itself a standard RSA key pair. Instead of just using a built-in prime generating function, the class goes against the grain by creating its own. Following the code we see that it generates smaller primes of size `lbit` (in bits) up until their product would be of size `pbit`. It then requires the length of the prime list to be smaller than the length of the corresponding set. In other words, it requires the prime list to contain at least one duplicate prime. It then repeats this process until it can mash all the small primes $q_i$ into a larger prime $Q$ using

$$ Q = 1 + 2 \prod_i q_i. $$

Finally, another prime $P$ is generated in identical fashion. Notice how for primes generated using this function $Q-1$ will factor into many (relatively) small factors. These kind of primes are called smooth primes and are notoriously dangerous for most cryptographic purposes as they allow for easy integer factorisation. Note that the security of RSA lies in the hardness of factoring the public modulus! Although we are never given the public modulus directly, this is definitely worth noting as a potential vulnerability.

Going down the list we find three more methods. `update_key()` effectively scrambles the private exponent by XORing it with a sha-512 output, and derives an updated public exponent. Note that the public modulus stays the same. `encrypt()` encrypts a message using the public key, whereas `decrypt()` decrypts a message using the private key, following textbook RSA. However, for inputs larger than the public modulus it splits the input into chunks and encrypts/decrypts them individually. 

To summarise, we made the following observations:
1. The service behaves as an unlimited RSA oracle with periodic scrambling of the private and public exponent;
2. We are given a hash of the public modulus, not its actual value;
3. The used prime generation method yields smooth primes allowing for simple factorisation of the public modulus;
4. The encryption/decryption methods split the input into chunks if necessary.



### Exploitation
---

Following the observations we have made, the most prominent attack vector is the oracle's use of smooth primes to generate the RSA key. However, there is one hurdle to overcome. We are only provided a hash of the public modulus, so we need to recover its value first somehow. So our exploit will contain three steps:
1. Recover the value of the public modulus;
2. Factorise the public modulus using Pollard's $p-1$ algorithm;
3. Decrypt the encrypted flag using the re-created initial private key.


***Recovery***

Trying to recover the public modulus from its hash is a lost cause, so we will have to find another way. Luckily the encryption/decryption methods of the oracle reveal some information about the public modulus, namely whether or not our input is larger than it. We can therefore apply a binary search to fully recover the public modulus one bit at a time. So here is the plan:
1. Set $N=0$ and $k=512$;
2. Encrypt/decrypt $N \oplus 2^{k-1}$ and if the response contains two chunks we know that $N \oplus 2^{k-1} > N$ so we continue to 3, otherwise we know that $N \oplus 2^{k-1} < N$ so we set $N = N \oplus 2^{k-1}$ and continue to 3;
3. Set $k = k - 1$ and go to 2, until $k = 1$ then continue to 4;
4. Set $N = N \oplus 1$. Return $N$.

The example code below uses a for-loop and iterates $k$ up instead, but works the same.

```py
# Loop to recover public modulus bits
def recover_public_modulus(oracle):

    N = 0
    for k in range(512):

    	pt = N ^ 2**(512 - k - 1)

    	resp = oracle.encrypt(pt)

    	if len(resp) == 1:
    		N = pt

    return N ^ 1
```


***Factorisation***

Now that we know the value of the public modulus, we can try to recover its two prime factors.
Consider a composite group of size $n$, where $p$ is one of the factors of $n$, and a number $x$ such that

$$ x \equiv 1 \mod{p}. $$

This implies that

$$ x - 1 = k p $$

for some integer $k$. As both $n$ and $x-1$ are a multiple of $p$, their greatest common divisor (GCD) will also be multiple of $p$. In other words, if we find such a number $x$ we can recover $p$ from $\mathrm{gcd}(x-1,\ n)$.

But how would we find such a number $x$ without knowing $p$? Luckily our friend Fermat comes to our rescue once more. Fermat's little theorem tells us that for a prime $p$ and any positive integers $a$ and $k$ we have

$$ a^{k(p-1)} \equiv 1 \mod{p}. $$

Although we know nothing about $p$ specifically, we do have some information about $p-1$! In fact we know that

$$ p - 1 = 2 \prod q_i, $$

where $q_i$ are a selection of 12-bit primes, more specifically we have $q_i < 2^{12}$ for all $i$. The idea of Pollard's $p-1$ factorisation is that knowing $p-1$ contains only factors smaller than some bound, in our case $2^{12}$, we can take some number $a$ and raise it to all primes smaller the bound. The result $x$ can be rewritten as $x = a^{k(p-1)}$ for some $k$ such that $x \equiv 1 \mod{n}$. This will allow us to then easily recover $p$ from the above stated GCD. If the algorithm fails, we try a different value for $a$. It usually works immediately for $a=2$. However, there are a couple of points we need to address.

Firstly, we can be a bit smarter than this. We have more specific information about $p-1$ than knowing some bound $B$, namely that all factors of $p-1$ are either a 12-bit prime or 2. So instead of taking all primes smaller than $2^{12}$ we only have to consider all possible 12-bit primes (and 2), this saves a bit of computing time.

Secondly, remember the `if len(qlst) - len(set(qlst)) <= 1` check in the prime generation? This makes sure that there is at least one duplicate prime factor in $p-1$. If we raise our number $a$ to the power of all 12-bit primes, we are sure to miss out on the duplicate prime in there. We can fix this by raising $a$ to the power of all 12-bit primes squared (or some higher power) instead. The product of all squared 12-bit primes will contain $p-1$ as factor with high probability so we should be good now.

Finally, both prime factors, say $p$ and $q$, of the public modulus are made in the same way. Therefore we will end up raising our $a$ to both a multiple of $p-1$ and $q-1$ such that $\mathrm{gcd}(x - 1,\ n)$ will return $n$ regardless of our choice of $a$. The way to deal with this is to NOT include 2 in our prime set and instead pick our $a$ such that it is a quadratic residue modulo $p$, but a quadratic non-residue modulo $q$. In this case $a$ can be written as $a \equiv b^2 \mod{p}$ for some $b$, whereas the same is not possible modulo $q$. Therefore raising $a$ to the power of all squared 12-bit primes we end up with 

$$ x = a^{\prod_i k_{p,i} \prod_i f_{p,i}} = b^{2 \prod_i k_{p,i} \prod_i f_{p,i}} = b^{\prod_i k_{p,i} (p-1)} \equiv 1 \mod{p}, $$

where $k_{p,i}$ are all 12-bit prime non-factors of $p$ and $f_{p,i}$ all 12-bit prime factors of $p$. Whereas we also have

$$ x = a^{\prod_i k_{q,i} \prod_i f_{q,i}} \not\equiv 1 \mod{q}, $$

such that $\mathrm{gcd}(x - 1,\ n)$ will be a multiple of $p$ but not of $q$. Since we do not know $p$ or $q$ we will just iterate over different values for $a$ until we hit one that reveals either $p$ or $q$.

Now we know everything we need to know, so let's find all 12-bit primes &cudarrr;

```py
# Find all 12-bit primes
prime_set_1 = set()
for k in range(2**11, 2**12+1):
    
    if isPrime(k):
        prime_set_1.add(k)
        
print(len(prime_set_1))
```
```
255
```

---

### Side Note

Note that it is better practice to mimic the exact methods used in the source code as they might behave slightly differently from what you would think. For instance, if we collect all possible outputs of `getPrime(12)`, as used in the source code, we get something interesting &cudarrr;

```py
# Find all 12-bit primes
prime_set_2 = set()
for k in range(10_000):
    
    prime_set_2.add(getPrime(12))
    
print(len(prime_set_2))
print([p for p in prime_set_2 if p not in prime_set_1])
```
```
256
[4099]
```

As it turns out, the `getPrime()` method from the `pycryptodome` package will misbehave for the case of 12-bit primes and sometimes output $4099$, which is 13 bits long! Luckily for us, it does not affect our exploit.

---

Next up is running our Pollard's $p-1$ algorithm as follows:
1. Set $a = 2$;
2. Set $x = a$ and raise it (one by one) to all 12-bit primes $p_i$, squared, such that we end up with $x = a^{\prod_i p_i^2}$;
3. If $\mathrm{gcd}(x-1,\ N)$ is either 1 or N, then set $a = a + 1$ and go to 2. Otherwise, the result will be one of the two factors of N, say $p$. Continue to 4;
4. Find the other factor as $q = N / p$ and return $(p, q)$.

Or in code &cudarrr;

```py
def pollard_factorisation(N, prime_set):

    a = 2
    while True:

        x = a

        for i in primeset:
            x = pow(x, i**2, N)

        p = GCD(x - 1, N)

        if p not in [1, N]:
            q = N // p
            break

        a += 1

    return p, q
```


***Decryption***

Having recovered the primes of the oracle's RSA key, we can now decrypt the flag by calculating the private exponent corresponding to the public exponent that was used to encrypt it &cudarrr;

```py
D = inverse(0x10001, (P - 1) * (Q - 1))

print(pow(encflag, D, N).to_bytes(128, 'big').lstrip(b"\x00"))
```
```
<insert your flag here :)>
```

A full solve script can be found below &cudarrr;

```py
# Imports
from pwn import *
from Crypto.Util.number import isPrime, inverse, getPrime, GCD
from math import log

# Connection
host = '0.0.0.0'
port = '5000'
s = connect(host, port)

# context.log_level = 'debug'



# Pass an enter
print('|\n|  ~ Waiting for prime generation...')
s.recv()
s.sendline(b"")

# Get public modulus (id)
s.recvuntil(b"id = ")
Nid = s.recvuntil(b"\n", drop=True).decode()
print('|\n|  ~ Collecting challenge parameters ::')
print(f"|    id = {Nid}")

# Get encrypted flag
s.recvuntil(b"e  =")
s.recvuntil(b"|    ")
encflag = int(s.recvuntil(b"\n", drop=True).decode())
print(f"|    f  = {encflag}")
s.recv()

print('|    Connection succesfully established ~ !')



# Loop to recover public modulus bits
print('|\n|  ~ Starting loop ::')
N = 0
for k in range(512):

    pt = N ^ 2**(512 - k - 1)

    s.sendline(b"e")
    s.recv()

    s.sendline(str(pt).encode())
    s.recvuntil(b"::\n")

    resp = s.recvuntil(b"~ ")
    s.recv()

    if sum([1 for i in resp if i == ord('\n')]) <= 2:

        N = pt

    print('|    N = {:0512b}'.format(N), end='\r', flush=True)

N ^= 1
print('|\n|  ~ Recovered the public modulus ::')
print('|    {}'.format(N))



print('|\n|  ~ Running p-1 factorisation...')

# Generate set of all 12-bit primes
print('|\n|  ~ Finding all 12-bit primes...')
primeset = set()
for _ in range(5_000):
    primeset.add(getPrime(12))
print('|    Found {}'.format(len(primeset)))

k = 0
while True:

    w = k

    for i in primeset:
        w = pow(w, i**2, N)

    p = GCD(w - 1,N)

    if p not in [1, N]:
        q = N // p
        break

print('|\n|  ~ Found the following primes ::')
for i in [p, q]:
    print('|    {}'.format(i))

F = (p - 1) * (q - 1)
d = inverse(0x10001, F)

flag = pow(encflag, d, N).to_bytes(128, 'big').lstrip(b"\x00")
print('|\n|  ~ Recovered the flag ::')
print('|    {}'.format(flag.decode()))

print('|\n|')
```

Ta-da ~ !