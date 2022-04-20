---
title: HackPack CTF 2022 - P(ai)^3
category: CTF
tags: crypto Paillier
hidden_tags: my-challenge
excerpt_separator: <!--more-->
---

Cryptography -- 469 pts (15 solves) -- Chall author: Polymero (me)

_Pai-ai-ai... My Paillier scheme seems to be broken and I stored my favourite flag in it. Please help me get it back, will you? Who could have guessed this would ever happen? ... Me... I- I wrote it... yeah._

<!--more-->

nc cha.hackpack.club 10997 or 20997

Files: [paiaiai.py]()

![](/assets/ctf/Paiaiai_chall.png)

This challenge was part of my guest appearance on [HackPack CTF 2022](https://ctftime.org/event/1620).

<br>

## Exploration

A broken Paillier scheme, ay? We will have to see about that, so let's check out that netcat address.

```
|
|   __________     ___   _____  .___  ___     /\  ________
|   \______   \   /  /  /  _  \ |   | \  \   /  \ \_____  \
|    |     ___/  /  /  /  /_\  \|   |  \  \  \/\/   _(__  <
|    |    |     (  (  /    |    \   |   )  )       /       \
|    |____|      \  \ \____|__  /___|  /  /       /______  /
|                 \__\        \/      /__/               \/
|
|
|  MENU:
|   [E]ncrypt
|   [D]ecrypt
|   [Q]uit
|
|  >>>
```

A simple encryption and decryption oracle by the looks of it. But is there a flag somewhere, or...?

```
|  >>> e
|
|  ENCRYPT:
|   [F]lag
|   [M]essage
|
|  >>> f
|
|  FLAG: 5034785281950343508744711185197053413579683684148346815055060643830096040661868151655540533876088575122326236411117844472809056644810603591168338896947065051838001190612137050286239757216637769428688458121795534498425150558799778262152211380500502315518078744021314932495226813697971002436193528611124439176499215601182718102181293884893725133193746104582566161413721747512035451101644872652626262911480381217826003138422858719320658061016453762663219079891957566134362778008467545382769109618240098365542282971245141679577428279057904116622344521602573879167018369528424811143805230006833934692544590370705590706749
```

Ah, there it is. How about we just try to decrypt the encrypted flag using the oracle. It's worth a shot, no?

```
|  >>> d
|
|  CIP: int
|   > 5034785281950343508744711185197053413579683684148346815055060643830096040661868151655540533876088575122326236411117844472809056644810603591168338896947065051838001190612137050286239757216637769428688458121795534498425150558799778262152211380500502315518078744021314932495226813697971002436193528611124439176499215601182718102181293884893725133193746104582566161413721747512035451101644872652626262911480381217826003138422858719320658061016453762663219079891957566134362778008467545382769109618240098365542282971245141679577428279057904116622344521602573879167018369528424811143805230006833934692544590370705590706749
|
|  MSG: 12871600377284678436598137255971594702778717571805789843087607005526820834753398893936142416141847404877983796452226917450460827082602907623668019954000946671758045381893241895902842877012194250175399626949591728996536054349500689273433699378169394830786556638694244611253646771790397394644439916576778434039
```

It did not complain, so let's see that juicy flag!

```
b'\x12Tk\xa2h?\xad\xd9\x7f\xf70\x17\xb0\x0e,L\t\x85@\x9aU\x146\xf1\x89\xcbG\x98\xe0\x90\x18\xc4\xfbz\xd0\xd7\xca\\\xe4\xcd\xcdk\xff)<\x92EI&\x7f\xec\x89\xb2K\xf2c\xe0\x80=\xf3\x8e\x1b\x00P\x80\xe3a\x00 x\xa3\xeeJ8\x1c/\xbb\x16A\x9c\xbd\xefK\xd8{\xc3\xff\x1b%\xbc\xd2W\xe7\xa2^\x11\x15v\xebB\xb2\x11\xcfA\x04Y\xf0\xcb\x03x\xbcpX\x90\xb6\xe8\xeb\xabF\xbaw\x82v\xc6\xd0\x7f5\xf7'
```

Oh... Mmh... Maybe somebody should go and tell them their Paillier scheme is broken. Oh, they already know? Right, right... Down into the source code we go! First stop, the main server loop. _I added some comments to help guide you through the code._

```py
# Just for you sanity
assert len(FLAG) > 64

# Server oracle
pai = Paiaiai()

while True:
    
    try:
        
        print(MENU)
        choice = input("|  >>> ").lower().strip()
        
        # Encrypt option
        if choice == 'e':
            print("|\n|  ENCRYPT:")
            print("|   [F]lag")
            print("|   [M]essage")
            subchoice = input("|\n|  >>> ").lower().strip()
            
            # Encrypt the flag
            if subchoice == 'f':
                enc_flag = pai.encrypt(FLAG)
                print("|\n|  FLAG:", enc_flag)
                
            # Encrypt input message
            elif subchoice == 'm':
                msg = input("|\n|  MSG: str\n|   > ")
                cip = pai.encrypt(msg)
                print("|\n|  CIP:", cip)
            
        # Decrypt option
        elif choice == 'd':
            cip = input("|\n|  CIP: int\n|   > ")
            msg = pai.decrypt(int(cip))
            print("|\n|  MSG:", msg)
            
        # Exit option
        elif choice == 'q':
            print("|\n|  Bai ~ \n|")
            break
            
        else:
            print("|\n|  Trai again ~ \n|")
        
    except KeyboardInterrupt:
        print("\n|\n|  Bai ~ \n|")
        break
        
    except:
        print("|\n|  Aiaiai ~ \n|")
```

Nothing unexpected so far, so let's take a look at that `Paiaiai` class to get to know this Paillier-like scheme. Although at this point it should be noted that we seem not to have access to the Paillier public key, something to keep in mind.

```py
class Paiaiai:
    """ My first Paillier implementation! So proud of it. ^ w ^ """

    def __init__(self):

        # Key generation
        p, q = [getPrime(512) for _ in range(2)]
        n = p * q

        # Public key
        self.pub = {
            'n'  : n,
            'gp' : pow(randbelow(n**2), p, n**2),
            'gq' : pow(randbelow(n**2), q, n**2)
        }

        # Private key
        self.priv = {
            'la' : (p - 1)*(q - 1),
            'mu' : inverse((pow(self.pub['gp'] * self.pub['gq'], (p-1)*(q-1), n**2) - 1) // n, n)
        }
        

    def encrypt(self, m: str):

        m_int = int.from_bytes(m.encode(), 'big')

        # Encrypting with one of two possible generators at random
        g = pow([self.pub['gp'],self.pub['gq']][randbelow(2)], m_int, self.pub['n']**2)
        r = pow(randbelow(self.pub['n']), self.pub['n'], self.pub['n']**2)

        return (g * r) % self.pub['n']**2
    

    def decrypt(self, c: int):

    	# Decrypting with same private key regardless of generator choice
        cl = (pow(c, self.priv['la'], self.pub['n']**2) - 1) // self.pub['n']

        return (cl * self.priv['mu']) % self.pub['n']
```

It appears this Paillier scheme uses two different generators, $g_p$ and $g_q$, which are both valid generators raised to the power of one of the two primes each. We see that during the encryption process only one of the generators is used and more specifically, chosen at random. However, during the decryption process the same private key is used regardless of generator choice. Furthermore, the private key is generated using the product of said generators instead. Obviously this scheme is not going to work... but can we help the author out? _What a crypto noob hehe_

<br>

## Exploitation 1: Fuzzing

The initial exploitation to this faulty Paillier scheme I found through playing around with it a bit. By inspecting decrypted ciphertexts of a local copy I found the following interesting relationship

$$ D_{\mu} \left( E_{g_{p}}(m) \right) \equiv \left\{  \begin{array}{c} 0 \mod{p} \\ m \mod{q} \end{array}  \right. $$

and similarly for the other generator I found

$$ D_{\mu} \left( E_{g_{q}}(m) \right) \equiv \left\{  \begin{array}{c} 0 \mod{q} \\ m \mod{p} \end{array} \right. $$

Frankly, this is exactly what we need. Not only does this allow us to recover the message knowing $p$ and $q$, it also allows us to recover $p$ and $q$ themselves! But first things first, let's get both possible faulty decryptions of the flag.

```py
# Get both possible faulty decrypted flag values
flag_r = []
while len(flag_r) != 2:

	k = get_decrypt(get_flag())

	if k not in flag_r:
		flag_r += [k]

flag_p, flag_q = flag_r
```

Next up is recovering the primes $p$ and $q$. We already know that getting a faulty decryption will yield a multiple of either $p$ or $q$ depending on the used generator. So if we can get two different messages encrypted with the same generator, we should be able to recover one of the primes from the greatest common devisor (GCD) of the faulty decryptions. Because we have no knowledge of the used modulus, we have to recover both primes this way.

```py
# Try to recover prime factorisation of unknown public modulus using random faulty decryptions
while True:

	rstr = [''.join(random.sample(ALP, 9)) for _ in range(8)]
	rdec = [get_decrypt(get_encrypt(i)) for i in rstr]

	p = max([GCD(flag_p, i) for i in rdec])
	q = max([GCD(flag_q, i) for i in rdec])

	for k in range(2, 1_000_000):
		while not p % k:
			p //= k
		while not q % k:
			q //= k

	if isPrime(p) and isPrime(q):
		break
```

Having recovered the primes we can use the faulty decryptions of the flag to obtain the flag value modulo $p$ and $q$, respectively. Combining them through the chinese remainder theorem (CRT) we can easily recover the original flag modulo $pq$.

```py
# Recover flag
n = p * q
flag_modp = flag_q % flag_p
flag_modq = flag_p % flag_q

flag, pub = crt([p, q], [flag_modp, flag_modq])

FLAG = int(flag).to_bytes(128,'big').lstrip(b"\x00")
print(FLAG)
```

Ta-da!
```
flag{p41_41_41_1_d0nt_th1nk_th1s_1s_wh4t_p41ll13r_1nt3nd3d_3h}
```


**Full Exploit Script**

```py
#!/usr/bin/env python3
#
# Polymero
#

# Imports
from pwn import *
import random
from Crypto.Util.number import GCD, isPrime
from sympy.ntheory.modular import crt

ALP = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_ '

# Connection
host = "cha.hackpack.club"
port = 10997
s = remote(host, port)


def get_flag() -> int:

	s.recv()
	s.sendline(b"e")
	s.recv()
	s.sendline(b"f")
	s.recvuntil(b"FLAG: ")

	return int(s.recvuntil(b"\n", drop=True).decode())


def get_encrypt(x: bytes) -> int:

	s.recv()
	s.sendline(b"e")
	s.recv()
	s.sendline(b"m")
	s.recv()
	s.sendline(x.encode())
	s.recvuntil(b"CIP: ")

	return int(s.recvuntil(b"\n", drop=True).decode())


def get_decrypt(x: int) -> int:

	s.recv()
	s.sendline(b"d")
	s.recv()
	s.sendline(str(x).encode())
	s.recvuntil(b"MSG: ")

	return int(s.recvuntil(b"\n", drop=True).decode())


# Get both possible erroneously decrypted flag values
flag_r = []
while len(flag_r) != 2:

	k = get_decrypt(get_flag())

	if k not in flag_r:
		flag_r += [k]

flag_p, flag_q = flag_r


# Try to recover prime factorisation of unknown public modulus using random erroneous decryptions
while True:

	rstr = [''.join(random.sample(ALP, 9)) for _ in range(8)]
	rdec = [get_decrypt(get_encrypt(i)) for i in rstr]

	p = max([GCD(flag_p, i) for i in rdec])
	q = max([GCD(flag_q, i) for i in rdec])

	for k in range(2, 1_000_000):
		while not p % k:
			p //= k
		while not q % k:
			q //= k

	if isPrime(p) and isPrime(q):
		break


# Recover flag
n = p * q
flag_modp = flag_q % flag_p
flag_modq = flag_p % flag_q

flag, pub = crt([p, q], [flag_modp, flag_modq])

FLAG = int(flag).to_bytes(128,'big').lstrip(b"\x00")
print(FLAG)

s.close()

```

<br>

## Exploitation 2: Mathemagics

Whilst writing this write-up, trying to find the mathematics behind my solve through fuzzing, I stumbled upon another solution. A much simpler and more elegant solution, at least in my opinion. Furthermore, unlike the above, this solution is extendable the general case of this scheme with any number of valid Paillier generators. So this would work even without raising the two generators by $p$ and $q$, respectively, as long as we would have access to the modulus that is. But to understand this solution, we should first take a closer mathematical look at how (and why) Paillier exactly works.

For (almost) any element $g$ of the multiplicative group over $N^2$, i.e. $\mathbb{Z}^{\times}\_{N^2}$, there exists a unique pair of $\alpha$ and $\beta$ both in $\mathbb{Z}^{\times}\_{N}$ such that

$$ g = \left( 1 + N \right)^{\alpha} \cdot {\beta}^N \mod{N^2}. $$

_Note that in literature this $\alpha$ is often also referred to as $[[g]]\_{1+N}$._

If we consider that $N$ is the product of two primes $p$ and $q$, then the order of the multiplicative group $\mathbb{Z}^{\times}\_{N}$ is $\lambda \equiv (p - 1)(q - 1)$. Then the order of the extension group $\mathbb{Z}^{*}\_{N^2}$ can be expressed as $p(p - 1)q(q - 1) = \lambda N$ such that for any element $x$ in $\mathbb{Z}^{\times}\_{N^2}$ we have

$$ x^{\lambda N} \equiv 1 \mod{N^2}. $$

With these two things in mind, let's take another look at the Paillier encryption function

$$ E_g(m) = g^m \cdot r^N \mod{N^2}. $$

If we substitute our expression for the generator we get

$$ E_g(m) = (1 + N)^{\alpha m} \cdot \left(r \beta^m \right)^N \mod{N^2} $$

which, when raised to the power of $\lambda$, neatly reduces to

$$ E_g(m)^{\lambda} = (1 + N)^{\alpha m \lambda} \cdot \left(r \beta^m \right)^{\lambda N} = (1 + N)^{\alpha m \lambda} \mod{N^2}. $$

If things were not complicated enough we are pulling another trick out of the box of mathemagics, namely the binomial expansion which states

$$ (a + b)^n = \sum_{k = 0}^n \left( \begin{array}{c} n \\ k \end{array} \right) a^{n - k} b^k = \sum_{k=0}^n \frac{n!}{k!(n-k)!} a^{n-k} b^k.$$

In our case of $1+N$ this becomes

$$ (1 + N)^x = \sum_{k=0}^x \frac{x!}{k!(x-k)!} b^k = 1 + x N + \frac{x(x - 1)}{2} N^2 + \cdots \equiv 1 + x N \mod{N^2}. $$

and hence

$$ E_g(m)^{\lambda} = 1 + \alpha m \lambda N \mod{N^2}. $$

If we now define a function $L(x)$ such that

$$ L(x) = \frac{x - 1}{N} $$

we can suddenly recover a multiplication of our plaintext message from its ciphertext as such

$$ L\left(E_g(m)^{\lambda}\right) = \alpha m \lambda \mod{N}. $$

All that is left is to get rid of the $\alpha \lambda$ factor. Luckily, we can consider the same process applied to just the generator as such

$$ L\left(g^{\lambda}\right) = \alpha \lambda \mod{N} $$

which we will consider part of the private key together with $\lambda$ as

$$ \mu = \left( \frac{g^{\lambda} - 1}{N} \right)^{-1} \mod{N} $$

such that using $(\lambda, \mu)$ we can define a decryption function as follows

$$ D_{\mu}\left( E_g(m) \right) = L\left(E_g(m)^{\lambda}\right) \cdot \mu = \alpha m \lambda \cdot \left( \alpha \lambda \right)^{-1} \equiv m \mod{N}.$$

Okay, that is nice and all but how does this help us solve the challenge? Well, if we look at the source code we see that the server defines $\mu$ using the product of both generators such that

$$ g_p g_q = \left( (1 + N)^{\alpha_p} \cdot \beta_p^N \right) \cdot \left( (1 + N)^{\alpha_q} \cdot \beta_q^N \right) = (1 + N)^{\alpha_p + \alpha_q} \cdot (\beta_p \beta_q)^N \mod{N^2} $$

and hence

$$ \mu_{pq} = L\left( (g_p g_q)^{\lambda} \right)^{-1} = \lambda^{-1} \cdot (\alpha_p + \alpha_q)^{-1} \mod{N}. $$

Noting that the server encrypts using only a single generator chosen at random, using the oracle to decrypt its own encryptions yields two possible results for every message, namely

$$ D_\mu ( E_{g_p}(m) ) = \alpha_p m \lambda \cdot \mu \equiv \frac{m \alpha_p}{\alpha_p + \alpha_q} \mod{N} $$

and

$$ D_\mu ( E_{g_q}(m) ) = \alpha_q m \lambda \cdot \mu \equiv \frac{m \alpha_q}{\alpha_p + \alpha_q} \mod{N}. $$

At this point it should become clear why it is important to realise exactly what is going on mathematically, because from the above one can see that the easiest solution to this challenge is to simply add the two possible decryption together to receive

$$ D_\mu ( E_{g_p}(m) ) + D_\mu ( E_{g_q}(m) ) = m \left( \frac{\alpha_p}{\alpha_p + \alpha_q} + \frac{\alpha_q}{\alpha_p + \alpha_q} \right) \equiv m \mod{N}. $$

And that is all there is to it!

```
|  >>> d
|
|  CIP: int
|   > 1508563904200115758871123802796131115429438395767235725430126225270064282372957049128479635644012811213142369490314897935233275652294261763416004481064188447326073236148653311742052425143236288265177936749008288180113937006340202658082863300158831065652045923763164285919057230737021279194018893688022624554226523789769629254232848594436289449906350000110448115017540045974949762896830310619195985238419666579475506330863125754867956149732992629835941880255568495224694410984036363445992989960710332607569473037419365006813739368290543056231532212913771588886708630967237311172682052100117552040394796866280873765679
|
|  MSG: 45905844988661526884032928400738513306705927861231218001294522400855438524722792393851619453761840219860876660123114644110922039807096859450738049483807543649810847491485034426602667376901594984634678685263129268460095358643633889094961705400995647438786159102442022154070982223649022207415719879059605204266

...

|  >>> d
|
|  CIP: int
|   > 2098633746438645599729573462164668305664484885904775669649183243397895502881073639420742427583467100656944226693791016834699744256713268929878034697880865968300571915694947275656180190215143081806981102009065587386531453723688451350167983787469510632178267434594765828267884946302861785498638239146814064020575884631387607245424778656895381725175222185214145849129314629802628823302932196076386742137133862519700362804627693811034694610424453002836964554578794276592322893521645322144163710212256247256996840666029983993920850326608138772369473801803583443280544885295274339186637363487976430710210975049789781577477
|
|  MSG: 44240939736520918515458405930348658991041520132242878502252380678258540214543421380187389569065208716802317169002785236132654378132435309544523912285269515202255802302862245056980949682061094310900859792370139687682960930662220361591368075405058333965456407491736561584134782826652784008814887012116387083610
```

```py
a = 45905844988661526884032928400738513306705927861231218001294522400855438524722792393851619453761840219860876660123114644110922039807096859450738049483807543649810847491485034426602667376901594984634678685263129268460095358643633889094961705400995647438786159102442022154070982223649022207415719879059605204266
b = 44240939736520918515458405930348658991041520132242878502252380678258540214543421380187389569065208716802317169002785236132654378132435309544523912285269515202255802302862245056980949682061094310900859792370139687682960930662220361591368075405058333965456407491736561584134782826652784008814887012116387083610

((a + b) % N).to_bytes(128,'big').lstrip(b"\x00")
```

Note that this method does require knowledge of the modulus used! So although this is not public for this specific challenge, we can recover the modulus by recovering the individual primes using the method from the first exploitation.

Ta-da!
```
flag{p41_41_41_1_d0nt_th1nk_th1s_1s_wh4t_p41ll13r_1nt3nd3d_3h}
```