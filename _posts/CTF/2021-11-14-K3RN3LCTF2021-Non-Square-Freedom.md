---
title: K3RN3LCTF 2021 - Non-Square Freedom (1 and 2)
category: CTF
tags: crypto RSA
hidden_tags: my-challenge
excerpt_separator: <!--more-->
---

Cryptography -- 465 pts (21 solves) and 490 pts (11 solves) -- Chall author: Polymero (me)

_"What can I say, I just like squares."_

<!--more-->

Files for 1: [nonsquarefreedom_easy.py](https://github.com/Kasimir123/K3RN3LCTF-2021/blob/main/downloadable/Non-Square-Freedom-1/nonsquarefreedom_easy.py)

Files for 2: [nonsquarefreedom_hard.py](https://github.com/Kasimir123/K3RN3LCTF-2021/blob/main/downloadable/Non-Square-Freedom-2/nonsquarefreedom_hard.py)

This challenge was part of our very first CTF, [K3RN3LCTF 2021](https://ctftime.org/event/1438).


## Exploration

On the surface players are presented with the output of some multi-prime RSA encryption.

```
# EASY
#----------------------------------------------------
#                       Output
#----------------------------------------------------
# M < N    : True
# M < P**8 : True
# M < Q*R  : True
#
# n = 68410735253478047532669195609897926895002715632943461448660159313126496660033080937734557748701577020593482441014012783126085444004682764336220752851098517881202476417639649807333810261708210761333918442034275018088771547499619393557995773550772279857842207065696251926349053195423917250334982174308578108707
# e = 65537
# c = 4776006201999857533937746330553026200220638488579394063956998522022062232921285860886801454955588545654394710104334517021340109545003304904641820637316671869512340501549190724859489875329025743780939742424765825407663239591228764211985406490810832049380427145964590612241379808722737688823830921988891019862
#
# D(C) = 58324527381741086207181449678831242444903897671571344216578285287377618832939516678686212825798172668450906644065483369735063383237979049248667084304630968896854046853486000780081390375682767386163384705607552367796490630893227401487357088304270489873369870382871693215188248166759293149916320915248800905458
#

# HARD
#----------------------------------------------------
#                       Output
#----------------------------------------------------
# M < N    : True
# M < P**8 : False
# M < Q*R  : False
#
# n = 4575829597858799419341358254099339062313194353857263690760863923804026600749439184775330442983454068796504813860650114437843860719657927599984274468923063336628389598105328878858384622054430674402403839270645603835832233587365339188250968852039492773992195746788936530150586208030748428985765114934032164269
# e = 65537
# c = 3704469765736808327150183385593470573779546046957340283734683699989596150060156191944264331756779846153685794890755215418575392561313787296737832446637414912621671452320923899214051811828161280972929008735017749715723409961801337999696046444992388364931185375322735030067979993625538441901181791804857243883
#
# D(C) = 3808886831337667850991686443291003571625029443294253379657761379567000961486361549315830406668585035951634722009857007794996473504806639953404195426190048807121464518905063268090265455608765879999313973046043954153720466695054029750321369389019308205783219802884185884371070551851548317370008588012333323252
#
```

However, it seems we are given some additional hints: some clues regarding the size of the plaintext message, and even the decrypted ciphertext! Although something seems to be wrong with it... Let us take a look at the provided source code.

```py
# Imports
from Crypto.Util.number import getPrime
import os

# Key gen
P = getPrime(512//8)
Q = getPrime(256)
R = getPrime(256)
N = P**8 * Q * R
E = 0x10001

def pad_easy(m):
    m <<= (512//8)
    m += (-(m % (P**2)) % P)
    return m

def pad_hard(m):
    m <<= (512//2)
    m += int.from_bytes(os.urandom(256//8),'big')
    m += (-(m % (P**2)) % (P**2))
    m += (-(m % (P**3)) % (P**3))
    return m

# Pad FLAG
M = pad_hard(int.from_bytes(b'flag{"""REDACTED"""}','big')) # <--- pad_easy for EASY, pad_hard for HARD
print('M < N    :',M < N)
print('M < P**8 :',M < (P**8))
print('M < Q*R  :',M < (Q*R))

# Encrypt FLAG
C = pow(M,E,N)
print('\nn =',N)
print('e =',E)
print('c =',C)

# Hint
F = P**7 * (P-1) * (Q-1) * (R-1)
D = inverse(E,F)
print('\nD(C) =',pow(C,D,N))
```

_The following is not strictly necessary to recover either of the 2 flags, but provides interesting background into this challenge and explains why the provided decryption is faulty._

As it turns out, a composite modulus that is NOT square-free will result in some interesting RSA behaviour. More specifically, a non-square-free modulus implies that for at least one of the factors we have

$$ N = 0 \mod{P^s} $$

for some $s >= 2$. If this is the case then the textbook RSA equation breaks such that

$$ m^{e^d} \neq m \mod{N} \forall m \in \left\{ m \mod{P^r} \in \left\{ k P\ |\ \forall k \in (1, ..., P-1) \right\}\ |\ \forall r \in (2, ..., s) \right\}. $$

This implies that a total fraction of 

$$ \sum_{r=2}^{s} \frac{p-1}{p^r} $$

of the messages will be invalid. We can see that both padding functions will make sure our message belongs to this invalid group, and as a hint we are given the faulty decryption of the ciphertext.

These or some of the **key observations**:

- The modulus contains a small prime raised to a power, such that we can recover P, and Q\*R with standard factorisation techniques.
- The modulus is non-square-free and hence contains messages that are invalid using the textbook RSA equation.
- The used padding schemes make sure the flags belong to this invalid group.
- As a hint, we are given the faulty decryption of the encrypted flag.


## Exploitation


**Non-Square-Freedom 1**

Although the faulty decryption seems to be useless, in this case it actually contains the full message. The only thing we have to do is to recover Q\*R such that we can simply take the mod of the faulty decryption and find our flag! Because the size of P is only 64 bits we can simply using any standard factorisation method (including online programs) to recover P and Q\*R and we are set to go.

```py
# Solution Easy!
win = long_to_bytes(DC_easy % (Q*R))
print(win)
```

Ta-da!

```
flag{y34_th1s_1s_n0t_h0w_mult1pr1m3_RS4_w0rks_buddy}
```


**Non-Square-Freedom 2**

This time we can apply a similar technique but because $M > Q R$ we need to use the Chinese Remainder Theorem to recover the full original message. In short, we have

$$ M = 0 \mod{P^3} $$

$$ M = \mathrm{hint} \mod{Q R} $$

such that we can use the extended euclidean algorithm to recover $a$ and $b$ in

$$ a P^3 + b Q R = 1. $$

Finally, we can recover the full message as

$$ M = 0 \cdot b Q R + \mathrm{hint} \cdot a P^3 = \mathrm{hint} \cdot a P^3 \mod{Q R P^3}. $$

```py
# Solution Hard!
def gcdExtended(a, b): 
    if a == 0 :  
        return b,0,1
    gcd,x1,y1 = gcdExtended(b%a, a) 
    x = y1 - (b//a) * x1 
    y = x1 
    return gcd,x,y

win = long_to_bytes(((DC_hard % (Q*R)) * P**2 * gcdExtended(P**2,Q*R)[1]) % (Q*R*P**2))
print(win)
```

Ta-da!

```
flag{1_th1nk_1_m1ght_b3_squ4r3_fr33_1nt0l3r4nt}
```

-----
Thanks for reading! <3

~ Polymero