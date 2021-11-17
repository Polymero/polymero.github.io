---
title: K3RN3LCTF 2021 - Poly Expo go BRRRRR
category: CTF
tags: misc maze Dijkstra
hidden_tags: my-challenge
excerpt_separator: <!--more-->
---

Cryptography -- 494 pts (9 solves) -- Chall author: Polymero (me)

_"I'm going to say this again: I did not have sexual relations with that polynomial, Miss Polinsky."_

<!--more-->

Files: [polyexpogobrrrrr.sage](https://github.com/Kasimir123/K3RN3LCTF-2021/blob/main/downloadable/Poly-Expo-go-BRRRRR/polyexpogobrrrrr.sage)

This challenge was part of our very first CTF, [K3RN3LCTF 2021](https://ctftime.org/event/1438).


## Exploration

We are given a short little script in Sage together with its output. Let us take a look.

```py
from Crypto.Util.number import getPrime

with open('flag.txt','rb') as f:
    FLAG = f.read()
    f.close()

n = getPrime(512) * getPrime(512)
e = 0x10001

P.<x> = PolynomialRing(GF(2))
N = sum([int(j)*x**i for i,j in enumerate('{:0{bl}b}'.format(n,bl=n.bit_length()))])
Q.<x> = P.quotient(N)

def encrypt(msg):
    if type(msg) == bytes:
        msg = int.from_bytes(msg,'big')
    msg = sum([int(j)*x**i for i,j in enumerate('{:0{bl}b}'.format(msg,bl=n.bit_length()-1))])
    cip = Q(msg)**e
    cip = int(''.join([str(i) for i in list(cip)]),2)
    return cip

c = encrypt(FLAG)

print('n =',n)
print('e =',e)
print('c =',c)

assert solve()
```

It starts off with common RSA parameter generation for $n$ and $e$, but then creates a quotient polynomial ring mod a polynomial over GF(2) created using the bits of the RSA modulus as coefficients. To encrypt the flag, the script first converts it to a polynomial and then raises it to the power $e$ over the previously created quotient ring. Finally, it turns the resulting polynomial back into an integer and prints it. We are given the following output.

```
n = 119688104315557021890936576297322528053073582644938225605833562855944546643311189725353580415278613605803528999976536949698525581164157480218289586687945087549976509446759942778609918817975151644563678567137671925049937536315926169828583738712154203276012477308556625213229949900385215601055758028238785190211
e = 65537
c = 59180475538014020769986137847579404920412136380976726613826924727288568855214946199702335444771145318394201684142700441287649150098774979773106915707593238156979003572684188994666984941867671144226245449471326607224512384706414018555885923177955268177207582929765645093722741174664225408159262482249199006862
```

In other words, it seems we are dealing with textbook RSA but over a polynomial ring. That must be just as secure as the integer version right?


## Exploitation

In short, no. In more detail, it comes down between an important difference between integer factorisation and polynomial factorisation. Textbook RSA is done over the integers and relies on the difficulty of integer factorisation. This polynomial version of textbook RSA is done over a polynomial ring and would therefore rely on the difficulty of polynomial factorisation. As it turns out, polynomials can be much more efficiently factorised than integers through a combination of Yun's algorithm and Cantor-Zassenhaus' algorithm. So let's try to straight up factor the mod polynomial $N$.

_It is also worth noting that converting an integer composed of two large primes to a polynomial does not ensure the polynomial is only composed of two large irreducible polynomials. But even if this were the case, they can still be efficiently factorised!_

```py
for i in list(N.factor()):
    print('{} : {}\n'.format(i[1],i[0]))
```

```
5 : x + 1

1 : x^3 + x + 1

1 : x^7 + x + 1

1 : x^24 + x^21 + x^20 + x^19 + x^18 + x^17 + x^16 + x^15 + x^14 + x^13 + x^9 + x^7 + x^5 + x + 1

1 : x^85 + x^84 + x^83 + x^82 + x^81 + x^80 + x^79 + x^76 + x^70 + x^67 + x^62 + x^59 + x^56 + x^53 + x^52 + x^51 + x^50 + x^49 + x^46 + x^43 + x^42 + x^38 + x^36 + x^29 + x^27 + x^26 + x^25 + x^24 + x^22 + x^20 + x^17 + x^13 + x^11 + x^9 + x^6 + x^4 + x^2 + x + 1

1 : x^257 + x^256 + x^255 + x^253 + x^252 + x^251 + x^250 + x^249 + x^246 + x^245 + x^242 + x^238 + x^237 + x^236 + x^232 + x^231 + x^230 + x^228 + x^226 + x^225 + x^223 + x^221 + x^220 + x^216 + x^211 + x^208 + x^205 + x^204 + x^203 + x^201 + x^200 + x^199 + x^198 + x^197 + x^193 + x^191 + x^189 + x^188 + x^186 + x^184 + x^181 + x^178 + x^175 + x^174 + x^172 + x^170 + x^167 + x^166 + x^163 + x^160 + x^159 + x^158 + x^157 + x^156 + x^154 + x^153 + x^152 + x^150 + x^149 + x^147 + x^146 + x^145 + x^143 + x^142 + x^141 + x^135 + x^133 + x^131 + x^130 + x^128 + x^127 + x^126 + x^125 + x^123 + x^122 + x^120 + x^118 + x^117 + x^112 + x^111 + x^110 + x^109 + x^108 + x^107 + x^106 + x^104 + x^103 + x^102 + x^101 + x^100 + x^99 + x^97 + x^93 + x^90 + x^89 + x^86 + x^85 + x^83 + x^81 + x^80 + x^79 + x^76 + x^73 + x^70 + x^68 + x^66 + x^65 + x^61 + x^60 + x^59 + x^57 + x^54 + x^53 + x^50 + x^49 + x^48 + x^47 + x^45 + x^44 + x^43 + x^42 + x^38 + x^36 + x^35 + x^33 + x^31 + x^26 + x^24 + x^23 + x^19 + x^18 + x^16 + x^15 + x^14 + x^11 + x^9 + x^3 + x^2 + 1

1 : x^642 + x^639 + x^638 + x^636 + x^634 + x^633 + x^631 + x^627 + x^626 + x^623 + x^618 + x^617 + x^615 + x^614 + x^613 + x^610 + x^606 + x^605 + x^602 + x^600 + x^599 + x^598 + x^597 + x^595 + x^592 + x^590 + x^589 + x^587 + x^586 + x^585 + x^583 + x^579 + x^576 + x^574 + x^573 + x^571 + x^569 + x^568 + x^567 + x^565 + x^564 + x^563 + x^561 + x^559 + x^557 + x^554 + x^552 + x^550 + x^549 + x^545 + x^543 + x^542 + x^539 + x^534 + x^533 + x^532 + x^529 + x^528 + x^525 + x^524 + x^523 + x^522 + x^521 + x^520 + x^518 + x^516 + x^513 + x^511 + x^510 + x^508 + x^505 + x^504 + x^501 + x^500 + x^499 + x^496 + x^495 + x^494 + x^493 + x^492 + x^491 + x^488 + x^487 + x^483 + x^480 + x^479 + x^474 + x^473 + x^472 + x^471 + x^469 + x^467 + x^464 + x^461 + x^459 + x^458 + x^457 + x^455 + x^453 + x^452 + x^450 + x^447 + x^445 + x^443 + x^441 + x^440 + x^439 + x^438 + x^437 + x^435 + x^431 + x^426 + x^425 + x^423 + x^419 + x^417 + x^415 + x^409 + x^408 + x^407 + x^405 + x^402 + x^400 + x^399 + x^397 + x^396 + x^395 + x^394 + x^392 + x^391 + x^390 + x^388 + x^386 + x^385 + x^382 + x^380 + x^378 + x^375 + x^372 + x^371 + x^369 + x^368 + x^367 + x^364 + x^363 + x^358 + x^356 + x^352 + x^350 + x^348 + x^347 + x^344 + x^343 + x^342 + x^340 + x^339 + x^338 + x^335 + x^334 + x^332 + x^330 + x^328 + x^325 + x^322 + x^320 + x^315 + x^313 + x^311 + x^308 + x^304 + x^303 + x^301 + x^297 + x^295 + x^292 + x^291 + x^285 + x^284 + x^282 + x^279 + x^278 + x^277 + x^275 + x^274 + x^273 + x^272 + x^271 + x^267 + x^265 + x^261 + x^259 + x^256 + x^254 + x^249 + x^243 + x^242 + x^240 + x^237 + x^233 + x^232 + x^231 + x^230 + x^227 + x^226 + x^225 + x^224 + x^222 + x^221 + x^214 + x^210 + x^208 + x^207 + x^206 + x^203 + x^201 + x^198 + x^197 + x^195 + x^194 + x^193 + x^191 + x^190 + x^188 + x^187 + x^185 + x^184 + x^182 + x^181 + x^180 + x^176 + x^171 + x^168 + x^167 + x^166 + x^164 + x^162 + x^161 + x^160 + x^159 + x^158 + x^157 + x^156 + x^153 + x^152 + x^151 + x^150 + x^149 + x^147 + x^146 + x^139 + x^138 + x^137 + x^136 + x^135 + x^134 + x^132 + x^130 + x^127 + x^125 + x^122 + x^116 + x^115 + x^114 + x^111 + x^109 + x^106 + x^103 + x^102 + x^98 + x^97 + x^96 + x^95 + x^92 + x^91 + x^87 + x^85 + x^83 + x^81 + x^79 + x^78 + x^77 + x^76 + x^73 + x^68 + x^67 + x^66 + x^65 + x^64 + x^54 + x^51 + x^48 + x^47 + x^45 + x^42 + x^40 + x^38 + x^37 + x^36 + x^22 + x^21 + x^20 + x^19 + x^18 + x^17 + x^15 + x^12 + x^10 + x^9 + x^6 + x^5 + x^3 + x + 1
```

Now that we have found the irreducible polynomials, we can decrypt over each individual ring and then put them together using the chinese remainder theorem. However that sounds like too much effort to me, so let's take another approach. Instead, we can use the standard RSA method of computing the private exponent using the total order of the modulus polynomial. We can determine the total order by adding the order of the individual factors taking into account their multiplicities, similar to what we would do for textbook RSA over the integers. Then we take the modular inverse of our encryption exponent $e$ with respect to the total order to generate our decryption exponent $d$. Finally, we can decrypt our ciphertext by turning it into a polynomial ourselves, raising it to the power of $d$ and turning it back into an integer. See script below. 

```py
def solve(n, e, c):

	# Setup our polynomial and quotient ring
    P.<x> = PolynomialRing(GF(2))
    N = sum([int(j)*x**i for i,j in enumerate('{:0{bl}b}'.format(n,bl=int(n).bit_length()))])
    Q.<x> = P.quotient(N)

    # Large polynomials are more easily factored than large integers
    facs = list(N.factor())

    # Get order of each factor
    ords = [P.quotient(i[0]).order() for i in facs]

    # Get multiplicity of each factor
    muls = [i[1] for i in facs]
    
    # Create decryption exponent
    phi = 1
    for i in range(len(facs)):
        phi *= (ords[i] - 1) * power(ords[i], muls[i] - 1)
    d = inverse_mod(e,phi)

    # Turn encryption into polynomial
    enc = sum([int(j)*x**i for i,j in enumerate('{:0{bl}b}'.format(c<<1,bl=n.bit_length()))])

    # Return decrypted byte flag
    return long_to_bytes(int(''.join([str(i) for i in list(Q(enc)^d)]),2))
```

Ta-da!

```
flag{bRrRrRrRr_Yun_C4nt0r_4nd_Z4ss3nh4us_34t_p0lyn0m14ls_f0r_br34kf4st_bRrRrRrRr}
```

-----
Thanks for reading! <3

~ Polymero
