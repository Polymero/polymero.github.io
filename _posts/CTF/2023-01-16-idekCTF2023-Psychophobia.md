---
title: idek CTF 2022* - Psychophobia
category: CTF
tags: crypto ECDSA
hidden_tags: my-challenge
excerpt_separator: <!--more-->
---

**Cryptography -- 495 points (11 solves) -- Chall author: Polymero (me)**

_"WANTED: CRYPTO PSYCHIC FOR SINGLE TIME HIRE! (URGENT)<br>
My signatures are all broken and I need somebody to magically fix them ASAP!"_

<!--more-->

Files: [psychophobia.py]()

<br>

I wrote this challenge for [idekctf 2022*](https://ctftime.org/event/1839) as part of the idek team.

## Exploration

Upon connection to the netcat address we are greeted by the following ::

```
|
|                                _           ___
|                               | |         / _ \
|    _  _  _ _   ___   _____   _| |_   ___ | |_) )_  __  __
|   | || || | | | \ \ / / _ \ /     \ / _ \|  _ <| |/  \/ /
|   | \| |/ | |_| |\ v ( (_) | (| |) | (_) ) |_) ) ( ()  <
|    \_   _/ \___/  > < \___/ \_   _/ \___/|  __/ \_)__/\_\
|      | |         / ^ \        | |        | |
|      |_|        /_/ \_\       |_|        |_|
|
|
|
|  ~ Are you the psychic I requested? What can I call you?
|    > Polymero
|
|  ~ Alright, here is the message I will sign for you ::
|    m = "Polymero here, requesting flag for pick-up."
|
|  ~ The following 500 signatures are all broken, please fix them for me to prove your psychic abilities ~
|    If you get more than, say, 72% correct, I will believe you ^w^
|
|  0. Please fix :: (57140182104793165120341096390846762348775117565963962647265137558808797990483, 38141308371739003390540256519247755706096109853308508073576080426130197022484)
|    > (r,s)
```

First, we are prompted to give our name to be prepended to a pre-set message. Then, we are told our task: to fix a majority of 500 allegedly broken signatures. Obviously signatures aren't meant to be broken, so let's check the source code to discover what is going on here. Let's start with the main server loop ::

```py
# Server connection
print(HDR)

print("|\n|  ~ Are you the psychic I requested? What can I call you?")
name = input("|    > ")

msg = f"{name} here, requesting flag for pick-up."
print('|\n|  ~ Alright, here is the message I will sign for you :: ')
print(f'|    m = \"{msg}\"')

ITER = 500
RATE = 0.72
print(f'|\n|  ~ The following {ITER} signatures are all broken, please fix them for me to prove your psychic abilities ~')
print(f'|    If you get more than, say, {round(RATE * 100)}% correct, I will believe you ^w^')


# Server loop
success = 0
for k in range(ITER):

    try:

        d = (2 * randbelow(O) + 1) % O
        Q = d * G
    
        while True:
            sig = ECDSA_sign(msg, d)
            if not ECDSA_verify(msg, Q, sig):
                break
                
        print(f"|\n|  {k}. Please fix :: {sig}")
        
        fix = [int(i.strip()) for i in input("|    > (r,s) ").split(',')]

        if (sig[0] == fix[0]) and ECDSA_verify(msg, Q, fix):
            success += 1

    except KeyboardInterrupt:
        print('\n|')
        break

    except:
        continue
        
print(f"|\n|  ~ You managed to fix a total of {success} signatures!")
        
if success / ITER > RATE:
    print(f"|\n|  ~ You truly are psychic, here {FLAG}")
else:
    print("|\n|  ~ Seems like you are a fraud after all...")
    
print('|\n|')
```

In the loop we can see that for every of the 500 broken signatures we need to fix a new set of private and public points is generated. So we don't have to consider recovering the public point to help us identify valid signatures. We won't be able to recover it. Furthermore, the server will keep generating signatures until it finds a broken one. As the server thus does not temper with the signatures, it must be that the underlying scheme itself is broken and/or incomplete. Finally, in order to correctly fix a signature we must adjust the $s$-component without changing the $r$-component.

Let's take a look at the underlying signature scheme. On the surface it appears to be plain old ECDSA ::

```py
# ECDSA Functions
# https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
def ECDSA_sign(m, priv):
    h = int.from_bytes(sha256(m.encode()).digest(), 'big')
    k = (4 * randbelow(O)) % O
    r = (k * G).x % O
    s = (inverse(k, O) * (h + r * priv)) % O
    return (r, s)
    
def ECDSA_verify(m, pub, sig):
    r, s = sig
    if r > 0 and r < O and s > 0 and s < O:
        h = int.from_bytes(sha256(m.encode()).digest(), 'big')
        u1 = (h * inverse(s, O)) % O
        u2 = (r * inverse(s, O)) % O
        if r == (u1 * G + u2 * pub).x % O:
            return True
    return False
```

Comparing the given functions with the prescribed ECDSA functions, the only discrepancy is the generation of the nonce $k$. We see that it is generated to always be a multiple of four. This holds even with the modulo operation is applied as $O$ itself is a multiple of four too, as seen in the next bit of code ::

```py
# Curve 25519 :: By^2 = x^3 + Ax^2 + x  mod P 
# https://en.wikipedia.org/wiki/Curve25519 
# Curve Parameters
P = 2**255 - 19
A = 486662
B = 1
# Order of the Curve
O = 57896044618658097711785492504343953926856930875039260848015607506283634007912

# ECC Class
class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y
        if not self.is_on_curve():
            raise ValueError("Point NOT on Curve 25519!")
        
    def is_on_curve(self):
        if self.x == 0 and self.y == 1:
            return True
        if ((self.x**3 + A * self.x**2 + self.x) % P) == ((B * self.y**2) % P):
            return True
        return False
    
    @staticmethod
    def lift_x(x):
        y_sqr = ((x**3 + A * x**2 + x) * inverse(B, P)) % P
        v = pow(2 * y_sqr, (P - 5) // 8, P)
        i = (2 * y_sqr * v**2) % P
        return Point(x, (y_sqr * v * (1 - i)) % P)
    
    def __repr__(self):
        return "Point ({}, {}) on Curve 25519".format(self.x, self.y)
    
    def __eq__(self, other):
        return self.x == other.x and self.y == other.y
        
    def __add__(self, other):
        if self == self.__class__(0, 1):
            return other
        if other == self.__class__(0, 1):
            return self
        
        if self.x == other.x and self.y != other.y:
            return self.__class__(0, 1)
        
        if self.x != other.x:
            l = ((other.y - self.y) * inverse(other.x - self.x, P)) % P
        else:
            l = ((3 * self.x**2 + 2 * A * self.x + 1) * inverse(2 * self.y, P)) % P
            
        x3 = (l**2 - A - self.x - other.x) % P
        y3 = (l * (self.x - x3) - self.y) % P
        return self.__class__(x3, y3)
    
    def __rmul__(self, k):
        out = self.__class__(0, 1)
        tmp = self.__class__(self.x, self.y)
        while k:
            if k & 1:
                out += tmp
            tmp += tmp
            k >>= 1
        return out

# Curve25519 Base Point
G = Point.lift_x(9)
```

The above is just a simple Python class providing basic ECC arithmetic through a `Point` object, nothing suspicious as far as I can see. However, checking the used parameters against the parameters mentioned in Curve25519 documentation, we do find a discrepancy. The used order is different from the prescribed order. So let's investigate that ~ !



### Point 1 :: Misbehaviour of `pycryptodome`'s inverse function

The actual order of the used curve turns out to be

$$ O = 2^3 \cdot p, $$

where $p$ is the recommended prime of the curve. So the order of the used group is actually a composite group lending to some interesting behaviour with Python's `pycryptodome` package. It includes an often used `inverse()` function used to calculate [multiplicative inverses](https://en.wikipedia.org/wiki/Modular_multiplicative_inverse). Let's take a quick look at the source code of this function ::

```py
if sys.version_info[:2] >= (3, 8):

    def inverse(u, v):
        """The inverse of :data:`u` *mod* :data:`v`."""

        if v == 0:
            raise ZeroDivisionError("Modulus cannot be zero")
        if v < 0:
            raise ValueError("Modulus cannot be negative")

        return pow(u, -1, v)

else:

    def inverse(u, v):
        """The inverse of :data:`u` *mod* :data:`v`."""

        if v == 0:
            raise ZeroDivisionError("Modulus cannot be zero")
        if v < 0:
            raise ValueError("Modulus cannot be negative")

        u3, v3 = u, v
        u1, v1 = 1, 0
        while v3 > 0:
            q = u3 // v3
            u1, v1 = v1, u1 - v1*q
            u3, v3 = v3, u3 - v3*q
        if u3 != 1:
            raise ValueError("No inverse value can be computed")
        while u1<0:
            u1 = u1 + v
        return u1
```

Behind the scenes, it uses the [extended euclidean algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm) to calculate the multiplicative inverse. The extended euclidean algorithm, with inputs $x$ and $O$, works by finding $y$ and $k$ such that

$$ x y + k O = \mathrm{gcd}\left( x,\ O \right), $$

where $\mathrm{gcd}\left( x,\ O \right)$ is the greatest common divisor of $x$ and $O$. Taking the above modulo $O$ and inserting $y$ to be the output of the inverse function, we find

$$ x \cdot \mathrm{inverse}\left( x,\ O \right) \equiv \mathrm{gcd}\left( x,\ O \right) \mod{O}. $$

Multiplicative inverses technically only exist in groups of prime size, i.e. a prime $O$, such that the gcd of any input $x$ and $O$ will always be 1. In this challenge, however, we have a non-prime order $O$. This means that any input $x$ of the inverse function that is NOT coprime to $O$ will result in an incorrect multiplicative inverse, i.e. $ x \cdot \mathrm{inverse}\left(x,\ O\right) \not\equiv 1 \mod{O} $.

Now we can find a relation between the inverses of $x$ modulo $O$ and modulo $O/8$ if we take the above relation modulo $O/8$ and move the $x$ to the other side (by inversing it modulo $O/8$). We find

<div style="color: #43d8d1;">

<div style="margin: -.75em 0px -1.6em -2em; font-size: 2em; font-weight: bold;">
!
</div>

$$ \mathrm{inverse}\left( x,\ O \right) \equiv \mathrm{gcd}\left( x,\ O \right) \mathrm{inverse}\left( x,\ O/8 \right) \mod{O/8}. $$

</div>

We can use the above relation to start repairing the broken scheme to the ECDSA we know and love ~ !

_Note that the above relation only holds for values of $x$ not divisible by $O/8$, but luckily the probability of encountering such a value is insignificant._



### Point 2 :: Finding a correct signature

Assuming we have a correct signature $\tilde{s}$ such that the ECDSA verification equation holds, we find

$$ \left[k \cdot G\right]_x \equiv \left[ \mathrm{inverse}\left( \tilde{s},\ O \right) \left( h + r d \right) \cdot G \right]_x \mod{O}. $$

Because the base point $G$ still has an order of $O/8$ the above equivalence boils down to

$$ k \equiv \mathrm{inverse}\left( \tilde{s},\ O \right) \left( h + r d \right) \mod{O/8}. $$

Remember that we can swap the inverse modulus using

$$ \mathrm{inverse}\left( \tilde{s},\ O \right) \equiv \mathrm{gcd}\left( \tilde{s},\ O \right) \mathrm{inverse}\left( \tilde{s},\ O/8 \right) \mod{O/8} $$

such that

$$ k \equiv \mathrm{gcd}\left( \tilde{s},\ O \right) \mathrm{inverse}\left( \tilde{s},\ O/8 \right) \left( h + r d \right) \mod{O/8}. $$

Rewriting the above gives us a relation for the correct signature as

$$ \tilde{s} \equiv \mathrm{gcd}\left( \tilde{s},\ O \right) \mathrm{inverse}\left( k,\ O/8 \right) \left( h + r d \right) \mod{O/8} $$

whereas the broken scheme gives us the broken signature

$$ s \equiv \mathrm{inverse}\left( k,\ O \right) \left(h + r d \right) \mod{O}. $$

Taking the broken signature modulo $O/8$ and applying the same inverse modulo swap trick we find

$$ s \equiv \mathrm{gcd}\left( k,\ O \right) \mathrm{inverse}\left( k,\ O/8 \right) \left(h + r d \right) \mod{O/8}. $$

We can now combine the correct and broken signature equations to find the relation between the two to be

$$ \tilde{s} \equiv \mathrm{gcd}\left( \tilde{s},\ O \right) \cdot \mathrm{inverse}\left( \mathrm{gcd}\left( k,\ O \right),\ O/8 \right) \cdot s \mod{O/8}, $$

which we can use to derive the correct signature from the broken one. There is only one hurdle left however, we still have a gcd term containing the correct signature. Although we calculate the correct signature modulo $O/8$, the server accepts anything within modulo $O$. So we can add any multiple of $O/8$ to the signature to force the gcd term between $\tilde{s}$ and $O$ to be $1$ as follows

<div style="color: #43d8d1;">

<div style="margin: -.75em 0px -1.6em -2em; font-size: 2em; font-weight: bold;">
!
</div>

$$ \tilde{s} \equiv \mathrm{inverse}\left( \mathrm{gcd}\left( k,\ O \right),\ O/8 \right) \cdot s + i \cdot O/8 \mod{O}, $$

</div>

where $i$ is either zero or one such that $\mathrm{gcd}\left( \tilde{s},\ O \right) = 1$. Now all that is left is to find out $\mathrm{gcd}\left( k,\ O \right)$ and we are good to go ~ !



### Point 3 :: Finding the multiplicity of $k$

Before we start, let's define the multiplicity of any number $x$ modulo $O$ as

$$ \mu\left( x \right) = x \cdot \mathrm{inverse}\left( x,\ O \right) = \mathrm{gcd}\left( x,\ O \right) $$

such that our goal is to find $\mu\left(k\right)$ in order to repair the broken signature using the previously found

$$ \tilde{s} \equiv \mathrm{inverse}\left( \mu\left(k\right),\ O/8 \right) \cdot s + i \cdot O/8 \mod{O}. $$

Looking at the nonce generation in the ECDSA scheme, the multiplicity of the nonce $k$ can only ever be either $4$ or $8$ with equal probability. So we could guess correctly with a 50% success rate, however the server requires us to have a minimum success rate of 72%. So we will have to find a way to learn something about the multiplicity of $k$ from the broken signature $(r,\ s)$ through

$$ \mu\left( s \right) = \mu\left( k^{-1} \left( h + r d \right) \right). $$

In order to be able to do that, we must first consider the arithmetic of the multiplicity property $\mu$.

The multiplicity of a product $x \cdot y$ will be the product of the individual multiplicities with a maximum of eight, so

$$ \mu\left( x \cdot y \right) = \mathrm{min}\left( 8,\ \mu\left(x\right) \cdot \mu\left(y\right) \right). $$

The multiplicity of a sum $x + y$ is straightforward if $x$ and $y$ have different multiplicities, but a bit more troublesome if they are the same. For the sake of simplicity, let's keep it as

$$ \mu\left( x + y \right) = \left\{ \begin{array}{ll} \ \ \ \in \left\{ \mathrm{min}\left( 8,\ 2^i \cdot \mu\left( x \right) \right) \right\}_{i=1}^3 & \ \ \ \mathrm{if}\ \mu\left( x \right) = \mu\left( y \right) \\ \ \ \ \mathrm{min}\left( \mu\left( x \right),\ \mu\left( y \right) \right) & \ \ \ \mathrm{else} \end{array} \right. $$

As for the inverse operation, if $x$ does NOT have maximum multiplicity, its inverse will have minimum multiplicity. In any other case, it can be any multiplicity, so

$$ \mu\left( x^{-1} \right) = \left\{ \begin{array}{ll} \ \ \ 1 & \ \ \ \mathrm{if}\ \mu\left(x\right) \neq 8 \\ \ \ \ \in \left\{ 1,\ 2,\ 4,\ 8 \right\} & \ \ \ \mathrm{else} \end{array} \right. $$

Finally, it should be noted that any ECC operation will remove any statistical correlation between the multiplicities, i.e. in the operation

$$ r = \left[ k \cdot G \right]_x $$

there is no correlation between the multiplicity of $k$ and the multiplicity of $r$. In other words, the multiplicity of $r$ can be regarded as random and will not contain any information on the multiplicity of $k$.

With these rules we can take a look at the signature equation 

$$ s = k^{-1} \left( h + r d \right) \mod{O} $$

to see how the multiplicities propagate through it. Let's take it step by step,

$$ \mu\left( r d \right) = \mathrm{min}\left( 8,\ \mu\left(r\right),\ \mu\left(d\right) \right) $$

and

$$ \mu\left( h + r d \right) = \left\{ \begin{array}{ll} \ \ \ \in \{ \mathrm{min}\left( 8,\ 2^i \cdot \mu\left( h \right) \right) \}_{i=1}^{3} & \ \ \ \mathrm{if}\ \mu\left( h \right) = \mu\left( r d \right) \\ \ \ \ \mathrm{min}\left( \mu\left( h \right),\ \mu\left( r d \right) \right) & \ \ \ \mathrm{else} \end{array} \right. $$

such that

$$ \mu\left( s \right) = \mathrm{min}\left( 8,\ \mu\left( k^{-1} \right) \cdot \mu\left( h + r d \right) \right). $$

The final thing to consider is that for each randomly generated number $x$ we can easily determine the probability distribution for its multiplicity to be

$$ \mu\left(x\right) \in \left\{ 1\ (50\%),\ 2\ (25\%),\ 4\ (12.5\%),\ 8\ (12.5\%) \right\} $$

and consequently for its inverse

$$ \mu\left(x^{-1}\right) \in \left\{ 1\ (93.75\%),\ 2\ (3.125\%),\ 4\ (1.5625\%),\ 8\ (1.5625\%) \right\}. $$

As you can see, analysing the above equations straight up for all possible combinations of multiplicities becomes a bit of a probabilistic mess. Luckily for us, we can infer some additional information from the server source code that will help us simplify these equations, after which we can determine our optimal signature repairing strategy. Time to create the exploit ~ !


<br>

To summarise, we have made the following observations ::
<table style="border: none; margin-left: 20px; margin-top: -.5em">
    <tr>
        <td style="background-color: #43d8d1; border: none; max-width: 5px;"> </td>
        <td style="border: none; padding-left: 20px; min-width: 25px; vertical-align: top;"> <b>1.</b> </td>
        <td style="border: none; padding-left: 0px;"> We are dealing with a broken ECDSA scheme due to an incorrect modulus. In order to solve this challenge, we need to repair enough broken signatures; </td>
    </tr>
    <tr>
        <td style="background-color: #43d8d1; border: none; max-width: 5px;"> </td>
        <td style="border: none; padding-left: 20px; min-width: 25px; vertical-align: top;"> <b>2.</b> </td>
        <td style="border: none; padding-left: 0px;"> The inverse function of Python's <i>pycryptodome</i> package misbehaves, mathematically speaking, in groups of non-prime order. More specifically, we find that $x \cdot \mathrm{inverse}\left(x,\ O\right) \equiv \mathrm{gcd}\left(x,\ O\right) \mod{O}$; </td>
    </tr>
    <tr>
        <td style="background-color: #43d8d1; border: none; max-width: 5px;"> </td>
        <td style="border: none; padding-left: 20px; min-width: 25px; vertical-align: top;"> <b>3.</b> </td>
        <td style="border: none; padding-left: 0px;"> We can easily repair a broken signature with knowledge of the greatest common divisor between the nonce $k$ and the used modulus $O$. We refer to this as the multiplicity of $k$; </td>
    </tr>
    <tr>
        <td style="background-color: #43d8d1; border: none; max-width: 5px;"> </td>
        <td style="border: none; padding-left: 20px; min-width: 25px; vertical-align: top;"> <b>4.</b> </td>
        <td style="border: none; padding-left: 0px;"> Deriving the arithmetic of the multiplicity property allows us to learn something on the multiplicity of $k$ from just the multiplicities of the broken signature $(r,\ s)$.</td>
    </tr>
</table>


<br>

## Exploitation

Let's start by simplifying the multiplicity equations we found earlier using some additional information found in the source code. More specifically, we find that both the private key $d$ and the nonce $k$ are generated in a slightly altered way. For the private key we find

```py
d = (2 * randbelow(O) + 1) % O
```

such that

$$ \mu\left(d\right) = 1 $$

and for the nonce we have

```py
k = (4 * randbelow(O)) % O
```

such that

$$ \mu\left(k\right) \in \left\{ 4\ (50\%),\ 8\ (50\%) \right\}. $$

Now we shall revisit our steps and simplify by substituting the above information. First we have

$$ \mu\left( r d \right) = \mathrm{min}\left( 8,\ \mu\left( r \right) \cdot \mu\left( d \right) \right) = \mathrm{min}\left( 8,\ \mu\left( r \right) \right) = \mu\left( r \right), $$

followed by

$$ \mu\left( h + r d \right) = \left\{ \begin{array}{ll} \ \ \ \in \{ \mathrm{min}\left( 8,\ 2^i \cdot \mu\left( h \right) \right) \}_{i=1}^{3} & \ \ \ \mathrm{if}\ \mu\left( h \right) = \mu\left( r \right) \\ \ \ \ \mathrm{min}\left( \mu\left( h \right),\ \mu\left( r \right) \right) & \ \ \ \mathrm{else} \end{array} \right. . $$

Now, we can improve our situation by considering we have control over the multiplicity of the hash value $h$ as well. By finding a username that results in a multiplicity for $h$ of eight, we can simplify the above further to

$$ \mu\left( h + r d \right) = \left\{ \begin{array}{ll} \ \ \ \in \{ \mathrm{min}\left( 8,\ 2^i \cdot 8 \right) \}_{i=1}^{3} & \ \ \ \mathrm{if}\ \mu\left( r \right) = 8 \\ \ \ \ \mathrm{min}\left( 8,\ \mu\left( r \right) \right) & \ \ \ \mathrm{else} \end{array} \right. = \left\{ \begin{array}{ll} \ \ \ 8 & \ \ \ \mathrm{if}\ \mu\left( r \right) = 8 \\ \ \ \ \mathrm{min}\left( 8,\ \mu\left( r \right) \right) & \ \ \ \mathrm{else} \end{array} \right. = \mu\left( r \right). $$

We end up with the much more manageable

$$ \mu\left( s \right) = \mathrm{min}\left( 8,\ \mu\left( k^{-1} \right) \cdot \mu\left( r \right) \right). $$

Taking a look at this we should realise that we can only learn some limited information about $\mu\left( k^{-1} \right)$. The most crucial is that $\mu\left( k^{-1} \right) \neq 1$ whenever $\mu\left(s\right) \neq \mu\left(r\right)$ and $\mu\left(r\right) \neq 8$. If $\mu\left(r\right) = 8$ we will not be able to learn anything about $\mu\left( k^{-1} \right)$, sadly. To further analyse this, let us consider the two possible multiplicities for $k$ and its inverse separately:

$$ \mu\left( k \right) = 4\ \ \ \rightarrow\ \ \ \mu\left( k^{-1} \right) = 1\ (100\%) $$

and

$$ \mu\left( k \right) = 8\ \ \ \rightarrow\ \ \ \mu\left( k^{-1} \right) \in \left\{ 1\ (50\%),\ 2\ (25\%),\ 4\ (12.5\%),\ 8\ (12.5\%) \right\}. $$

We can turn this around to find

$$ \mu\left( k^{-1} \right) \neq 1\ \ \ \rightarrow\ \ \ \mu\left(k\right) = 8\ (100\%) $$

and

$$ \mu\left( k^{-1} \right) = 1\ \ \ \rightarrow\ \ \ \mu\left( k \right) \in \left\{ 4\ (66.7\%),\ 8\ (33.3\%) \right\}. $$

We can now set up a strategy to find our best guesses for $\mu\left(k\right)$ based only on $\mu\left(r\right)$ and $\mu\left(s\right)$:

$$ \begin{array}{l} \mathrm{if}\ \mu\left(r\right) \neq 8:\ (87.5\%) \\[.5em] \cdots\ \mathrm{if}\ \mu\left(r\right) = \mu\left(s\right) \rightarrow \mu\left(k\right) = 1:\ (75\%) \\[.5em] \cdots \cdots\ \mu\left(k\right) \in \left\{ 4\ (66.7\%),\ 8\ (33.3\%) \right\} \\[.5em] \cdots\ \mathrm{else} \rightarrow \mu\left(k^{-1}\right) \neq 1:\ (25\%) \\[.5em] \cdots \cdots\ \mu\left( k \right) = 8\ (100\%) \\[.5em] \mathrm{else}:\ (12.5\%) \\[.5em] \cdots\ \mu\left(k\right) \in \left\{ 4\ (50\%),\ 8\ (50\%) \right\} \end{array} $$

I have added the (relative) probability of each case in parentheses so we can calculate the success rate of our strategy to be

$$ 87.5\% \cdot \left( 75\% \cdot 66.7\% + 25\% \cdot 100\% \right) + 12.5\% \cdot 50\% = \frac{7}{8} \left( \frac{3}{4} \cdot \frac{2}{3} + \frac{1}{4} \right) + \frac{1}{8} \cdot \frac{1}{2} = \frac{23}{32} = 71.875\%. $$

With a little bit of luck we should be able to surpass the required $72\%$ success rate just fine ~ !


<br>

To summarise, our exploit consists of the following steps ::
<table style="border: none; margin-left: 20px; margin-top: -.5em">
    <tr>
        <td style="background-color: #43d8d1; border: none; max-width: 5px;"> </td>
        <td style="border: none; padding-left: 20px; min-width: 25px; vertical-align: top;"> <b>1.</b> </td>
        <td style="border: none; padding-left: 0px;"> Send any username such that the used message within the signatures has maximum multiplicity, i.e. $\mu\left(h\right) = 8$; </td>
    </tr>
    <tr>
        <td style="background-color: #43d8d1; border: none; max-width: 5px;"> </td>
        <td style="border: none; padding-left: 20px; min-width: 25px; vertical-align: top;"> <b>2.</b> </td>
        <td style="border: none; padding-left: 0px;"> For each broken signature, using our derived strategy, find the best guess for $\mu\left(k\right)$ from calculating $\mu\left(r\right)$ and $\mu\left(s\right)$; </td>
    </tr>
    <tr>
        <td style="background-color: #43d8d1; border: none; max-width: 5px;"> </td>
        <td style="border: none; padding-left: 20px; min-width: 25px; vertical-align: top;"> <b>3.</b> </td>
        <td style="border: none; padding-left: 0px;"> Fix the broken signature by multiplying the $s$-component by our the inverse of our best guess for $\mu\left(k\right)$ and add $O/8$ if necessary, such that $\mu\left(\tilde{s}\right) = 1$; </td>
    </tr>
    <tr>
        <td style="background-color: #43d8d1; border: none; max-width: 5px;"> </td>
        <td style="border: none; padding-left: 20px; min-width: 25px; vertical-align: top;"> <b>4.</b> </td>
        <td style="border: none; padding-left: 0px;"> Repeat the process with a fresh server connection until we satisfy the $72\%$ success rate. </td>
    </tr>
</table>

<br>


### Example Solve Script

```py
#!/usr/bin/env python3
#
# Polymero
#
# Solve script for [Psychophobia] from [idekctf 2022*]
#

# Imports
from pwn import *
from time import time
from Crypto.Util.number import inverse, GCD


# Globals
O = 57896044618658097711785492504343953926856930875039260848015607506283634007912

# Functions
def mu(x):
    return (x * inverse(x, O)) % O

while True:

    # Server connection
    # s = connect('psychophobia.chal.idek.team', 1337)
    S = process(['python3', 'psychophobia.py'])

    # 1. Send username such that hash value has multiplicity of eight
    S.recv()
    S.sendline(b'Polymeme')

    t0 = time()
    for k in range(500):
        t1 = (time() - t0) / (k + 1) * (500 - k - 1)
        print('|  ~ {}/500 (ETA {}m {}s)   '.format(k+1, int(t1)//60, int(t1)%60), end='\r', flush=True)

        # 2. Receive broken signature (r, s)
        S.recvuntil(b':: (')
        r, s = [int(i) for i in S.recvuntil(b')\n', drop=True).decode().split(', ')]
        S.recv()

        # 3. Find best guess for multiplicity of nonce 'k'
        mr, ms = [mu(i) for i in [r, s]]

        if mr == 8:
            mk = 4
        elif mr == ms:
            mk = 4
        else:
            mk = 8

        # 4. Fix the broken signature using mu(k) and add O//8 if necessary
        s_fix = (inverse(mk, O//8) * s) % (O//8)
        if not s_fix & 1:
            s_fix += O//8

        # 5. Send fixed signature
        S.sendline(', '.join([str(r), str(s_fix)]).encode())

    # 6. Filter for the flag
    result = S.recv()
    print(result)
    
    if b'idek' in result:
        break
```