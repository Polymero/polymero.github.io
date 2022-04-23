---
title: HackPack CTF 2022 - Repeating Offense
category: CTF
tags: crypto RSA Paillier homomorphism
hidden_tags: my-challenge
excerpt_separator: <!--more-->
---

Cryptography -- 443 pts (20 solves) -- Chall author: Polymero (me)

_One-time oracles using RSA or Paillier are not a great idea due to those slippery mathemagicians... I would like to see them slip their way through RSA AND Paillier! After all, you cannot rob two banks at the same time. ... What?_

<!--more-->

nc cha.hackpack.club 10996 or 20996

Files: [repeatingoffense.py](https://github.com/hackpack-ncsu/CTF-2022/blob/main/crypto/repeatingoffense/repeatingoffense.py)

![](/assets/ctf/RepeatingOffense_chall.png)

This challenge was part of my guest appearance on [HackPack CTF 2022](https://ctftime.org/event/1620).

<br>

## Exploration

As always with netcat-based challenges, let's connect to see what we are dealing with.

```
|     _______    _______    _______    _______       __  ___________  __    _____  ___    _______
|    /"      \  /"     "|  |   __ "\  /"     "|     /""\("     _   ")|" \  (\"   \|"  \  /" _   "|
|   |:        |(: ______)  (. |__) :)(: ______)    /    \)__/  \\__/ ||  | |.\\   \    |(: ( \___)
|   |_____/   ) \/    |    |:  ____/  \/    |     /' /\  \  \\_ /    |:  | |: \.   \\  | \/ \
|    //      /  // ___)_   (|  /      // ___)_   //  __'  \ |.  |    |.  | |.  \    \. | //  \ ___
|   |:  __   \ (:      "| /|__/ \    (:      "| /   /  \\  \\:  |    /\  |\|    \    \ |(:   _(  _|
|   |__|  \___) \_______)(_______)    \_______)(___/    \___)\__|   (__\_|_)\___|\____\) \_______)
|                ______    _______   _______   _______  _____  ___    ________  _______
|               /    " \  /"     "| /"     "| /"     "|(\"   \|"  \  /"       )/"     "|
|              // ____  \(: ______)(: ______)(: ______)|.\\   \    |(:   \___/(: ______)
|             /  /    ) :)\/    |   \/    |   \/    |  |: \.   \\  | \___  \   \/    |
|            (: (____/ // // ___)   // ___)   // ___)_ |.  \    \. |  __/  \\  // ___)_
|             \        / (:  (     (:  (     (:      "||    \    \ | /" \   :)(:      "|
|              \"_____/   \__/      \__/      \_______) \___|\____\)(_______/  \_______)
|
|
|  STAGE 1 :: RSA-then-Paillier
|
|   N: 52466172930101150662452273574587782205200219539613514933212280147819278207177945619362319360084443009840711892084888765387235617342932272699612791229032725512962412833860843081032511628117684241746369412143042706896313415454727622872601958285529584661307629693457797669457828143933554103910237046393359508533
|   G: 271267186001714196255000028312140764295982489159261925880312800451562582620532474661053679301331215337820452659304807476832043735514944656712376898552837846167342398362493442350572303593449754611508540094012366232013997208458539764971054527155865972268583614392223677253786800922270818463912735056327589094992263471792798861344572356998390008443678767722620022874149220732215335073894217640572874692292096797305521442698692077953775132987061473300748380751578925844800143035937460431914988985611693676871546669915287602516113741127107397566371009793343139734014089155438369625112255929546197666820728483476080351455
|
|  RTP(Password): 849078305375236268402214306923055024452833802944055843984266802070376764313599660670880067857738493323217615907029977573292131601508494955633486500110564999301048370993134293380610184319632438984105554837449300422188423414094669973111071783125543919822226398191347978416054869384650029646479767067888719640695338527280696059897264301708529219441558470704290701353369939877878885213149408174115505267381992181096735109531672926794677697515843084262486801859038068390802309269563417160785723690610948827735559460114267413583962476820993473713006710132097424219881600695879881512658997473464693888621150663766656512402
|
|
|  MENU:
|   [E]ncrypt
|   [D]ecrypt
|   [S]ubmit Password
|
|  >>>
```

It appears to be an encryption and decryption oracle with some sort of encrypted password perhaps? Let's try to directly decrypt the password and see what we get.

```
|  >>> d
|
|  CIP(int): 849078305375236268402214306923055024452833802944055843984266802070376764313599660670880067857738493323217615907029977573292131601508494955633486500110564999301048370993134293380610184319632438984105554837449300422188423414094669973111071783125543919822226398191347978416054869384650029646479767067888719640695338527280696059897264301708529219441558470704290701353369939877878885213149408174115505267381992181096735109531672926794677697515843084262486801859038068390802309269563417160785723690610948827735559460114267413583962476820993473713006710132097424219881600695879881512658997473464693888621150663766656512402
|
|  MSG -> -1
```

Errr... That does not seem right. Well, I suppose it is about time to dive into the source code then. First up: the main server loop. _I added some comments to help guide you through the code._

```py
# Server generates domain parameters
DOMAIN = [getPrime(512) for _ in range(2)]

# Challenge consists of two stages with separate loops
STAGE_1, STAGE_2 = True, False



# First stage oracle
RTP = RSA_then_Paillier(DOMAIN)
print("|\n|  STAGE 1 :: RSA-then-Paillier\n|\n|   N: {}\n|   G: {}".format(RTP.N, RTP.G))

# First stage password
RTP_PWD = int.from_bytes(os.urandom(32).hex().encode(), 'big')
print("|\n|  RTP(Password): {}".format(RTP.encrypt(RTP_PWD)))

while STAGE_1:

    try:

        print("|\n|\n|  MENU:\n|   [E]ncrypt\n|   [D]ecrypt\n|   [S]ubmit Password")

        choice = input("|\n|  >>> ").lower()


        # Encrypt option
        if choice == 'e':

            user_input = input("|\n|  MSG(int): ")

            print("|\n|  CIP ->", RTP.encrypt(int(user_input)))            


        # Decrypt option
        elif choice == 'd':

            user_input = input("|\n|  CIP(int): ")

            print("|\n|  MSG ->", RTP.decrypt(int(user_input)))    


        # Check password option
        elif choice == 's':

            user_input = input("|\n|  PWD(int): ")

            # Our goal for stage 1!
            if user_input == str(RTP_PWD):

                print("|\n|\n|  Correct ~ On to Stage 2!\n|")

                STAGE_2 = True
                break

        else:
            print("|\n|  ERROR -- Unknown command.")

    except KeyboardInterrupt:
        print("\n|\n|\n|  Cya ~\n|")
        break

    except:
        print("|\n|  ERROR -- Something went wrong.")


if STAGE_2:

	# Second stage oracle
    PTR = Paillier_then_RSA(DOMAIN)
    print("|\n|  STAGE 2 :: Paillier-then-RSA\n|   N: {}\n|   G: {}\n|".format(PTR.N, PTR.G))

    # Second stage password
    PTR_PWD = int.from_bytes(os.urandom(32).hex().encode(), 'big')
    print("|\n|  PTR(Password): {}".format(PTR.encrypt(PTR_PWD)))

while STAGE_2:

    try:

        print("|\n|\n|  MENU:\n|   [E]ncrypt\n|   [D]ecrypt\n|   [S]ubmit Password")

        choice = input("|\n|  >>> ").lower()


        # Encrypt option
        if choice == 'e':

            user_input = input("|\n|  MSG(int): ")

            print("|\n|  CIP ->", PTR.encrypt(int(user_input)))            


        # Decrypt option
        elif choice == 'd':

            user_input = input("|\n|  CIP(int): ")

            print("|\n|  MSG ->", PTR.decrypt(int(user_input)))    


        # Check password option
        elif choice == 's':

            user_input = input("|\n|  PWD(int): ")

            if user_input == str(PTR_PWD):

                print("|\n|\n|  Correct ~ Here's your flag: {}\n|".format(FLAG))

                break

        else:
            print("|\n|  ERROR -- Unknown command.")

    except KeyboardInterrupt:
        print("\n|\n|\n|  Cya ~\n|")
        break

    except:
        print("|\n|  ERROR -- Something went wrong.")

```

So both stages essentially present us with the challenge of recovering a 32-byte password whilst providing us with its encryption. The only difference between the two stages being the classes that are called, namely `RSA_then_Paillier` and `Paillier_then_RSA`, respectively. Let's take a look at these classes one by one.

```py
class RSA_then_Paillier:
    """ Layered Cipher of RSA : Zn -> Zn then Paillier : Zn -> Zn2. """

    def __init__(self, domain: tuple):
        # Class parameters
        P, Q = domain
        self.HISTORY = []

        # RSA public key
        self.E = 0x10001
        self.N = P * Q

        # RSA private key
        F = (P - 1) * (Q - 1)
        self.D = inverse(self.E, F)

        # Paillier public key
        self.G = randbelow(self.N * self.N)

        # Paillier private key
        self.L = F // GCD(P - 1, Q - 1)
        self.U = inverse((pow(self.G, self.L, self.N * self.N) - 1) // self.N, self.N)


    def encrypt(self, msg: int) -> int:
        # RSA
        cip_rsa = pow(msg, self.E, self.N)

        # Paillier
        g_m = pow(self.G, cip_rsa, self.N * self.N)
        r_n = pow(randbelow(self.N), self.N, self.N * self.N)
        cip = (g_m * r_n) % (self.N * self.N)

        # Update HISTORY
        self.HISTORY += [hashlib.sha256(cip.to_bytes(256, 'big')).hexdigest()]
        return cip


    def decrypt(self, cip: int) -> int:
        # Check HISTORY
        if hashlib.sha256(cip.to_bytes(256, 'big')).hexdigest() in self.HISTORY:
            return -1

        # Paillier
        cip_rsa = ((pow(cip, self.L, self.N * self.N) - 1) // self.N * self.U) % self.N

        # RSA
        return pow(cip_rsa, self.D, self.N)
```

As its name implies, `RSA_then_Paillier` is a toy cipher that consists of two encryption layers. First the plaintext is encrypted with RSA public key $(N,e)$,

$$ E(m) = {m}^e \mod{N} $$

which is followed up by a second encryption with Paillier public key $(N,g)$,

$$ E(m) = g^{m} \cdot r^N \mod{N^2}\ \ \ \mathrm{for\ some\ } r\ \mathrm{in\ } \mathbb{Z}_{N}. $$

Together they result in the combined encryption function

$$ E(m) = g^{m^e \mod{N}} \cdot r^N \mod{N^2}. $$

Another key part of the class is the `HISTORY` attribute. After an encryption call, the server stores a SHA-256 hash of the ciphertext into said attribute. Upon handling a decryption call, the server will check whether or not a hash of the input ciphertext is already present in its history attribute and if so, will return `-1` instead of a valid decryption. _The choice to store a hash of the ciphertext instead of the plaintext is questionable in this scenario, as will become clear from the non-intended solution to this challenge._


Now let's take a look at the other class used during stage 2.

```py
class Paillier_then_RSA:
    """ Layered Cipher of Paillier : Zn -> Zn2 then RSA : Zn2 -> Zn2. """

    def __init__(self, domain: tuple):
        # Class parameters
        P, Q = domain
        self.HISTORY = []

        # RSA public key
        self.E = 0x10001
        self.N = P * Q

        # RSA private key
        F = (P - 1) * (Q - 1)
        self.D = inverse(self.E, F * self.N)

        # Paillier public key
        self.G = randbelow(self.N * self.N)

        # Paillier private key
        self.L = F // GCD(P - 1, Q - 1)
        self.U = inverse((pow(self.G, self.L, self.N * self.N) - 1) // self.N, self.N)


    def encrypt(self, msg: int) -> int:
        # Paillier
        g_m = pow(self.G, msg, self.N * self.N)
        r_n = pow(randbelow(self.N), self.N, self.N * self.N)
        cip_pai = (g_m * r_n) % (self.N * self.N)

        # RSA
        cip = pow(cip_pai, self.E, self.N * self.N)

        # Update HISTORY
        self.HISTORY += [hashlib.sha256(cip.to_bytes(256, 'big')).hexdigest()]
        return cip


    def decrypt(self, cip: int) -> int:
        # Check HISTORY
        if hashlib.sha256(cip.to_bytes(256, 'big')).hexdigest() in self.HISTORY:
            return -1

        # RSA
        cip_pai = pow(cip, self.D, self.N * self.N)

        # Paillier
        return ((pow(cip_pai, self.L, self.N * self.N) - 1) // self.N * self.U) % self.N
```

A similar construction as in the other class with two major differences, 1) this time we apply Paillier before applying RSA, and 2) the RSA is performed over $N^2$ instead of just $N$. The combined encryption function becomes

$$ E(m) = \left( g^m \cdot r^N \right)^e \mod{N^2}. $$

Now that we know what is going on in the server and what we are able to do, let's see how we can slip our way past the two password protected stages.

<br>

## Exploitation 1: Missing Group Validation

My friend [willwam](https://willwam.me/) pointed out the existence of this embarrassingly simple non-intended solution. We have seen that all operations are done modulo $N^2$, so we can abuse the notion of equivalence classes, i.e.

$$ E_K(password) \equiv E_K(password) + k N^2 \mod{N^2},\ \ \ \mathrm{for\ any\ integer\ } k $$

in order to bypass the hash-based history check. The core of this vulnerability is the fact that the user input is directly hashed and checked against the server's history of ciphertexts. In other words, there is no validation of whether or not our input actually belongs to the integer ring $\mathbb{Z}_{N^2}$. So even though the decryption oracle will not allow us to directly decrypt the encrypted password, we can fool it by giving it an equivalence class of it, e.g. $E_K(password) + N^2$. Its hash will look different, but its decryption will be identical to the decryption of just $E_K(password)$. We can abuse this mistake for both stages to easily and quickly retrieve the flag...

For example:
```
|  STAGE 1 :: RSA-then-Paillier
|
|   N: 160010280772794894372346768588185595033036239842143826703576211275767486638801219138479090496844268512676275285546332038002679504781963873100927209318103776202605031760250195675960815850724011979827130814199376153514849938722371316671427378316636070753560341463406962322989572975001519379691891119282911422259
|   G: 16912921449637187454501572080193084300063950498460546513417683045268496628862100061983593492295725032388261480891368389927161288762913687087239396290651549761458870492321310456191434087369914023552598295797221685332128802292693167930588368476367008517725202175736663133833481092493694433716267399468381171517304973943442492659208624303175760327007240721148884665700766842642300309125818000420981673002700104315522580262228024500214311369858573894840047375651161818003285586660444594892041462626433289877226654118075430527775900684193748107122904466789368336872494964951414904657941374270405121612443881917748930770160
|
|  RTP(Password): 5885667527208066135556481648379229647434502259448768509376094014250827345923308310329414269715095611635097629134010982429276255027595635900544442690841259740771537668151566195514321391232757854477644320222883784496280315577302630427374074813239270584711614805213317222539033012196543037610157001386572658313383140271882785487149208177037590827493891420297248924899022920159459456624385031586760418970583695889524332646466488385192587719234135356458839930858841682019191544750528291378560968567529165718890462594080858309581584041888621064154139194048431479962396198063444259263752714067532842725657347059311249629215
|
|
|  MENU:
|   [E]ncrypt
|   [D]ecrypt
|   [S]ubmit Password
|
|  >>> d
|

# Time to decrypt 'RTP(Password) + N**2'

|  CIP(int): 31488957480196721594947691814127392417180927443854117400911826198246421983198602732847556046151044475027532461588802476194393437570683050434259682121708279665898987218972110630865736894455848990668549024522304856350283221331507794903853261866679915962071563888718563314256018553075662397270297448593611771822157673857811770849693344411585268434843789048321851604308799031088577492092778675793505892090044426028313271745469800531655984821517781770152562521531339712088814293476772367652178090496453360116946908127117859042043640129133492339897361193973166864625259927627523686784955637407773719177018255545921450292296
|
|  MSG -> 5152560067282923825768845532474274340759312717638100487922550476714856454049223183489772638156788215071640460067545727038145043548908203340486779342370914
|
|
|  MENU:
|   [E]ncrypt
|   [D]ecrypt
|   [S]ubmit Password
|
|  >>> s
|
|  PWD(int): 5152560067282923825768845532474274340759312717638100487922550476714856454049223183489772638156788215071640460067545727038145043548908203340486779342370914
|
|
|  Correct ~ On to Stage 2!
```

Ta-da!
```
flag{s4dly_f0r_y0u_j41l_t1m3_1s_n0t_h0m0m0rph1c4lly_r3duc1bl3}
```

<br>

## Exploitation 2: Abusing Homomorphisms

Both RSA and Paillier have well known **homomorphic properties**, which allow you to modify ciphertexts such that the underlying plaintext is altered in a predictable way. If, for instance, we know of a homomorphic property that allows us to multiply the underlying plaintext by 2, we can ask the oracle to decrypt this modified ciphertext. Because the server has only seen the original ciphertext it will happily give us the proper decryption to us. However, as we know that the returned decryption is two times the original plaintext, we can apply an inverse operation to easily recover the original plaintext. This way, any sort of similar history-based 'security' can be easily bypassed. To see how exactly we can do this for this challenge, let's consider the homorphic properties of RSA and Paillier individually at first.

The homomorphic properties of RSA come from the mathematical properties of exponentiation. Not surprising considering this is the primary operation done during both encryption and decryption. Hence we can easily state that the multiplication of two individual RSA encryptions of $m_1,\ m_2$ is equivalent to the RSA encryption of their respective product $m_1 \cdot m_2$, i.e.

$$ E(m_1) \cdot E(m_2) = {m_1}^e \cdot {m_2}^e = (m_1 \cdot m_2)^e = E(m_1 \cdot m_2) \mod{N^2}. $$

This implies that if we call the server to decrypt the above left hand side, we end up with the product $m_1 \cdot m_2$ from which we can easily recover $m_1$ as we have full control over $m_2$.

As for the Paillier cryptosystem, its homomorphisms also come from exponentiation, albeit slightly differently. Let's take look at the multiplication of two individual encryptions again,

$$ E(m_1) \cdot E(m_2) = \left( g^{m_1} \cdot {r_1}^N \right) \cdot \left( g^{m_2} \cdot {r_2}^N \right) = g^{m_1 + m_2} \cdot \left(r_1 r_2\right)^N \approx E(m_1 + m_2) \mod{N^2}. $$

This time it relates to the sum of the underlying plaintexts! _Note that the above is not strictly true since every Paillier encryption call generates a random $r$ value. However, having the server decrypt both the left hand side and the right hand side will yield identical plaintexts._

But with Paillier we can go one step further, let's see what happens if we raise an encrypted message to the power of some arbitrary second message/value,

$$ E(m_1)^{m_2} = \left( g^{m_1} \cdot {r_1}^N \right)^{m_2} = g^{m_1 m_2} \cdot \left({r_1}^{m_2}\right)^N \approx E(m_1 \cdot m_2) \mod{N^2}. $$

Another homomorphic property! _Again, the same applies here as before._ Now let's apply what we just learned to this challenge.

<br>

#### Stage 1

Let's start by considering the encryption function for this stage once more,

$$ E(m) = g^{m^e \mod{N}} \cdot r^N \mod{N^2}\ \ \ \mathrm{for\ some\ } r\ \mathrm{in\ } \mathbb{Z}_{N}. $$


We are faced with the problem of finding a homomorphism of the function ourselves, so let's just try something. Let's try raising the encrypted password $E(password)$ to some power $a$ using the Paillier homomorphism we discussed just now and think about what its decryption would be.

$$ D\left( E(password)^a \mod{N^2} \right) = D\left( g^{a \cdot {password}^e \mod{N}} \cdot \left(r^a\right)^N \mod{N^2} \right) = a^d \cdot password \mod{N}, $$

where $d$ is the private RSA exponent. We have no knowledge of this exponent but we do know its multiplicative inverse over $N$, namely the public RSA exponent. So using $a = b^e \mod{N}$ we have found ourselves a nice multiplicative homomorphism of this RSA-then-Paillier cipher!

$$ D\left( E(password)^{b^e \mod{N}} \mod{N^2} \right) = D\left( g^{(b \cdot {password})^e \mod{N}} \cdot \left(r^{b^e \mod{N}}\right)^N \mod{N^2} \right) = b \cdot password \mod{N}. $$

From this we can easily recover the password using the multiplicative inverse of $b$.

```py
# Stage 1
N1, G1, P1 = s_params()
s_submit( (s_decrypt( pow(P1, pow(2, 0x10001, N1), N1*N1) ) * inverse(2, N1)) % N1 )
```

<br>

#### Stage 2

For the second stage, the encryption is now done with Paillier first and RSA second,

$$ E(m) = \left( g^m \cdot r^N \right)^e \mod{N^2}. $$

Similar to the first stage we need to find some sort of homomorphism. If we multiply an encryption with some $a$ it is fairly straightforward to see that we need $a = (g^b)^e$ for some $b$ in order to create an additive homomorphism, i.e.

$$ D\left(\left( g^b \right)^e \cdot E(password)\right) = D\left(\left(g^b \cdot \left( g^{password} \cdot r^N \right)\right)^e\right) = D\left(\left( g^{b + password} \cdot r^N \right)^e\right) = b + password \mod{N}. $$

From this we can easily recover the password using the additive inverse of $b$.

```py
# Stage 2
N2, G2, P2 = s_params()
s_submit( (s_decrypt( (P2 * pow(pow(G2, 2, N2*N2), 0x10001, N2*N2)) % (N2*N2) ) - 2) % N2 )
```

<br>

#### Challenge

Now all that is left is our communication with the server. Of course one could do all of the above manually since there are only two interactions required (aside from submitting the passwords) with the server. I have used a standard pwntools Python script which can be found below in the full solve script.


Ta-da!
```
flag{s4dly_f0r_y0u_j41l_t1m3_1s_n0t_h0m0m0rph1c4lly_r3duc1bl3}
```

<br>

#### Full Exploit Script

```py
#!/usr/bin/env python3
#
# Polymero
#

# Imports
from pwn import *
from Crypto.Util.number import inverse

# Connection
host = "cha.hackpack.club"
port = 10996
s = remote(host, port)

context.log_level = 'debug'


def s_encrypt(x: int) -> int:

	s.recv()
	s.sendline(b"e")
	s.recv()
	s.sendline(str(x).encode())
	s.recvuntil(b"CIP -> ")

	return int(s.recvuntil(b"\n", drop=True).decode())


def s_decrypt(x: int) -> int:

	s.recv()
	s.sendline(b"d")
	s.recv()
	s.sendline(str(x).encode())
	s.recvuntil(b"MSG -> ")

	return int(s.recvuntil(b"\n", drop=True).decode())


def s_submit(x: int) -> int:

	s.recv()
	s.sendline(b"s")
	s.recv()
	s.sendline(str(x).encode())


def s_params() -> tuple:

	s.recvuntil(b"N: ")
	N = int(s.recvuntil(b"\n", drop=True).decode())
	s.recvuntil(b"G: ")
	G = int(s.recvuntil(b"\n", drop=True).decode())
	s.recvuntil(b"(Password): ")
	P = int(s.recvuntil(b"\n", drop=True).decode())

	return (N, G, P)


# Stage 1
N1, G1, P1 = s_params()
s_submit( (s_decrypt( pow(P1, pow(2, 0x10001, N1), N1*N1) ) * inverse(2, N1)) % N1 )

# Stage 2
N2, G2, P2 = s_params()
s_submit( (s_decrypt( (P2 * pow(pow(G2, 2, N2*N2), 0x10001, N2*N2)) % (N2*N2) ) - 2) % N2 )


# Get flag
s.recvuntil(b"flag: ")
FLAG = s.recvuntil(b"\n", drop=True)
print(FLAG)
```