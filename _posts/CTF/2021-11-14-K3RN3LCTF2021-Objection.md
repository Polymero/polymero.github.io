---
title: K3RN3LCTF 2021 - Objection!
category: CTF
tags: crypto DSA forgery
hidden_tags: my-challenge
excerpt_separator: <!--more-->
---

Cryptography -- 500 pts (2 solves) -- Chall author: Polymero (me)

_"Looks like Harry is hoarding his flags again... Maybe he will stop if we can convince him both Alice and Carlo dislike hoarding too. Alice and Carlo, being stereotypical CTF admins, are not responding to your complaints. Guess you will just have to answer for them... Luckily, I managed to secure you a channel to the domain controller of the CTF server."_

<!--more-->

nc ctf.k3rn3l4rmy.com 2240

Files: [objection.py](https://github.com/Kasimir123/K3RN3LCTF-2021/blob/main/server-files/objection/objection.py)

This challenge was part of our very first CTF, [K3RN3LCTF 2021](https://ctftime.org/event/1438).


## Exploration

On the surface players are presented with the following. It seems we have some control over the domain parameters used by the present clients, and we can send signed messages to our nemesis Harry.

```
|
|     ___   ____    ____    ___     __  ______  ____   ___   ____   __
|    /   \ |    \  |    |  /  _]   /  ]|      ||    | /   \ |    \ |  |
|   |     ||  o  ) |__  | /  [_   /  / |      | |  | |     ||  _  ||  |
|   |  O  ||     | __|  ||    _] /  /  |_|  |_| |  | |  O  ||  |  ||__|
|   |     ||  O  |/  |  ||   [_ /   \_   |  |   |  | |     ||  |  | __
|   |     ||     |\  `  ||     |\     |  |  |   |  | |     ||  |  ||  |
|    \___/ |_____| \____||_____| \____|  |__|  |____| \___/ |__|__||__|
|
|  Current domain parameters:
|   P = 122655067766956583809101358083692118136465533590275443506490706322581338962760242903073840915350787438460018067396513089778731099401529523753641704852145409252845871666984594832126823007230930878315900031324990599780412519840765095924701578072216896079165618757355878332840507852170929126758061736111077100967
|   Q = 1354419371291659890795784389432090130901508696109
|   G (default) = 16874834016243520222116414145277622362009309666054446600209328449625936386087301101896108070032256012512557895750834628966225072894024265269856709280807595259801984898348291000366262059715077863594167761057132301837728767668031019720441088126982962643398178972550743954546919816346251900754447874753643753538
|
|
|  Domain Controller options:
|   [G]enerate new domain parameters
|   [P]rovide domain parameters
|
|  Network options:
|   [S]end signed message to Harry
|
|  >>
```

Let us dive into the class source code first. There really is not much too see, other than a standard, not tampered with, DSA signature scheme. But of course, we can only know this if we check it.

```py
# Imports
import hashlib, secrets, json
from Crypto.PublicKey import DSA

# Local imports
with open('flag.txt','rb') as f:
    FLAG = f.read()
    f.close()


class CCC:
    """ Certified Certificate Certifier. (It's just DSA...) """
    
    def __init__(self, p, q, g):
        """ Initialise class object. """
        self.p = p
        self.q = q
        self.g = g
        
        self.sk = secrets.randbelow(self.q)
        self.pk = pow(self.g, self.sk, self.p)
        
    def inv(self, x, p):
        """ Return modular multiplicative inverse over prime field. """
        return pow(x, p-2, p)
        
    def H_int(self, m):
        """ Return integer hash of byte message. """
        return int.from_bytes(hashlib.sha256(m).digest(),'big')
    
    def bake(self, m, r, s):
        """ Return JSON object of signed message. """
        return json.dumps({ 'm' : m.hex() , 'r' : r , 's' : s })
        
    def sign(self, m):
        """ Sign a message. """
        h = self.H_int(m)
        k = secrets.randbelow(self.q)
        r = pow(self.g, k, self.p) % self.q
        s = ( self.inv(k, self.q) * (h + self.sk * r) ) % self.q
        assert self.verify_recv(m, r, s, self.pk)
        return self.bake(m, r, s)
        
    def verify_recv(self, m, r, s, pk):
        """ Verify a message received from pk holder. """
        if r < 2 or r > self.q-2 or s < 2 or s > self.q-1:
            return False
        h = self.H_int(m)
        u = self.inv(s, self.q)
        v = (h * u) % self.q
        w = (r * u) % self.q
        return r == ((pow(self.g,v,self.p) * pow(pk,w,self.p)) % self.p) % self.q

# Set up domain
domain = DSA.generate(1024)
P,Q = domain.p, domain.q
G_default = domain.g
```

Our win condition can be found in the server code, see below. We need to convince Harry to stop hoarding flags by sending a specific message verifiable from both Alice and Carlo. Hence we must somehow make use of the domain generator injection to provide Harry with a malicious generator that seems innocent, i.e. has order Q, but allows us to spoof messages by both Alice and Carlo. Interstingly, the win conditions are reset if we supply new domain parameters, so we are only allowed a single injection in order to convince Harry to stop hoarding.

```py
elif choice == 's':
            
    try:
        
        signed_msg = input('|\n|  JSON object (m,r,s,pk): ')
        
        jsonobject = json.loads(signed_msg)
        
        if Harry.verify_recv(jsonobject['m'],jsonobject['r'],jsonobject['s'],jsonobject['pk']):
            
            if jsonobject['m'] == b'I, Authenticator Alice, do not concur with the hoarding of flags.'.hex() and jsonobject['pk'] == Auth1.pk:
                
                WIN1 = True
                    
            elif jsonobject['m'] == b'I, Certifier Carlo, do not concur with the hoarding of flags.'.hex() and jsonobject['pk'] == Auth2.pk:
                
                WIN2 = True
                
            print('|\n|  Your message was delivered succesfully.')
                
        else:
            
            print('|\n|  VERIFICATION ERROR -- Message was rejected.')
        
    except:
        
        print('|\n|  USER INPUT ERROR -- Invalid input.')
```

All in all, we have found the following **key observations**.

- Messages are verified using a standard, not tempered with, DSA signature scheme.
- We are allowed to provide custom, yet valid, domain generators to Alice, Carlo, and Harry.
- In order to win we must provide Harry with a innocent looking, but malicious domain generator such that we can spoof signatures from both Alice and Carlo and convince him to stop hoarding his flags.


## Exploitation

Our approach will consist of the following steps.

- Do some math the find the vulnerability.
- Set Harry's generator such as to allow us to spoof both Alice and Carlo simultaneously.
- Send both messages to Harry and serve him some justice (in court).

Time to dive into the maths of DSA! Let us consider the verification of a signature $(r_A, s_A)$ from Alice, it is only valid if

$$ r_A = g_B^{H s_A^{-1}} y_A^{r_A s_A^{-1}}. $$

The easiest solution to this is to consider $r_A$ and $g_B$ only in powers of $y_A$:

$$ r_A = y_A^k, $$

$$ g_B = y_A^{\alpha}. $$

Using the verification equation this results in

$$ s_A = k^{-1} \left( \alpha H + r_A \right). $$

This should be simple enough, however it becomes more tricky to make sure our injected $g_B$ also allows us to impersonate Carlo. So let us consider his signature's verification, which is only valid if

$$ r_C = y_A^{\alpha H s_C^{-1}} y_C^{r_C s_C^{-1}}. $$

Without introducing any non-trivial connection between $y_A$ and $y_C$, which are not under our control, we conclude that $r_C$ must be expressed in powers of both:

$$ r_C = y_A^m y_C^n. $$

In order for the signature to be valid the exponents of both $y_A$ and $y_C$ must satisfy

$$ m = \alpha H s_C^{-1}, $$

$$ n = r_C s_C^{-1}. $$

We can rewrite this to find what $s_C$ should be, however, we find two equations

$$ s_C = m^{-1} \alpha H = n^{-1} r_C $$

such that

$$ n \alpha H = m r_C. $$

This, in fact, gives us a constraint on $\alpha$ as

$$ \alpha = n^{-1} m H^{-1} r_C $$

which we can simplify a little bit by saying $m = n = \beta$ such that

$$ r_C = \left( y_A y_C \right)^{\beta}, $$

$$ \alpha = H^{-1} \left( y_A y_C \right)^{\beta}, $$

and

$$ s_C = \beta^{-1} r_C $$

for any integer $\beta$ in (1, ..., q-2).

Now we can simply forge signatures for both messages and finally make Harry stop hoarding flags. Or well, at least for now...

Setting $\beta$ and $k$ to 1 for further simplification we find the following solution to the challenge.

$$ g_B = y_A ^ {y_A y_C H^{-1}} $$

$$ (r_A,\ s_A) = (y_A,\ y_A y_C) $$

$$ (r_C,\ s_C) = (y_A y_C,\ y_A y_C) $$

Not convinced? Plug them into the DSA equation yourself and check it out :).

Ta-da!

```
flag{0BJ3CT10N_SUST41N3D_1t_s33ms_l1k3_y0u_c0uld_b3_4_r34l_4C3_4TT0RN3Y}
```

-----
Thanks for reading! <3

~ Polymero