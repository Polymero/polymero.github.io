---
title: K3RN3LCTF 2021 - Shrine of the Sweating Buddha
category: CTF
tags: crypto blinding Paillier
hidden_tags: my-challenge
excerpt_separator: <!--more-->
---

Cryptography -- 500 pts (0 solves) -- Chall author: Polymero (me)

_"Welcome to the Shrine of the Sweating Buddha. Share the burden of your worries, my child ~~~."_

**Hint:** share some (7) of your worries and perhaps your fortune will guide you to the flag.

<!--more-->

nc ctf.k3rn3l4rmy.com 2243

Files: [pravrallier.py](https://github.com/Kasimir123/K3RN3LCTF-2021/blob/main/server-files/shrine-of-buddha/pravrallier.py)

Hidden Files: [server.py](https://github.com/Kasimir123/K3RN3LCTF-2021/blob/main/server-files/shrine-of-buddha/server.py)

This challenge was part of our very first CTF, [K3RN3LCTF 2021](https://ctftime.org/event/1438).


## Exploration

Upon connecting with the netcat address we arrive at the 'Shrine of the Sweating Buddha'.

```
|
|                    (\         ._._._._._._._._.         /)
|                     \'--.___,'================='.___,--'/
|                      \'--._.__                 __._,--'/
|                        \  ,. |'~~~~~~~~~~~~~~~'| ,.  /
|           (\             \||(_)!_!_!_.-._!_!_!(_)||/             /)
|            \\'-.__        ||_|____!!_|;|_!!____|_||        __,-'//
|             \\    '==---='-----------'='-----------'=---=='    //
|             | '--.      Shrine of the Sweating Buddha      ,--' |
|              \  ,.'~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~',.  /
|                \||  ____,-------._,-------._,-------.____  ||/
|                 ||\|___|"======="|"======="|"======="|___|/||
|                 || |---||--------||-| | |-||--------||---| ||
|       __O_____O_ll_lO__ll_O_____O|| |'|'| ||O_____O_ll__Ol_ll_O_____O__
|       o | o o | o o | o o | o o |-----------| o o | o o | o o | o o | o
|      ___|_____|_____|_____|____O =========== O____|_____|_____|_____|___
|                               /|=============|\
|     ()______()______()______() '==== +-+ ====' ()______()______()______()
|     ||{_}{_}||{_}{_}||{_}{_}/| ===== |_| ===== |\{_}{_}||{_}{_}||{_}{_}||
|     ||      ||      ||     / |==== s(   )s ====| \     ||      ||      ||
|    =======================()  =================  ()=======================
|
|
|                  Welcome to the shrine of the Sweating Buddha.
|
|                           This shrine's key (n) is:
|
|        cd375b70ed0be5ffe4637cf1f0b459e4150ee3296088ea90e908b07457be8dca
|        8c6a02e356d37e32acd38a1c54e8d24a25cff9fd05b714d7b36ed312c523f694
|        d09410df641522850bf827473ff843d60223b65720553684fc6f63874400585b
|        c8942307821a8198ee075598bee73d88c3fe8ead0fcadff1ea47118731435e5f
|
|
|  Share the burden of your worry, my child ~~~
```

The server only seems to allow input messages of the form "I worry that ..." and returns some kind of fortune ticket or leaflet.

```
|
|  Share the burden of your worry, my child ~~~
|
|   >> I worry that cryptography is slowly driving me insane...
|                                                                                                                
|                                                                                                                
|  Your worries are just, but they are also just worries my child ~~~                                            
|                                                                                                                
                                                                                                                 
　　・一一一一一一一一一一一一一一一一・                                                                           
　　｜・一一一一一一一一一一一一一一・｜                                                                           
　　｜｜　　　　湳　汯　特　睯　　｜｜                                                                           
　　｜｜　　　　慮　睬　灴　牲　　｜｜                                                                           
　　｜｜　　　　攮　礠　潧　礠　　｜｜                                                                           
　　｜｜　　　　　　摲　牡　瑨　　｜｜                                                                           
　　｜｜　　　　　　楶　灨　慴　　｜｜                                                                           
　　｜｜　　　　　　楮　礠　　　　｜｜                                                                           
　　｜｜　　　　　　朠　楳　　　　｜｜                                                                           
　　｜｜　　　　　　浥　　　　　　｜｜                                                                           
　　｜・一一一一一一一一一一一一一一・｜                                                                           
　　｜　１９Ｆ３５１３１ＣＦ２７４　｜                                                                           
　　｜　６Ｅ１Ｄ９ＢＦ１ＦＤＤ２１　｜                                                                           
　　｜　０Ａ７Ａ６Ｅ２０ＡＦ８ＡＦ　｜                                                                           
　　｜　４４Ｂ５Ｆ２３Ｆ２２２ＥＣ　｜                                                                           
　　｜　７５６６Ｅ９Ａ５２３０Ｆ７　｜                                                                           
　　｜　ＣＥ２Ｃ２７Ｄ２Ａ２６７Ｆ　｜                                                                           
　　｜　９Ｆ０Ｂ９２４８２Ｃ１３０　｜                                                                           
　　｜　Ｅ８４ＢＤＣ８５６８６Ａ７　｜                                                                           
　　｜　７Ａ６４８ＣＡＣ６Ｅ２ＤＣ　｜                                                                           
　　｜　Ｆ９Ｅ３６Ｂ１２９７９６７　｜                                                                           
　　｜　ＡＤ５１Ａ６６５６５５１０　｜                                                                           
　　｜　５０１８２５Ｃ８３Ｅ８Ｆ９　｜                                                                           
　　｜　７７８ＦＥ８Ｂ６９Ｆ０６２　｜                                                                           
　　｜　３ＦＥ０８Ａ１ＦＦＥ５１９　｜                                                                           
　　｜　ＢＦ８ＢＤＡＦ６１９Ｂ６８　｜                                                                           
　　｜　Ａ７Ｆ１５９ＢＡ９Ｆ５４１　｜                                                                           
　　｜　０３５Ｂ８２０１ＥＢ１２７　｜                                                                           
　　｜　６５６６１７Ａ８５３５５６　｜                                                                           
　　｜　７１７ＦＤ２６Ｄ１３７ＡＦ　｜                                                                           
　　｜　３５３Ｃ８Ｂ６４ＣＢＢＥ６　｜                                                                           
　　｜　５２５５４９Ｆ１７６４１Ａ　｜                                                                           
　　｜　ＣＦ１６８Ｃ０８８ＥＦ９Ｂ　｜                                                                           
　　｜　０７４６５ＡＣ０９９６Ｃ６　｜                                                                           
　　｜　８３Ｂ９７６１３３１Ｅ７４　｜                                                                           
　　｜　ＡＥ８Ｃ６Ｂ６ＤＣ６２Ｆ５　｜                                                                           
　　｜　Ｃ２４ＥＦ８ＤＢＡＢ６Ｅ３　｜
　　｜　Ｄ５３ＦＥ８７３１９２３Ｂ　｜
　　｜　ＥＢ６Ａ９０１３７ＣＢＡＤ　｜
　　｜　１５８Ｆ３ＦＣ８９４ＤＤ６　｜
　　｜　６５６Ｆ３０６６５Ｅ４８７　｜
　　｜　２８Ａ７ＤＡ６ＢＦ２Ｃ３Ｂ　｜
　　｜　Ｆ４ＦＤ９７ＢＥＦ６２Ｂ５　｜
　　｜　Ｂ７ＦＢ３８７２９３４Ｄ６　｜
　　｜　８Ｆ４ＡＤ０３ＦＦ１ＤＤ３　｜
　　｜　０４１Ｅ８８０２Ｅ３７５Ａ　｜
　　｜　５Ｅ２９２Ｂ４５ＣＦ４０Ｆ　｜
　　｜　１８１Ｂ５４５ＣＡＦ１７Ｅ　｜
　　｜　Ｂ７１１ＡＢ１Ｃ６Ｃ３ＦＥ　｜
　　｜　８８６０９８９４４１３１２　｜
　　｜　６Ｂ４５Ａ　　　　　　　　　｜
　　・一一一一一一一一一一一一一一一一・

```

This shrine warden seems suspiciously nice, I don't trust him! Well whatever *shrugs*, let's check out his source code.

```py
class Pravrallier:
    def __init__(self):
        # Keygen
        while True:
            p, q = getPrime(512), getPrime(512)
            if GCD(p*q, (p-1)*(q-1)) == 1:
                break
        self.n = p * q
        # Blinding
        self.r = { r+1 : random.randint(2, self.n-1) for r in range(128) }
        self.i = 1

    def fortune(self, msg):
        """ Generate fortune ticket flavour text. """
        nums = [int.from_bytes(msg[i:i+2],'big') for i in range(0,len(msg),2)]
        luck = ['']
        spce = b'\x30\x00'.decode('utf-16-be')
        for num in nums:
            if num >= 0x4e00 and num <= 0x9fd6:
                luck[-1] += num.to_bytes(2,'big').decode('utf-16-be')
            else:
                luck += ['']
        luck += ['']
        maxlen = max([len(i) for i in luck])
        for i in range(len(luck)):
            luck[i] += spce * (maxlen - len(luck[i]))
        card = [spce.join([luck[::-1][i][j] for i in range(len(luck))]) for j in range(maxlen)]
        return card

    def encrypt_worry(self, msg):
        # Generate fortune ticket
        card = self.fortune(msg)
        # Encrypt
        gm  = pow(1 + self.n, bytes_to_long(msg), self.n**2)
        rn  = pow(self.r[len(card[0])] * self.i, self.n + self.i, self.n**2)
        cip = (gm * rn) % self.n**2 
        self.i += 1
        return cip, card

    def encrypt_flag(self, msg, order, txt):
        # Generate fortune ticket
        card = self.fortune(msg)
        # Encrypt up to given order
        cip = bytes_to_long(msg)
        for o in range(2,order+1):
            cip = pow(1 + self.n, cip, self.n**(o))
        return cip, card

    def print_card(self, cip, card):
        """ Print fortune ticket to terminal. """
        upper_hex = long_to_bytes(cip).hex().upper()
        fwascii = list(''.join([(ord(i)+65248).to_bytes(2,'big').decode('utf-16-be') for i in list(upper_hex)]))
        enclst = [''.join(fwascii[i:i+len(card[0])]) for i in range(0, len(fwascii), len(card[0]))]
        # Frame elements
        sp = b'\x30\x00'.decode('utf-16-be')
        dt = b'\x30\xfb'.decode('utf-16-be')
        hl = b'\x4e\x00'.decode('utf-16-be')
        vl = b'\xff\x5c'.decode('utf-16-be')
        # Print fortune ticket
        enclst[-1] += sp*(len(card[0])-len(enclst[-1]))
        print()
        print(2*sp + dt + hl*(len(card[0])+2) + dt)
        print(2*sp + vl + dt + hl*len(card[0]) + dt + vl)
        for row in card:
            print(2*sp + 2*vl + row + 2*vl)
        print(2*sp + vl + dt + hl*len(card[0]) + dt + vl)
        for row in enclst:
            print(2*sp + vl + sp + row + sp + vl)
        print(2*sp + dt + hl*(len(card[0])+2) + dt)
        print()
```

Looks a lot like the Paillier cryptosystem to me, but with some card length dependent blinding patterns. This 'card length' is derived deterministically from the message itself and hence lacks any form of entropy. Predictable blinding patterns are basically like sticking a post-it note over some confidential government papers in order to cover them up...

Interestingly, after about seven requested fortune tickets we seem to find one laying on the floor.

```
|
|  As you walk away with your fortune ticket, you see a lost ticket lying at the bottom of the stairs.
|  Maybe you should try to decipher it?
|
|   Press enter to pick it up...

　　・一一一一一一一一一一一一一一一一一一一一一一一一一一一一・
　　｜・一一一一一一一一一一一一一一一一一一一一一一一一一一・｜
　　｜｜　　　　牯　慬　癥　牥　祲　桡　潲　　　　　業　呥｜｜
　　｜｜　　　　灨　獥　爬　　　慮　琠　特　　　　　　　汬｜｜
　　｜｜　　　　整　　　　　　　湩　祯　　　　　　　　　　｜｜
　　｜｜　　　　　　　　　　　　捡　畲　　　　　　　　　　｜｜
　　｜｜　　　　　　　　　　　　氠　　　　　　　　　　　　｜｜
　　｜｜　　　　　　　　　　　　捨　　　　　　　　　　　　｜｜
　　｜｜　　　　　　　　　　　　慲　　　　　　　　　　　　｜｜
　　｜｜　　　　　　　　　　　　慤　　　　　　　　　　　　｜｜
　　｜｜　　　　　　　　　　　　敳　　　　　　　　　　　　｜｜
　　｜・一一一一一一一一一一一一一一一一一一一一一一一一一一・｜
　　｜　２５ＢＥ１Ａ５ＤＣ９３０５９Ｆ６０２４ＢＡ１４５Ｂ　｜
　　｜　９ＢＥＢ１Ｂ１ＢＢ８１Ｃ４１４１０ＤＥ１Ｃ０１６Ｃ　｜
　　｜　４ＥＤ１９６８ＤＤＦ２ＦＡＤ３ＣＢＦ０７９７２４７　｜
　　｜　１３Ｃ２６３０２ＦＡＥ１１ＢＣ７１Ｅ３９Ｃ７１４３　｜
　　｜　４ＥＡＥ８Ｃ２３ＦＣ９３８Ｅ９Ｄ２３ＣＡＤ６４Ｅ０　｜
　　｜　Ｆ９６７０Ｄ９２５３Ｃ３Ｄ８６ＦＤＣ９ＢＤ７Ａ１３　｜
　　｜　５７０Ｂ４１４５２１２１ＣＡ４ＤＤ６Ｄ９２０２Ａ６　｜
　　｜　ＤＦ８ＣＥ６１６３６２Ｃ９ＡＤＦＢＡ０２１Ａ４６２　｜
　　｜　７ＦＣ５Ｄ４８７Ｆ４９ＢＡ７９３９４３ＥＦＣ１Ｄ９　｜
　　｜　１３９Ｂ５６８２Ｃ０１Ｄ１ＢＣＣ０２１７Ｄ２４Ａ０　｜
　　｜　Ｄ４３７Ｂ０４３２７Ｃ７０９５０８６４Ａ２４５４８　｜
　　｜　Ｆ２２８７Ｂ７ＡＣＣ３Ｅ１Ａ４４Ｂ５ＢＥ０ＥＢＤ０　｜
　　｜　８５Ｃ７６５３３Ａ５Ｃ４Ａ１５５Ａ３７Ｅ１９Ｃ５６　｜
　　｜　Ｂ３０ＣＡ３９８４０ＡＢＣ００９００８ＡＢ０ＡＡ２　｜
　　｜　１Ｂ１１７Ｃ６２Ｄ５８ＢＦ７０１４６９６Ｅ３６Ｅ５　｜
　　｜　Ｄ１６６２２７０５Ｃ２２Ｅ０Ｂ６８１６２Ａ００Ｅ６　｜
　　｜　ＥＤＦ８４２ＦＦ６６３Ｄ２２５８ＣＡ９５７３３Ｅ４　｜
　　｜　ＥＤＥ０３１５９５６３３７８６９３Ｂ４４Ｅ９Ｃ６５　｜
　　｜　８３２１７Ｄ０５ＥＣ１５８１３６１ＣＣ４Ｅ６１１０　｜
　　｜　８Ｄ３４２Ｄ２９Ｄ５６７２８Ｅ２６１ＥＤ４４Ｂ２Ｄ　｜
　　｜　９６４Ｄ０Ｅ９８０ＡＡＢ　　　　　　　　　　　　　　｜
　　・一一一一一一一一一一一一一一一一一一一一一一一一一一一一・

```

Creepy, but interesting...


## Exploitation

Although not clear on the surface, this challenge actually consists of two separate parts. In the first part we use the shrine to recover the predictable blinding patterns used in this Paillier implementation. So let's check how our so-called worries are encrypted.

```py
    def encrypt_worry(self, msg):
        # Generate fortune ticket
        card = self.fortune(msg)
        # Encrypt
        gm  = pow(1 + self.n, bytes_to_long(msg), self.n**2)
        rn  = pow(self.r[len(card[0])] * self.i, self.n + self.i, self.n**2)
        cip = (gm * rn) % self.n**2 
        self.i += 1
        return cip, card
```

We get the shrine's public key $N$, we can control $m$, hence we can easily figure out the used blinding patterns by sending two 'similar sized' messages. Note that the 'size' here is the size of the fortune tickets. The easiest way would be to just send the same message twice. Furthermore, since we will only require the blinding pattern of the picked up leaflet, we can just send random messages until we find one of the same size. Consider sending two consecutive messages $m$,

$$ c_1 = (1 + N)^m (i r_\mathrm{size})^{n+i} \mod{N^2} $$

$$ c_2 = (1 + N)^m ((i+1) r_\mathrm{size})^{n+i+1} \mod{N^2} $$

such that we find that

$$ c_2 (c_1)^{-1} = (i+1)^{n+i+1} (i^{n+i})^{-1} r_\mathrm{size} \mod{N^2} $$

from which we can recover the blinding pattern seed to be

$$ r_\mathrm{size} = c_2 (c_1)^{-1} (i^{n+1}) \left((i+1)^{n+i+1}\right)^{-1} \mod{N^2}. $$

Having recovered the appropriate blinding pattern for the picked up leaflet, we can recover its contents by simply noting that

$$ (1 + N)^m \mod{N^2} = 1 + m N \mod{N^2}. $$

```
Tell him: "I worry that your tyrannical charades are over, false prophet!"
```

Upon confronting the shrine warden with his true identity, we are in for a surprise...

```
|  Share the burden of your worry, my child ~~~
|
|   >> I worry that your tyrannical charades are over, false prophet!
|
|  ...
|
|  ...
|
|  OH?!
|
|  ...
|
|  IT SEEMS YOU HAVE FIGURED ME OUT HUH?!
|
|  ...
|
|  WELL WELL WELL...
|  DO YOU HAVE ANY IDEA WHAT YOU HAVE GOTTEN YOURSELF INTO, 'MY CHILD'
|
|
|           .                                                      .
|         .n                   .                 .                  n.
|   .   .dP                  dP                   9b                 9b.    .
|  4    qXb         .       dX                     Xb       .        dXp     t
| dX.    9Xb      .dXb    __                         __    dXb.     dXP     .Xb
| 9XXb._       _.dXXXXb dXXXXbo.                 .odXXXXb dXXXXb._       _.dXXP
|  9XXXXXXXXXXXXXXXXXXXVXXXXXXXXOo.           .oOXXXXXXXXVXXXXXXXXXXXXXXXXXXXP
|   '9XXXXXXXXXXXXXXXXXXXXX'~   ~'OOO8b   d8OOO'~   ~'XXXXXXXXXXXXXXXXXXXXXP'
|     '9XXXXXXXXXXXP' '9XX'   DIE    '98v8P'   HUMAN  'XXP' '9XXXXXXXXXXXP'
|         ~~~~~~~       9X.          .db|db.          .XP       ~~~~~~~
|                         )b.  .dbo.dP''v''9b.odb.  .dX(
|                       ,dXXXXXXXXXXXb     dXXXXXXXXXXXb.
|                      dXXXXXXXXXXXP'   .   '9XXXXXXXXXXXb
|                     dXXXXXXXXXXXXb   d|b   dXXXXXXXXXXXXb
|                     9XXb'   'XXXXXb.dX|Xb.dXXXXX'   'dXXP
|           (\         ''      9XXXXXX(   )XXXXXXP      ''         /)
|            \\'-.__            XXXX X.'v'.X XXXX            __,-'//
|             \\    '==---='--- XP^X''b   d''X^XX ---'=---=='    //
|             | '--.      Shrin X. 9  '   '  P )X uddha      ,--' |
|              \  ,.'~~~~~~~~~~ 'b  '       '  d' ~~~~~~~~~~',.  /
|                \||  ____,----- '             ' -----.____  ||/
|                 ||\|___|"======="|"======="|"======="|___|/||
|                 || |---||--------||-| | |-||--------||---| ||
|       __O_____O_ll_lO__ll_O_____O|| |'|'| ||O_____O_ll__Ol_ll_O_____O__
|       o | o o | o o | o o | o o |-----------| o o | o o | o o | o o | o
|      ___|_____|_____|_____|____O =========== O____|_____|_____|_____|___
|                               /|=============|\
|     ()______()______()______() '==== +-+ ====' ()______()______()______()
|     ||{_}{_}||{_}{_}||{_}{_}/| ===== |_| ===== |\{_}{_}||{_}{_}||{_}{_}||
|     ||      ||      ||     / |==== s(   )s ====| \     ||      ||      ||
|    =======================()  =================  ()=======================
|
|
|  MHUAHAA HAHAHAAA ~~~
|
|  MMH... YOU'RE STILL HERE?!
|  WELL I WILL LEAVE YOU WITH WHAT YOU CAME FOR THEN
|
|
|   Press enter to open the gift...
|
|
|  Flag: 04a713d804b237451f8ba3e19e3e96504983d9e22775b58e9c4fef31fece87f8042c2081956465daf9eb711746028436bb40c25874d39abab646c43a1e03fb504a4787ba7f6878b7583c5adcda6bf5cd93496949bcc8ec8fdf47d455fc74ebb094077ea0b66e61cc072f0ace37072494856dc397ad72980cd9f20de73557c0d943439efc403916e2565d6b98bae419538ec8a6f74ca18a83ebbe04096c1b6f10ccf069c3d5277465b30fda07e8e6a1abc8831e7aae60c1edc05235c1c51a0ff5faef89413380d354a7d8da2ef19fe51957556cfe1c811eaf880d1f48e01d42bb83176f172a96a18e9cb7dbb31e83ea207977607bb230a9a3bc532add31a3a922b3626c9f4d5a31d14b0a774cc53cad5e0484bfee6dfcf84810cd5a8ba6daed9a624bb2c8bad04b922bfa04e129996739fd2efe3d3a166361816ea8dc453619b1bbf3f3fcb5f17a06245709b84de0ce197dfd9ad72e913cca4ce0af413e94a5a4759b30ee39be2e92f13e51f049217792a69c2ef9d52399c8dbea2b57cf650e5c46ab9d4d9686846356d73176e949ddd2ed39890a0d03a5cda53116dfccd640e39522e9460ca33523b555c2d1e8b1632c3977d171fac128841e3ba80b6bf5dfbbd7c8b8092fde34711b5aca422f371c93ed6b844f3d622367ceb86af92b2b7ecbd58bfc9e2bf76800e42207d55f2855ece22d1fca68d32ec52cfb6431ff7e3c72763054916731d56642bc7b20bb0cf97f4216611aa2e4ab4a833e43e351bfc6aa9c35c08f26997d8ae1a0476c68dfe3ed5c66c7a540f59905c4b4ea11cdd625e192bb1bbb87d13bb927f1753469312adfd98d0d1cc8b22aec97657ec62eccb45c6ee6c3c4fbf26b68913280e873fb58d961d6ad41fc2f2005d40485096cf3be26866d698761f425acdbb943a5ccac4439096390deda781111a74e5137bebc038bd17724bc7abdf0dc9e748d2c4d74f3c702e3bb9733b0702c67d41469c77acb1249171827fc85cceb4c97ca89bbd85fcad4467e222870b24e6704d5546d1bc16aeee41ae0b10f3f33d8eff5b288ca610650a41218e5bb99513d9df77d44ceafb881a4b107ca08fe97473ae2f37bfda20c04a834042ab82afa1449d80363e512cc7d5f93b8be41a571a7eb90a0f4a0b42f122fc9620cc0d3e77bc07d5b097cc7c2aa59139f8253a6844d0212ad8fc1ec0acf8510b993895c0abb8557aea21e0673bd0b15b502c1d95ec2bd675f1d09fefac41196b42e32654a9ccdfb7823be4bdb2bf6bc6bb2aad9cdb7774a5557721c5efccb42c5f59ce9bd688e93f402685925e5566b517017f3171f2b4561dc8e12de2ce5dd51485576aa33c1566ecde44f4fabdcceaf59fcefba4c80509de66f7cb3027a38009766b45a5a2a51d30439843d91af2b5e42e45f3aa0e423e8a5eef97c7c1d32c476e74c352d992f5a5d94dab756c1cfabd3c86c28d00e844fe31ec072d1b510e2b61f9e9ba4ed87a46bf85774d06c724cb1a34246af75727010970ff6bdb03503a57542dd84efec3817b468b82c88bdd6760a815d97f7e178981075a72e27eec1dc6d960eb012dc56589a0165f3387282f10d5cc5bc8daf147618934aade832283435dc1c86f6a720ee2b95be7c7b416f0c726a8e3e7908d5fc9bd9bc91bee7406b73a149b533dd00eded5783e47f6ef18f222c2c442efaa71158c29b2c7dfd221a9bfa72fb148cfb84b1627a9872dec6ccf0526e34831943de6fe4488446aad3b05c2d607032fd27fee7baecfb30c9ed8bf50e47a29cabf866fda7ec5dcbc0b007be1555e6619674cdf9e98b27c476321a36d814dfdfbd0a970ed96078cb891e61321bbbda4b32d6843677aa88b6cf9c90d6dabdf40f67580b001be1b55c51ae3325051970d54a4d1a95bc1b44c03741e0e5c92e3f1b6433edc054f8faeb0214e187cc738937e7a6035198727427fe4f1d718179a7e52863629d0bfac01a0b5780853df0f94beb349eddbec707d9acc88d58311cbbb02e1e1f16fd0ce232092245f60c31536891c35949e7775986973702897e1cf348032d447a94dea9435bc1e7f755dd2fc0314ec030f7e2688122869a9a1660e9f7524c378c489c287bdbb992a824734f6fe5a885143d2d9a45a26513865ccda37f8a060ddcb834647c139967b65b29cab03952b6808af603acf5dd0a370afca4904929d2f5c90ed05343315f6b8d2405eb39c4af05ab0306a30363e4802f86b7381d591bb12d242a35c4fb5d4f3022e93d5e1ad2b90b3ffef69a258b5e40bcdab4ceaffce2bb1e1af8dadbbffa6e3e688f6279dff580484981c23742bb3902349ce3474e5f2847b8136b31dd2ac49f8deb8d92614baf95
```

Errr, right. Well at least he gave us a gift. Although I must say that is an unusually large flag. Taking a look at the encryption function used for the flag reveals why this is the case.

```py
    def encrypt_flag(self, msg, order):
        # Generate fortune ticket
        card = self.fortune(msg)
        # Encrypt up to given order
        cip = bytes_to_long(msg)
        for o in range(2,order+1):
            cip = pow(1 + self.n, cip, self.n**(o))
        return cip, card
```

It seems the flag is iteratively encrypted without applying any blinding! We also do not know what the order of encryption was, but this can be easily deduced from the size of the encrypted flag. Dividing the bit length of the encrypted flag by the bit length of the modulus, we find the used order was 13. Now, if we would write out the encryption equation for, let's say, the fifth order we would have

$$ (1+N)^{(1+N)^{(1+N)^{(1+N)^{m}\mod{N^2}}\mod{N^3}}\mod{N^4}}\mod{N^5} $$

Yea, that looks troublesome... especially since we have to go all the way to the 13th order. It seems were are dealing with the iterative series

$$ g_i = (1 + N)^{g_{i-1}} \mod{N^i} $$

where

$$ g_1 = m \mod{N}. $$

By using the binomial expansion we can slightly simplify this series

$$ g_i = \sum_{j=0}^{i-1} \left( \begin{array} g_{i-1} \\ j \end{array} \right) N^j \mod{N^i} $$

Mmh... Let's have Sage calculate the terms up to the 13th order for us.

```py
order = 13
m,N = var('m N')

gi = m
for s in range(2, order+1):
    ret = 0
        for i in range(0,s):
        bc = 1
        for j in range(0,i):
            bc *= (gi - j)
        bc /= factorial(i)
        ret += (bc * N**i)
    gi = sum([y*N**k for k,y in enumerate(ret.list(N)[:s])])
    
    print('m*' + ' + '.join([str(i) for i in gi.list(m)[::-1]]))
```
```
order = 1,    m
order = 2,    m*N + 1
order = 3,    m*N^2 + N + 1
order = 4,    m*N^3 + 1/2*N^3 + N^2 + N + 1
order = 5,    m*N^4 + 4/3*N^4 + 3/2*N^3 + N^2 + N + 1
order = 6,    m*N^5 + 3*N^5 + 7/3*N^4 + 3/2*N^3 + N^2 + N + 1
order = 7,    m*N^6 + 243/40*N^6 + 4*N^5 + 7/3*N^4 + 3/2*N^3 + N^2 + N + 1
order = 8,    m*N^7 + 4321/360*N^7 + 283/40*N^6 + 4*N^5 + 7/3*N^4 + 3/2*N^3 + N^2 + N + 1
order = 9,    m*N^8 + 118061/5040*N^8 + 4681/360*N^7 + 283/40*N^6 + 4*N^5 + 7/3*N^4 + 3/2*N^3 + N^2 + N + 1
order = 10,   m*N^9 + 115481/2520*N^9 + 123101/5040*N^8 + 4681/360*N^7 + 283/40*N^6 + 4*N^5 + 7/3*N^4 + 3/2*N^3 + N^2 + N + 1
order = 11,   m*N^10 + 97333/1080*N^10 + 118001/2520*N^9 + 123101/5040*N^8 + 4681/360*N^7 + 283/40*N^6 + 4*N^5 + 7/3*N^4 + 3/2*N^3 + N^2 + N + 1
order = 12,   m*N^11 + 13505299/75600*N^11 + 98413/1080*N^10 + 118001/2520*N^9 + 123101/5040*N^8 + 4681/360*N^7 + 283/40*N^6 + 4*N^5 + 7/3*N^4 + 3/2*N^3 + N^2 + N + 1
order = 13,   m*N^12 + 1017614099/2851200*N^12 + 13580899/75600*N^11 + 98413/1080*N^10 + 118001/2520*N^9 + 123101/5040*N^8 + 4681/360*N^7 + 283/40*N^6 + 4*N^5 + 7/3*N^4 + 3/2*N^3 + N^2 + N + 1
```

Oh? That is interesting! It appears that, no matter what the order is, the ciphertext will be linear with respect to the message $m$! This means that once we know the constant coefficient, we can easily work out what the original message was. More specifically, it seems the series boils down to a linear function as such

$$ g_i = (1 + N)^{g_{i-1}} \mod{N^i} = \sum_{j=0}^{i-1} \left( \begin{array} g_{i-1} \\ j \end{array} \right) N^j \mod{N^i} = m N^{i-1} + C_i \mod{N^i} $$

where $C_i$ is the constant coefficient for which I have not been able to deduce an expression so far. 

If you might have an idea for this expression or would like to discuss, hit me up! I even bugged some of my students with this series, but to no avail :c.


Ta-da!
```
flag{___st4y_4w4k3_4nd_d4nc3_w1th_th3_g0ds___my_ch1ld___}
```

-----
Thanks for reading! <3

~ Polymero