---
title: K3RN3LCTF 2021 - Poly-Proof
category: CTF
tags: crypto polynomial fuzzing
hidden_tags: my-challenge
excerpt_separator: <!--more-->
---

Cryptography -- 490 pts (11 solves) -- Chall author: Polymero (me)

_They asked me to set up a zero-knowledge proof that runs in polynomial time. I don't know what that means but I assume they want me to use polynomials, right?_

<!--more-->

nc ctf.k3rn3l4rmy.com 2232

Files: [polyproof.py](https://github.com/Kasimir123/K3RN3LCTF-2021/blob/main/server-files/poly-proof/polyproof.py)

This challenge was part of our very first CTF, [K3RN3LCTF 2021](https://ctftime.org/event/1438).


## Exploration

When we connect to the netcat address we are taunted with the following.

```
|    ________  ________  ___           ___    ___      ________  ________  ________  ________  ________
|   |\   __  \|\   __  \|\  \         |\  \  /  /|    |\   __  \|\   __  \|\   __  \|\   __  \|\  _____\
|   \ \  \|\  \ \  \|\  \ \  \        \ \  \/  / /    \ \  \|\  \ \  \|\  \ \  \|\  \ \  \|\  \ \  \__/
|    \ \   ____\ \  \\\  \ \  \        \ \    / /      \ \   ____\ \   _  _\ \  \\\  \ \  \\\  \ \   __\
|     \ \  \___|\ \  \\\  \ \  \____    \/  /  /        \ \  \___|\ \  \\  \\ \  \\\  \ \  \\\  \ \  \_|
|      \ \__\    \ \_______\ \_______\__/  / /           \ \__\    \ \__\\ _\\ \_______\ \_______\ \__\
|       \|__|     \|_______|\|_______|\___/ /             \|__|     \|__|\|__|\|_______|\|_______|\|__|
|                                    \|___|/
|
|  To prove to you that I own the flag, I used it to make a polynomial. Challenge me all you want!
|
|  Name your challenge (as ASCII string):
|   >>
```

We can send challenges to the server as ASCII strings which it will then use to evaluate its secret polynomial which it then sends back to us.

```
|  Name your challenge (as ASCII string):
|   >> What?
|
|  Here's my commitment: 1447364664466658745634609006499115939497198715920801082173457633425709812015283953309290513176895277149309166571140810961192651441443866800701993336580733369465293320630862147845791803330623467788667707671953255974935403482534879770931870637071152329745004747603809110777452686904449223672052672170113629567547805034189299394112494314201691476008754691590175240308288667354812972495081353784096645283356825376183951402133610540318422614714332935449783595600816284734130450654958799759036288136806679584624435315405627544112699677719288979198805419410628338055254342814069770262245057964082270687580069080779566692841606621070291484237472900901715167106391825794795533248374021761057244316614087268316181767570777672031176667674548887653561854324036573986047064798388496989464907868018682339587155540891443519952910871275878722386095250243240915392902970375307583161455626390565419873993055932274283530924573869709517212450005859135802220751793544080309754441325066477433237585550191582023833479600142126886394061487014465518235450960218332332793514846652659467242634026754399113098648922610429019199357526083784322746390799682454041676704789253058028254414516281669169070751298432
```

Let us take a look at a snippet from the source code in order to find out what exactly is going on.

```py
class Server:
    def __init__(self, difficulty):
        self.difficulty = difficulty
        self.coefficients = None
        self.limit = 8
        self.i = 0
        self.set_up()
        
    def _eval_poly(self, x):
        return sum([ self.coefficients[i] * x**i for i in range(len(self.coefficients)) ])
    
    def _prod(self, intlst):
        ret = 1
        for i in intlst:
            ret *= i
        return ret
        
    def set_up(self, verbose=False):
        print(HDR)
        print("|  To prove to you that I own the flag, I used it to make a polynomial. Challenge me all you want!")
        noise = [ self._prod(list(os.urandom(self.difficulty))) for i in range(len(FLAG)) ]
        self.coefficients = [ noise[i] * FLAG[i] for i in range(len(FLAG)) ]
```

Upon connection the server takes all flag bytes and multiplies them individually with 15 other randomly chosen bytes. These 16-byte values will act as the coefficients of the secret polynomial. We could easily recover all 16 coefficients if we send the server 16 different commitments, but we are only allowed to send 8 commitments. We cannot even cheekily get the zeroth coefficient as we are not allowed to send a zero-byte to the server. Either way, we will have to think of another way to fetch these coefficients. But even if we do, how do figure out which bytes within the coefficients are the flag bytes...


## Exploitation

To fully recover the flag we need to solve two problems:
1. Recover the server's secret coefficients,
2. Determine which of the bytes within these coefficients is the actual flag byte.

In order to solve the first problem we can actually use a pretty simple strategy. If we send a challenge that (in numerical value) is larger than the individual coefficients of the secret polynomial, so larger than 16 bytes, then we can use base conversion (repetitive divmod) to recover the coefficients easily. See the following example code snippet.

```py
S = Server(15)

def get_coeffs():
    our_input = int.from_bytes(os.urandom(16),'big')
    out = S.accept_challenge(our_input) 
    coeffs = []
    while out:
        coeffs += [out % our_input]
        out //= our_input
    return coeffs

coeffs = get_coeffs()
print(coeffs)
```
```py
[54118028903721061320206290944000, 78559713531686838491439759360, 0, 40557061554008760241166939390280000, 0, 0, 24277296579817238501806080000000, 564499119260834601011427409920000, 0, 131408747777613421205312302080000, 12807136469469229342812185400000, 2148641069498552575807660800000, 263140628135842167205017600000, 246779371149623729150837553450000, 7855985244678239953659375000000, 0, 56744154243512571674425466880000, 11465302370023058598778522705920, 3538484881250940111749441863680, 92765059848646183886650963200000, 22691579046414091916058028800000, 2949247435932597059685089280000, 15040668587188547127825000000, 2583408477051856905633697321699200, 238579614248105030169975552000000, 87824833530365826301635993600000, 32815726441054405578858885120000, 2046453718472817490721364480000, 67655564982612388019589120000000, 6643843271535015512366400000, 892170906744116194208133120000, 27162647483500631326944720000000, 108488148950432709872013600000000000, 35889406320060343190504649600000, 9608531021341087573669123325952000, 2683734040512067775178419665920000, 186295310456071672590545268057600, 2458671876353598540066432000, 0, 2887733488489451995509378662400, 84072150485893882910723973120000, 0, 28376858963494575947363670720000, 11493717336438096236247996825600, 326460269774799981719624613888000, 826753693158670143011276036505600, 1221033651603043203734814720000, 399434779131840346688806572000, 0, 4630564825692968415085272760320000, 21417307887989715193695362661089280, 121336547288662733228001440640000, 135903456304943912766918696960000, 3066064860828356200774459699200000, 3411893074283413113240000000, 4494723346002640579450997760000000, 1646041893033880891742519918592000, 25443483196550683962297600000000, 1925632949803255816547024240640000, 764814387350328243364391155200000, 16958390787396603922370273280000, 21937374571604030052433920000000, 69486958640527097230011373977600, 24454806743709628062693396480000, 320729714015241288704788073232000, 33640834445045786036594880000000, 45064408943036195533752750000000, 390376284921877359915234754560, 16354052939605783480257671331840, 5275328917715729099335398850560, 1357865113071861133667794944000, 3204988185377761444647943372800, 692688752079361828861040551526400, 27508327216363717967863775232000, 30599496457601939988339098880000, 4595508159454554799944027340800, 57280011483798894690754414560000000, 45586982445445249260167607091200, 165115795438389626925079265280, 1681031814326472943193042995200000, 89872182534481557341051289600000, 0, 4639828334270614157746225152, 353891028037609355911833600000, 66289844585249773214786002944000, 9198715559846218094637268992000, 575403495733678436932717209600, 2408614309381438115135833374720000, 147049184929323273856696288051200, 0, 740711709386096055591845862000000, 834174133986745652288348160000, 3038299608905422146109440000000, 398973077015790800368854226842624000, 14017608105731660387189658746880, 38187057169623260189491200000, 14950350284722174077390835200000, 13511300855151912086336832000000, 5878265257026181876387687833600, 255984618814882515559048320000000]
```

Finding the correct flag bytes from these coefficients alone is never going to work. However, the flag byte will always be one of the factors. So if we connect multiple times to the server, we can recover multiple coefficients and check whether they are divisable by a specific byte. If not, we know that byte cannot be the correct flag byte and we remove it from the list of possibilities. It turns out we need quite some server calls in order to get the list down to a reasonable number of possibilities, but it works out. See the following example code snippet.

```py
flag = [list(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789{_}') for _ in range(len(coeffs))]

def update_flag(coeffs):
    global flag
    for k in range(len(flag)):
        
        c = coeffs[k]
        if c == 0:
            continue
            
        for i in flag[k]:
            
            if c % i != 0:
                flag[k].remove(i)
                
    print(' '.join([str(len(i)) for i in flag]))
    
update_flag(coeffs)
```
```
48 44 45 41 48 40 65 47 41 42 45 45 46 43 65 48 46 47 41 46 46 47 65 47 46 44 65 45 47 46 45 43 45 45 46 44 45 65 45 42 43 43 46 42 46 42 46 45 45 45 48 42 44 43 45 46 65 47 46 40 65 43 42 46 43 47 46 42 48 65 46 44 39 40 38 44 43 38 45 46 46 42 46 65 43 41 47 44 44 45 45 41 47 41 65 38 44 43 47 44
```

So let's iterate this process for 'x' times.

```py
for _ in range(as_many_as_you_want):

    S = Server(15)

    coeffs = get_coeffs()

    while len(coeffs) != len(flag):
        coeffs += [0]

    update_flag(coeffs)
```
```
...
3 3 1 1 2 1 2 1 3 3 3 1 1 2 3 3 2 1 1 5 3 2 1 2 4 3 3 1 1 1 2 3 2 1 1 2 3 2 1 2 1 3 4 1 2 3 3 1 2 3 2 2 1 1 2 1 3 3 2 2 1 1 1 2 2 1 1 2 2 2 2 2 1 2 3 1 3 1 1 1 1 2 2 1 2 1 2 1 1 2 1 2 4 2 1 2 2 3 1 3
```

This seems more workable. We still have not been able to perfectly recover the flag, but we can get it through some easy fuzzing. Just let the random module pick a random character from the leftover possibilities and see if we can recognise parts of the flag.

```py
print(bytes([random.choice(i) for i in flag]).decode())
```
```
fHagRmhybf9cyclf_y0Nr_s3Xr3ts_hXd_sh7bt1zfryHN9_bnputsL099hhs_t4bs_8h72fmbc_n0t_t4ughtLy0N_4PXt4bXg}
3HagRmhy1f9cyBlfLy0u9_s3BrDts_472_shXbtbzD9yHNr_b7puts_0L94hs_th1s_p4723mbc_70t_thug4t_y0u_4nyt417g2
3lagRm4y1D9cyclD_y0hLLs3Br3ts_hXd_shX1t1zf_y04r_1XpNts_0r9h4s_t41s_84n23m1B_X0t_thughtLy0N_hPXthb7g}
flag{mhyb39cyBHD_y049_sfcrfts_hnd_s471tbzf_y0NL_1n8utsL0r_h4s_t41s_847dfmbB_70t_t4NghtLy0u_hnXt41ng}
36ag{mhy139cyB6D_y0u9LsfXr3ts_hXd_shn1t1z3Ly04r_b78utsL0r9h4s_t41s_8472fm16_n0t_thNg4t_y0u_4nXt417gd
f6ag{mhy1f_cycHDLy049_sfBLfts_47d_s4Xbt1zf_y04r_bX8uts_0rLhhs_thbs_84nd3m1c_70t_thNg4t_y0u_47yth1ng}
3Hag{m4y13_cycH3_y0uLLsfcLfts_4n2_sh71t1zf_y0NL_178uts_0L_44s_thbs_p4723mbB_n0t_thught_y0N_hXythbng2
...
```

From the above it should be relatively straightforward to recover the full flag. Of course adding more server calls will decrease the number of possible characters, but with quickly diminishing returns.

Ta-da!

```
flag{m4yb3_cycl3_y0ur_s3cr3ts_4nd_s4n1t1z3_y0ur_1nputs_0r_h4s_th1s_p4nd3m1c_n0t_t4ught_y0u_4nyth1ng}
```

-----
Thanks for reading! <3

~ Polymero