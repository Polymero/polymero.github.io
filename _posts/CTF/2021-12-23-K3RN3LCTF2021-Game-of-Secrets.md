---
title: K3RN3LCTF 2021 - Game of Secrets
category: CTF
tags: crypto cellular-automata leak
hidden_tags: my-challenge
excerpt_separator: <!--more-->
---

Cryptography -- 500 pts (2 solves) -- Chall author: Polymero (me)

_"John wants to play a game, a game of secrets. Recover his secret or be encrypted."_

<!--more-->

Files: [gameofsecrets.py](https://github.com/Kasimir123/K3RN3LCTF-2021/blob/main/downloadable/Game-of-Secrets/gameofsecrets.py), [output.txt](https://github.com/Kasimir123/K3RN3LCTF-2021/blob/main/downloadable/Game-of-Secrets/output.txt)


This challenge was part of our very first CTF, [K3RN3LCTF 2021](https://ctftime.org/event/1438).


## Exploration

The title of the challenge, 'Game of Secrets', together with the reference to the name 'John' were direct hints at the origin of the below home-rolled (read: insecure) cryptosystem, [John Conway's Game of Life](https://en.wikipedia.org/wiki/Conway%27s_Game_of_Life). We can see the shape of the inner state by taking a look at the `slicer()` method. It is a simple 8x8 bit plane, which is updated according to the standard rules of the Game of Life:

1. Cells that contain a '1' are considered alive, whereas '0' cells are considered dead.
2. An alive cell which has 1 or fewer, or 4 or more neighbours will die out in the next step.
3. Any dead cell with 2 or 3 neighbours will come back alive in the next step.
4. Any cells not affected by rules 2 or 3 retain their state.

Note that in the consideration of the neighbours, a 3x3 grid is used which wraps around the full 8x8 plane. The key stream is then created by running the above for 12 steps and then XORing the field with one of the four round keys, where the round keys are simply generated from the sha256 hash of the master key. Every 48 steps, all the round keys are individually hashed with sha256. The resulting key stream is then simply XORed with the input plaintext to produce the ciphertext.

```py
class GoS:
    def __init__(self, key=None, spacing=12):
        self.spacing = spacing
        if type(key) == str:
            try:    key = bytes.fromhex(key)
            except: key = None
        if (key is None) or (len(key) != 8) or (type(key) != bytes):
            key = os.urandom(8)
        self.RKs = [ sha256(key).hexdigest()[i:i+16] for i in range(0,256//4,16) ]
        self.ratchet()
        self.state = self.slicer(self.RKs[0])
        self.i = 0
    
    def slicer(self, inp):
        if type(inp) == str:
            inp = bytes.fromhex(inp)
        return [ [ int(i) for i in list('{:08b}'.format(j)) ] for j in inp ]
    
    def ratchet(self):
        self.RKs = [ sha256(rk.encode()).hexdigest()[:16] for rk in self.RKs ]
    
    def update(self):
        rk_plane = self.slicer( self.RKs[ (self.i // self.spacing) % 4 ] )
        for yi in range(8):
            for xi in range(8):
                self.state[yi][xi] = self.state[yi][xi] ^ rk_plane[yi][xi]
                
    def get_sum(self, x, y):
        ret =  [ self.state[(y-1) % 8][i % 8] for i in [x-1, x, x+1] ]
        ret += [ self.state[ y    % 8][i % 8] for i in [x-1,    x+1] ]
        ret += [ self.state[(y+1) % 8][i % 8] for i in [x-1, x, x+1] ]
        return sum(ret)
    
    def rule(self, ownval, neighsum):
        if ( neighsum < 2 ) or ( neighsum > 3 ):
            return 0
        return 1
    
    def tick(self):
        new_state = [ [ 0 for _ in range(8) ] for _ in range(8) ]
        for yi in range(8):
            for xi in range(8):
                new_state[yi][xi] = self.rule( self.state[yi][xi], self.get_sum(xi, yi) )
        self.state = new_state
        self.i += 1
        if (self.i % (4 * self.spacing)) == 0:
            self.ratchet()
        if (self.i % self.spacing) == 0:
            self.update()
        
    def output(self):
        return bytes([int(''.join([str(j) for j in i]),2) for i in self.state]).hex()
                
    def stream(self, nbyt):
        lst = ''
        for _1 in range(-(-nbyt//8)):
            for _2 in range(3):
                for _3 in range(self.spacing):
                    self.tick()
            lst += self.output()
        return ''.join(lst[:2*nbyt])
    
    def xorstream(self, msgcip):
        if type(msgcip) == str:
            msgcip = bytes.fromhex(msgcip)
        keystream = list(bytes.fromhex(self.stream(len(msgcip))))
        bytstream = list(msgcip)
        return bytes([ bytstream[i] ^ keystream[i] for i in range(len(msgcip)) ]).hex()
```

Finally, we are given 9600 key stream bytes for free. Although this challenges will provide a solvable ciphertext, with this size of known keystream almost any randomly generated key stream will be vulnerable to the exploit described in the next section.

```py
def __main__():

    gos = GoS()

    print("\n -- Here's your free stream to prepare you for your upcoming game! --\n")
    print(base64.urlsafe_b64encode(bytes.fromhex(gos.stream(1200*8))).decode())
    print('\n -- They are indistinguishable from noise, they are of variable length, and they are the key to your victory.')
    print('    Ladies and Gentlemen, give it up for THE ENCRYPTED PADDED FLAG!!! --\n')
    print(base64.urlsafe_b64encode(bytes.fromhex(
                         gos.xorstream( 
                         os.urandom(int(os.urandom(1).hex(),16)+8) +
                         FLAG +
                         os.urandom(int(os.urandom(1).hex(),16)+8) 
                         ))).decode().rstrip('='))
    print('\nGood Luck! ~^w^~\n')

__main__()
```
```
 -- Here's your free stream to prepare you for your upcoming game! --

LnDURReIZnkK5nIAaH9H8ahTRebMIXxrm7OOOW0a8aj_-PJXiWMVJ_QE4Ei2n7zBS6AEq1ky-U5VxFSOdBOoXZKKJRwHuXoJZ33gUiQhzwRdh3ed3m5VFu9s-5szPef3mzWTZCedLQ5pWQ_YyOI2mL_MLqsAR0_w_j9xOWtNbsBl30-9ZkdknhcgCXPoIJrvb0YpxWmucQ1tmzY-mAzHIxGLSLdb7-8O8F5ryzfotI6SqUAKiMwGkSzreXOYNtgudVr8S20RbXDcQmv1bisnEFEChGUmfwHTxXm2vpzo4YBPDvYhl8Z4qre0n58V_kGi6YRr4j3D_Ze_GbgabeNZuHyVokowiDgeppgJWrWgkg5aUpUuKfPB-ZcD9zZpQqnq-9gUUuW05X93sD6I9o09SLT7zTsecPW9pJ0fooTxISMYOuucdmPHdC98ZGh77aThrASx-d1XFUxenwg3grnN7GYqtDv4ITTQicsC_cijqAQ0CyOaM5wpk8szmatKEXmnkF9_hREgM70ArHdeYECKom3oqVYiG-weF0UrlvXqYItAB_OteQLFhWmroC7CwatxCrLpeE7qxPAC9oTZGcyM8pE1dRnxqbHayM4ZwSqfNXBDsnFOJL7rJWL3KOSvlhnSc1uVsGJAEEKK2dEbUj8oZ5IMPjmBqHIRwGN-dzitTbW1vzQcF3L9mjFP0qt4SSZRpdJHc6PKlWspH95a3uGAW9qO6MVUjL-M2L5RyxldMp8qyHwcpDSoHt9Hg-rd8_eeT6_QewpmsFGY7c0DE77lzMmk8Fk_WMB3xJAoa1-qpaXLqibqDWfmcGbCL2UIsXbZc4B7V9NJy2yZXYFlQhkUUi37zzqk1XcSOH51iHyd93vZRQG4HDRJmrco1YmpJrHoXOIYaVQXauVih9tZAWEBQHhE-RfTrFGsbwK6YburrYK6_OqATkxC5N5ZW7jS5xZCFMhI46P4TUajjeJ6TS7B7qDXNgLCc7l2GNPikDC1LRwxjgQlMPI4fcyZJMGynEFT5pws8sPLe-eR2w1E7PRStWY8iQq9Oq7TuUY6BZ_b2s5ppOsxJn00XCo4jy5aei8mFhPjHBpYMuIuy-YGC0u6PvnxM1okurbs98z0FUh0GfqKtoRMCcBZONf26G9yDACjX8LshZoU2_fzMEefoEOu5URKni4RqfIU8Uuv1wIK3flYovUArcD79ySO-196msfmq9tD0LmI9aXiD3IV2rSXdJeAd6rAlHxdQ4zM2hDlo8mKAFgT1UQaCL_09kYKX7V1l64xdRfMw2MxGqI9LDid9fAqCyZ-jQknRa9P7JuJr_hkW0XBHFOXUGJfEzPYMSGk9Y0boqY0_DGUnBz_VOwljgOSaA4h3MYlKxilKsEku7Z0NX5t0EmBil1GxFi214_C1f7zmjbGfD1FLD9N-6QjwY56Xyg0kTg2KJuvO-41b16ZedaUIplFZv5Z-exnpmZGuKQkbZb8d4hwM5iobolX1hrUVn-SvpfsPgr-IB5QWKxayBdLINUu98lkPpRoCiCsszUzfUaUsR8KvE3ryhyibjDZOqybeXI-h8eCH7bdEhIeZN7fcEhnvhlHO2pjWQVbIRrDqmkyw10rpkmnfQzubbWMmxsfMDnEmEkQzkdBCjN22p3K88rAOTnlwY5gvNkDGbso1mvfHOiBMMvET5qHUe-YbXBEs-lvi0jgNvvXSPOIjvfAMfPdClt3BTBU5_fQCz6oGRNp7-3jil-c34FR52ddxF9jI7-TbcWOk0IJ3IoAzUvzhx3PnzOZ4yeyTm7rOtnGgADaRUjTOP-RvKIVBSVyykG9fogpIJKPI0RTNhE-S3epbWkTko--OU8ClOCa6_MmFXaRvblNfsWMgGm4fzPrSo-smKiB766PfxGo1V8HNzcogjLRyhegQRsMIOqulArvj5GchbSqlqgIbRDd5ZbFGMf5xC3PXFoGmcvyt6q4a52HF-agDnQQwgoJSj4CKKQY_G8uYMEGU5Fi-kxPzTaG7Iw8kqDt03jdD3nyrFxYfkr3D4_zkrF1fbtc2R0xw6wp0Mb3Ufig-LGwyxXtnQqXEX8CyXlCYKCFczoHzHTjo_4ZAjCi_tMOLoDBuk-UaL_5OTCn1g2U3J2iC0PyuKr8Zh5jNLu_pSBAq5bMrisIKtB5pqBTKv3DR_wR1gtsz8k2nusFYAngCCaPvpX_SLFVBlOuXWfMvA8zFux_O_78TVQmBr2znt9L_WVZa7ltq9jx5jSgNO9Zd45D9379Zo61DaUxYS2-e-DT-UYZYpmhfujuYvNcqxWCKPk983N6EnXi08qx3dNOlamhSvwpO68_3H5-35m5adoxt5dQ6w6uI0tgZxCpn4RV38hBAKmcPN_kZZ7KsDH8H2ISGOo3wRWd6VhUw4wkLwpGtH8h-nzsbqmk7wIXheD2u1-GVPl9pU0QN67X6DEWItHcT6cVhcmepKkvcS74IvUoOalN1NVbaDEZnX5WtprUiU15ZZM-JjtBDgeWagAsT7dW-bWdaZkG_rl7hJcGcDLd7Vuhc6506ZypoImQd14AGBw7IbmpIcVa8_PncRfwgYGmmEJkY73xyj9Fgygi5wn_TTMkO9wMlOMfIgnvvQmuP-N9rnacFIvovMrG03QnfrxNJeoKrcyPJ0vFDsbeKwIfrnoBZwhF6-H10Z5eu3mrvSmdXqJE6U515X1VzQ-2C9qO9HksWKef1HF1N9dc2EgzXfNZrMzc9YI3wo3UIP00vxIA7WBcde_xEWZRWpaffu2MEOiawmbAhZBqfpmK-OUD-EyRyP5QsNuWt9F2xt0GGfLRmdZ-H3aSmMa72LscOM7oJhZaZwHo-LLubTT4ILMmoZygtD4mByvw8tyRucyGrlDcGzXY52LZeLhjQ0HXTPVZmUBd1Lbmttdima2OleuV8-8FZRsxNlX5A8ZxqpxwOm953Qa8LWlfmp6f9dLe5pZC7rS6seeEL7FeA0gQm2ARUU6kjh7QoseXx5_vCSAYCWg37MLsAJEwxgQ1fjh3uNhvGj3gj1spWncmASudsUHlxxGErQZKuSdXCEhji5f9l1A009GMtHaSJUndfVi9WZuXcNdhff1wlQCzE1jo9HEcCJs1ttBsx04RhV9I4ekYY5G2-HHIANxOPV7V5QUEzwaHQIMlQjMnmutldm1qErhq0ht2LXi2tL73CyaCzVarXSDEhCV9bUpqpoQvkvwanYrLhXnCjoCV9M2BWTYPusBkxOJ02ZzYLPBN3zoi16z7RTRltNJ4v-CKLURZS6rEoo3PtO6h1UBlJ4POCX5oC7QmrEPtHwpb5sHKJXHOAbHCUWly8fK4Eq_qDHyJ7F1aIrcva2zuSBXqvs8cAOR0BNtmBPgutKYjF4kPEdzqBgQlKuZm2AnQYmxDCSS_OS7sNj2ENV8Q9IfPnbFLIFcFETnwwBBg3l5lFQ8EpAOazDQiB0sLU77YJzh-YyEGaG0QLhGnJaQG2MaLB3GrRposAzW8S1rE-bLDyICI8-aRsaK-a-G4yQfEwl0WJdqyENWYV4NZcIffKHVl3edr9VK4xoF3LxhlROqiYaFSAQFGWoLo8OccuH8Mxi9KZJZyd3gpsm1cAdRe4w3bNREcpUaWeR1DVcx1Cy1VWZV4LCZ1rvLmV55yJQSw1w2ATJHpbUj-dk8N27O9I2FH6osPTTuMZZTqYAICyJkJbapOvHAnihRkUjXuoBVrt6EK_8bFWygxgXXpnjN9Kchvg85ZsZ09tkXZeQCZua4rDuXTjSjzdfWLP-BVhL0cdmLNKLVjkTlGoPiNgXdUieQ8x6TbM9HXA6iBjk1vmQIlvnH0McjhoRLAJJZCSlDWfM3qHlsvNMwGN_OK7Qy3wFG1WNqtlKcCJUPiisWaKAWJSQ1rkB16dKn_BFwFXZwNIIvkIOvVZLYc7t2yfQlmate6OViyPxDgf4A9co312cQd4XWi6wQMZg5G4xlHVU67YTZ-MfXkMUZDKz7NsTLT7YoaWjVeUW_dQeFy2oQKD0fyTTfosLS-WwrhDK4xzpySDibaqZI07gzVB9Xd37JukLuU7MwYT9fGZflLq4o0JPFodN6C5436RUdGDOngIpwb6d5AyWEGGhCAeih12R9KO9C55mhdXdmQQ22XNMS7bMllR12U6ddv4FOBaXhChpZBFIKBsCaTkJ_0BVr-Wp7ej28IDTKm1wbozSagjVtp8VBa04Eulv1hLEqhzs1sETw4UrtaZYqS567CpZ7e9nM2iPKJoQKVXhnHBtVlW0KgWGEmS4AiSlM7efcDeUuCi9cY__pgU9hpg0OzsGrLHLWwnj7Ch4VElKl7v93dL2CgOfYyfVuNtDGZ4HQBAMPWfGVlbMwA1liJdUBbkjdBbuCgBFPv2XEX0e8S9p32mc6Zo5zoMas6VYFYFmKQmHnbrfvnfjH0_8-I3QXin12e88GUC2hVtjug3mDaE_eOuBzW2Eiq6iKh_48kkhGNtzLyV8TYBd5FcgORcAgTZofpB2ML5NoXaGkWKeEHwG-i7w2lgc57SeIrPtNcKdgAC6sBQksGMQAGLHD5X_gN06jdh9fsIL9d3OHkvr5V5ylD_OXv24d5HsHfxhhaJtasn_k2iONowAmoTQyUkPwxsAACCFns6D13RttBgyhZAnKSNNPGcK8u2-TPLOIeyiJhVnOF-jLHmiRuNKmEYUCHgB939K3tzU4XRYb_O50LBVCJ5tnFJVx9C1IJyRfemXYaw-HUgF096qBkhU-sEwWGqwz-lFaTsPe9wPxydc-NOakhINCQG8axz8rlaTI0XWhhXjq_W17xUNBHRi2JTc3uqkj1aigIrS8jP_jG2tGRMPSIqjXbhRvmxzfkAbKWciOc-8RtfUJyhwamxfrybxqnTiHqU7dC3LpFOW9YX70FGOrubTbMGr_yMPMcSxyngJrdc3wubyJiAprwa_hreqfKenY79x8oBgGXxvJWGLZd2GZ4r_5_xBxc2V2B6dblcqh335Ve9GC2r9mwPCAG5ETfFsN1LbmnghycKsYdzuLg8MNwoQ79PDwXKcHEywEEQUzbdnAAyUdIqxuXaFvRJKqMM7CV3pCZJbfGpS_sHg-L6AL_l-LujXJbHzwhLaVzG6x9y-bEmkoyTc8XFlSrEJPwn-W1wFGf4rZw-oLl3rwvKTukQYUzHEhRX1VOBPJuG0rX0DeEOJaQIGtw_9VHMnxqEB6Kgdj9fsGcqYvyQPK2lkPZYlJqcsEE9h9QFv0EBY5ZdsR8i9qOnoT0RanBtSiKVDiqwgdILEYS3JWwlljikCnbdaeg0szM_6nh_HuEH3P8Cl0nUzH_MdWXJFOO6KQ5pYISy-uWlUZShU_Linz6AorngliN1mTYbF5I5e16uiUwCTrWFHMiuXCEhLymRamKy6kgj4iihQdy4_HM98AlvEtnA3pJGdD1iCIzp2O097958j3sXpFON3O87oQQ4PIIB19vRjUFsCwjQOH8EeQChxCsCucgyJpSfoRgtXP1gabmO65QfcjTkrJ3L7gtxzz7SWdRCTD4pVPGNkNmmq8O4DKJ9BO6YiuxqiTQRcxJZEROj7O_1nHY8WIS1-E9OOgdvg_Qsz68hzOb_2bu065tTXce4p6gX3-Z2x97VtFuOyJQhR5vNRjMBdO40IqUu6fyJhmdE2Bth4V8hkWWjGLnDIR2ZWRnpE3EeRsVGGE6ZDxlETAgHp9Q1YEaOSsotkykCWGNK6N8EfnSpBdeDhh76E9ElrNmmUvpijn1QufS-6VvL2S0_--kA0bodukNl0xtJ-DUeimsn9ZC5hBGVJHl4o8L_LRNcXWXGJTv6DHF9LaeMTqd2s6nGy6_O621UleTLxs2HzC6hO2K13IfdRN8rUFH2-dKTvJXsuFUZufdI6Ku6DN4JWD4P66cpmM5Bj69VWcMlwdNa8DoM9hp-IH1TMJotP-KxmUTa6WRhO1Zqq6UkbEQ0eErRGeoIoUsym9s3NN66B8k6zf7wCTuP4-zNdxd8Te5q9_fny27FczW9QUNDpvJr3AIXXa6BlVmIiTZtgqlPrAqlQxL-JHtBXYOLUxTIO_wWvJGW3Rl_WTL5W92DodpzTaHLnuaViq2vPB1Ykmm_Zb6El6AjHnKt_Yy3iDiLUJrMC9mLWm7la4NwTYZfDGqg-tq2TVklNCPl5349GU4jb0PlgGhfQwEkMn-1iiQtb-8KtjBJPfpo8U9rEh2-7xZaFSVb-X35qjJc_nAAAu0qd4it2xNilofKgZ5KknRGt52LZPZIUbQ4BjnpkGqRe22i28f1bNl73cUmc4jvBbjudq6xO0WHxhKCGKD39NePqmdfo5rOQiJpWx38Q3djQnmezZdrdIEJMvYXoWIcGpXoVkmBsGElqjeIRYwq5lQ4itAL-YSt8r0VslML_wTt3NIymLB4H_2xS0TownYV6a4mwck2UG43eITx1x8D9d9dgXXJQRocGV8l-zWKZ4tVhnr3K0nQoyKCvhe_ACOWBZ87kVUd15H2GHNscLbb-4L-u74an5PaNCdIjFQXwYqIWLMdsinn5L-5_Y01ja5g77NnPMM7W-ly0PUYJzNYOjYzK-m-xRft0SJod0KK6mfEwPjJbQYqfkjJd4OZHJeRlbaGMEj9q8UMaYFOknywwwtCibPRvrrLDtQSUbKI-njp4IHPP_LO2Booj7jrrsLzWZiflX7SQh8JsG36U8QN7cMZFoSvkJKvSw2gWpfx7-5xt-BAW5Mwzo78bEAvQYbyABrA18tK0gBf0eC66ZPCb3MxZQMwfn6VvGtnPKaNNVzjLKcp_oYS92EzDthzZtEyvXzPQi_KeazjxjS-Ao6fHPAPw6vo-TO5ZOhOcD7mhTmemPRuy2YriEfyTLaetNqUqBCZa_LZLx_A9FZwt68FUIuTHziRT5W3UjAWiTSz08f9bq4_Bzlg0THP_HUsajRZnU5LgjQQBg1nzyP2K0BFWqIZOQAU2v0aV0gsGX0ejluF_MQmt_1F6iTHvNw2YHe4kucr11ceBK0G8KW0VxFwbwUzNSez56GbBLSLbNqnsUk3eRX1VXnjas9mzaHKbu-09xf0omfBU9NcAT1bbSJMHgLDMAj3iXm2VgWTK3-wYQAPFJ95VpUl5N-hwRcyJu31ohjqhOSfWnEBqij5nF2zODzke-Zdtr9nz_k2yahAluBBj-ktZxbEp1Y46RrRr57VlrOm7ZKDhQsXHX8shTHpupDz0gUsSGJgbRAV3xyFx2FS8Q6xvTkxFle3Jid7Si1M5buvFRpQPyd0sjHrtnHLAMbLZ2JqcVwlyDlJjdhF6Q9FGK6zW2oputN3P7CQwJGTW-0A4VOY51qhDJqqj33ki4oGbhATgusEMDujvr7dSvmkwTdOqvnNdy4cwvO3FAO1zVR-GEd9REY49F_9UEAvPhHGJyt24kuTLzplZyaDJ71X3hmIV1rPj5PfNvBRQFC_Hb-fwjQKzgtfQvI85yIBIwQZslHX-o0cKQC_y6EZqSpU_FOj4T0pqPq7NHctJXKoXGYoiIYF8cAispiwofcPD8xNmIISE2p8Ads20Uf6rHX2QtaHEW7yZQ0JeGK-Z_4FpaNh0upz7MLG2VGsP3Z1pg1Ua8DIxI8GQFFdJd4R679nwuY6hD28WohrL8qx-wuAClG3N32gEAjFzEDPs8u4Tgg8vkwU56GDDv7dxI8tP5LtUk8hVTiyeRj4Z87WkSDIXpqu5BfdF8gXyDb6GldeqpAcmhEJ0uf8Cikck9NVg-jT8xsWbxypf9Z8P6qbpDwRW5o9JGgVMz6vga5eFYBLUo6Pwr0L-j-ymv4hEavUZeuuqrdz45RMXEYW9CoId3YX6oHUQImzzIFrkhzRRjuPxtt-IGkb9jZqiw4KXBpT6Ves97wD3_apQCdwfrQCO3U1NiR8mdTaux5QPpi_gu84O5C-w7KsZQilRWvx_9jLDuoEuj4Lz1PFbAkAP54-qEknJbemzGUA7YvsWDkssqT9FkVqNhJa4Hjhj_jylFgNXr_qxzrx-O5WzKJxdQ5woXfBSMbY7scPTSWYw85DQFCbQfSU5FozU57lOuXr6NmT7MhXMEoXFTAdG7M5RkCcuyr43DsVpWtlP-pl15v6jx3lgD9xm0S9lna9MoX-9_B1EEzFYEdvfJuMEi7MgD_mdjouad2FTq_quBqGHHwUGJA53alWpbNQ-st0ZntrIYPkt1PAkg6D8gtwIr2xEcIC9st0FL1LZ5LawHxXxoMrYG-0axjODSDq4AC3VbCo7Mn6-WaZ2NvNfsVZuadVn56490M08IWO6jiOUEYBsNkg8XcjdLZa_p0u3DFxHRFdbGUCSy5tMWwNUAKZvTFJDHp2ijQ7OXJS9EtH4YH_KLwqiGcUENVagvn0hkct1aHbAADMfvru7ClNYgDXNjbjs3wvqgVJLXBBCCxcgS6NX1gGg_GFt-KJPm0cAaiUMjQ8pd1Pq3f0LD6uf6J7z8Hqwb0r77wy3vT4OVRSGI_uM4MGyJ6F5h5cnR0THsnRLF8rqmlO2neNC1ZWmUGfOS4iXcyNYoFHSPUY1ko8lLFwZspNhij-3zBRcLoHyECV6W_EVR_pPQV9gxTECPNpHHQ0BhuUhq5Wdw3IdNxxkslEYW2LglYw4OmtWRba9CpQTJzE6TXdiOP--BbSFQSqdCRj_Kuss2bkBXASCwZwg8b_qHxUqRIEBZmPXBBGyxlQPCJ0TZujowwAeYLfYDUz_ovee7zo4KImAIeZYw_q16t9T4fylcCNxPUNFShVUi9XbQ2w6QTDb7Do6z93GPUdEYBJ0osL6LjM3vLjN7RtEF7sSecTV1BN3muBT9p25j6yCDbwS9Yyq25r1d_9hQcbNShx2aJ7IMoYvar4e5ilnuq0ly-DR4y-zcdTtcAkC9T61yuhmksmACJFvNWU1pDDCqvTh_Tff2xqQc651S6wwupjRy1WCWp5kvYLep5Gus-OAW2US4mEhsBuSBX--mLMGL6Ypj8ruIJUG-ZLLpkAFkTPl_C0XEsLChL2-rP-xWjw4AwOSjuVI2vHBNPRzZDDRuGGjHvreCWByIyIYBSzgbVMxsJ7eWB8Gtti3e7Cl6wIvRbmmmzSVOA6Cu_ZXkqJtnxvXfeqR6a34fHN4SB2Z5jHaGPMkCOqOCC3I9s7Tb8zynnaOFx-uPVetdW10yyEgkOb3qT8S7YKRveyvtIJF-O4-4eGSzCaMtIF4hIubrPcLAOlKU0sMBGKhswJV37SgtQD-EXY6MYgqwFOXyypfDFy7vRfeXCFiJawAsUlsUhSjlxMugEhImhlQGX9D14XgkeXqSKr_d-zfpcp6Di63Ctw6h6xeugn4Y86bgY799r7JwCVMTX6VHnwyMm3Uqa6LkkvX_5H1QbJv0asaqpxtC9bpjuEIdHm1-Q-hJt5O0SmRJNjvTW7kOYYn5LH2TRxfAo4oNjuDjnGOz2TAWqKLpm1EqFLYnxi5K32Qo3H0qznJIwwUk0NHEICqCDmdmhiknEqqSkgsRHVFc-sllYDjWPJrDxsJt2xc1K49-Wwv-opNJNTEBwUzzGtqyfVbJ1F-JaWJR4CqTThRGTGJrZi6Mj-jDY-OLw-PKcXGj97Bch14rw8l22Pe_aLMeH5cB3f8tNdTrftDbv2IEZy56AhbUXl6PwzfQKmNp1_0wm2xjebeb6BdPnxHSMnnl_t30ku8tpR_Hkc1c0X-JysatYcVP_97xWj_AZVDkJ3EsyB4cWiIGEAJhNtLxcdWRVL1lbjTtMQ_wzgNzJjy8BXqVDdmt-Qc84CTtVJfrNBOMcgtUc_7_zMMgS5zd5S6L5u1AJ39KLjmwiS8jAIdvy2PAJNaIxITfS6XzA_dH91ZzHxz530dm1o5u2QysGqh1PUQHAe_28r2Zvf3VwNwzIBQjnt3FjnMxu41X5KBuNTTxIaJA8Dw9FZJUCirj4YIPqNp_SPJEq1w5CplZHXG6K7tvtHFpTdgPr3DlrhIe5TgMeoeCoBuddg9j4xxnN85ZxiEmHLaRn9fTFg7bcAcz9IpRS89EkUSHsKm-j_FpftY-Qid9LGsLz2N_rsReg-dazboNKs9Ou5u5CmyKfiKqnpkCjxK4AQ8cmKFtpgd1fq7njDE4DGMvG8WwRLnGL9L1WjMDYhF2NG5jEPa9rrElSGnoVvP5vpcuUdQS_B31LMH2wA4McgQVvWo4keWNn2-kQ0kxF_4s868Qo_hptVTh0aWjvlJvmjAeToiwUn04uYsJNxdvGIiDNr1t7JbU6MwvZQ8kfVv9sU6PemTcYG6YR4usiQfZ2dAZssJj-juTUkM_u4WPiAaNKNmBeyajxFLPZqeSsT742m9_VYdO-4OE0yETZQwf94QM9fne7htU2xB4tIr0cTGPBaPfBAc4sj2OG5kSX8wR-913a5QBuhQDJA2lb-eIUZHl74vzvllR8prOcjT5EJbmmgXSySx-cmPrSnGxNciX6pIB1i7syn47yJg6fQB_HI0_kO_lRbq2kzhvH-xQKTIi7oN2bkXBjbBaMUZDv1A7mk1NnzdlmSuAr89Duzt_wonzv10z0lx4Fw9dxZYqUGv6757C_gKgvAyLbuRSHYj-WDeo_qzc9nZq8VaUgouyNMClfGKFWa49X7t81BWDiVra5b3Tw5Bu1cwMHayaTiOs0VsqVHSBEaczvn6fCxCFomZ__XCHpICe_3o3xxnjQlBtsszmqa2E3-sRY_yQFls4zbkYeeFxkgIXN75_7HQF3ZKJGbHRn3uqD13GRHMVjqj97dxo_yzPqr5Zj3ONYtxqavjWcolva7-3o_ArXRfGOB7SiZr2dGNBIQL6nyzeAwCRKfXmbo-Uvx8GfLxCk4hMHp8KW5DZs03tBeijm7RwHOC83nhqafehzFg92buuz36Xe5TxgBv92nE2YMttRXRblsEQRzWrhElzep8EgqRSgTx5OxMGxTUUASZMSOUQi-7G6NGcRN56MM1UjjxJsceNXxNFj1VmsCTApcqq7jT4091k2fRCm4_kt5bDw5N9BJtA_tbCS2JwTnvUhm8ISpv5oYzZfJu20xhWLKbONV7H2efnRnCfZSL-hv2Oey_vIM5BLilUc3gt8RGw-QfmFNnIUH8qWPyHRYJmZAL5PgIuvSWX6Y-G5WCXD0-sUOX0AkunB-P-7L5bWWO2NOyh_rwzkcbdPa_6oFDxXKDAMHtzccO1Otc75zmpkXCR_zzj89nOfG-8huE78K91BgMP2a5th01NL2yaYjhTvYxw7qzAjk04cvlLDj-UK3Oz5KQYG35AuVx3XG6mdGcHgLDly9VL5KLGY5g7NIKuE3OnEumokkUxgIN0kqwjFpstCkj267PqmEUbJUeHHmHjkGXODxw32MbErvGsecWo3c-OPpxQE_xr7n1q2uiNavcRr0XHuvJsnzHM6sX3yoNW6H4VRz2e7B4kf-bO1JN44pT_jx3aSep6XP6J0YVzyca00ca5aAnj6KQzjCeU7AJa6PkA8pmmhYv6TtqwSadWl3wXmrSIt6-jcizaY4Q0wqolspheMPMpGL1FnzMtr4AB2NS_O_fRHHPz0AJFY3-mn4DQbKw1KOY-wBZJJXa7CaSa-ZkPCqvGii3-_BWyiOfAwLGPfE7qR7NomK5il6k_2TRQK2aa65mI5u5ROSmoP8xQ8RHsW0XtZiSI13FPWpn4ch_N8j0B3oiK5Qs2Weeenfa_tAUACSoQ4jbueai_tecaQSYbnUKnUmeYCJZilHUxsa3tapX2Swhi513y5Vjh1RHOVWFSMy6QcFvKWFoazQEUqsNXmzDTIKAYeCUGgYFCbpalu6tjKz2vWrpqBBm_tHf8u3H05hFQZD5JGZ0GCmMB2sISMljllT4LB5XY89k2P1GIXUr-e6oz7f5HdcHtDdVaFr8tsJiig2PAou8io42VPc55UeM8aFRkt6akO5g3iXvN4V4RvV9UUWbm6dwnlLfB9iaMoeV1qWpxtBLGH2lp2m_aKu_I25J1lX2SPfXFRrTwlPkKrHBrkOQeObvderQp5D6_LuI8Y3xtWHn9BVmg_5nskufnd5ReiSGOnq5_44FapCj3dCTUy5rbkEfs6Pwgae9Yxoj75mrRFead7nrXd_AiHr224UjXHDZusLgzLUcvtTo9xXUHnfJGTzXfyvpl-sg3hItCTm-SdUH_kTmA_yJEj38Y728ZTjUq_P-YoQYdFyveE6OwbotgIxAZjOn6yRxga08fJHHG2ELm47Sz9Bqouk8uKv-gKnIheWk6TeGMdOn2Us1vTzWbwlDXOtFyY6ZdhRcrLf2MnJc4Wb874OuxvCZTqLc6bahv_vTfBN572iCiSFfSO2cXxwqkX3_mS0IK1sjosM76nv1pN9OWUqBchcRDdx0czjYFf6mKP5VgLFUvoLKF4RzLzRbpmqmwbBvvTrUwTfD6vOVMknJymRfHfYEveqduZjMQN05W4VVZZktm8P3imRlGOdvUQp6XfBJNXmm4U-VoREDuISQxcoXTFIdnyZqXCdQvouvkpfLZWT9VKuuO33d-zabjxeqFxpCsXSjP97GFi22arrjnKPg2no-glMiFbYKkQLZMGrJWZOXPOinqENokcQXZFFXrdNCeZ97oP3r1k2kHeg-UQD8H7MQ4jrUVHmgGonl-F86WgfX2V4SfzXxHLY1cXl6jnWPZKBtbQVY3aKZYYucegeIdsU41bdyZvvV6MR2RweSLL_t8tM71A_YS2OdXjrPHIBDPBreNGmlvE0kYWk_uFUaDazF5B_9puQVnjerBihga_PY-16UM1BWL4DA5Z6DSXrRGvDrfaUJycgPQgaaF64tN9AjOuyOdbyxHdy_rtALGM

 -- They are indistinguishable from noise, they are of variable length, and they are the key to your victory.
    Ladies and Gentlemen, give it up for THE ENCRYPTED PADDED FLAG!!! --

Z7slPiJ_t8Aq3Wm4_Yd-uqHXdXrxVfgOjq5tthxXyinrtZfWBhfmSXgLGB14jfZv4_EPcKtEkPB2ITlcBzHrocOuW7QZXAjgwMhzpcOISA4DoteJhw1w-O6AyunM0mdrdXxqTwOwr0jcTArKW06lEqVjDvu8HIxcFORRhDjQxzqyIVPwgXZ_Nsm44ih4knzu1INL1xAnilv1ZnMoAlu-iqwZe5tLhAeZeDf0ZDLWT_6NkzmsvoOcQFwSAjLtGk3u7Zzkaf1xSYAM8SrBejuSGK90q6t-I4Uqrv08mN4ABCWAgLx1uT2jetBMH_Sz7Gb1iytsC9wOzg46Be4d07lKmcyUpd63eDyRranLCzTH1lmFSm5Q0agCwWUcwLZNuiNJK_Y1ZHLnWtXEaoKCW9zHrHHNF_zXVakZlWl66eAZvTkPMhF_SVUZxglXg3FWoRVg-YMmMoAIfiXDYLgDT3cFEryudwacv6jLSMeUMPrt3IL_ktoxOX9ICoiEe3Hk

Good Luck! ~^w^~
```


## Exploitation

Cellular automata are fun and all, but there is a slight inherent problem with the Game of Life. The population can die out and when it does the resulting field is all zeroes, see the figure below.

![](/assets/ctf/zrs.png)

Whenever this occurs, the round key is fully exposed! So from here on out, our exploit strategy will be quite straightforward. For every set of 16 bytes per 64 byte block, we check whether or not any corresponding hash derivates are present in the given key stream. If it is, this implies we have recovered a round key derivate some distance into the key stream. If we manage to recover round keys for all four round keys, and derive them to what they will be at the point of flag encryption, we can set up our own local version and simply find the key stream used to encrypt the flag. Easy peasy.

### Vulnerability Ghost-Checker

To further visualise this procedure, I wrote a little ghost-checker that checks where which round key is exposed. Note that this is a ghost-checker as it uses information not accessible to an attacker. _Note that in the scripts below I still called the class `JSG` instead of `GoS`, but they operate identically._

```py
jsg = JSG()
print(jsg.RKs)
n = 1000
out = []
iii = []
fks = []
kis = [3 - (i % 4) for i in range(n)]
xks = []
for i in range(n):
    for j in range(3):
        for k in range(jsg.spacing):
            jsg.tick()
    xks += [jsg.RKs[(jsg.i // jsg.spacing) % 4]]
    out += [jsg.output()]
    iii += [jsg.i]
    fks += [jsg.RKs]
    print(i+1, end='\r', flush=True)
vln = [out[i] == xks[i] for i in range(n)]
print(sum(vln),'        ')
print(jsg.RKs)
```

```py
plt.figure(figsize=(32,8))
xkslst = [int(i,16) for i in xks]
outlst = [int(i,16) for i in out]
#plt.plot(range(len(outlst)),outlst,c='black',alpha=0.6,zorder=0)
plt.scatter(range(len(xkslst)),xkslst,c='tab:green')
plt.scatter([i for i in range(n) if vln[i]],[xkslst[i] for i in range(n) if vln[i]],c='tab:red',s=500)
for i in range(n):
    if vln[i]:
        plt.text(i,xkslst[i],'{}'.format(kis[i]),fontsize=18,ha='center',va='center',c='white',fontweight='bold')
plt.ylim(0,2**64-1)
plt.xlim(-1,n+1)
plt.show()
```

![](/assets/ctf/vgc.png)

Turns out round keys are exposed quite frequently. Let's see if we can recover them.

### Recovering Round Keys

The following script is an exploit example on a local instantiation of the `GoS` class, see above.

```py
k4s = out[0::4]
k3s = out[1::4]
k2s = out[2::4]
k1s = out[3::4]

found_RKs = []

# For every of the four round keys
for RKi in range(4):

    res = []
    olst = out[3-RKi::4]

    # For every 16-byte outputs
    for i,kk in enumerate(olst):

        ki = kk

        for ok in olst[i+1:]:

            # Triple hash as 12//4 = 3 times a hash is applied between state XORs
            ki = sha256(sha256(sha256(ki.encode()).hexdigest()[:16].encode()).hexdigest()[:16].encode()).hexdigest()[:16]

            # Check for matching 16-byte blocks
            if ok == ki:

                if [olst.index(kk)*4 + (3-RKi), kk] not in res:

                    res += [[olst.index(kk)*4 + (3-RKi), kk]]

                if [olst.index(ok)*4 + (3-RKi), ok] not in res:

                    res += [[olst.index(ok)*4 + (3-RKi), ok]]

    found_RKs += [res]
    print('RK', RKi)

    for ri in res:
        print(ri)

    print()

```
```
RK 0
[79, '282885f5bcf4c433']
[271, '2e75d25cb01d0936']
[587, '759a7cf2fd3e2335']
[679, '25db17884d944100']
[747, '9a26e457a293a11d']

RK 1
[362, '7068f3322c6c8d77']
[382, 'a0d671e3e62923c3']
[646, '446e6b6954879b36']
[746, 'e091e79f2feff66a']
[870, 'b01febfb716b7694']

RK 2
[93, '73f0ba728086aedb']
[113, '302e9178c210d0e4']
[201, '3004a268c27f2cfe']
[289, 'f154d50db8eff779']
[293, 'acf51e7577aa4dc9']
[349, '332cbc6503cbf19d']
[353, 'dcdf9b1cf6004a32']
[641, 'f936915832dd3cbf']
[777, '53bbe6a5a2c71d45']
[789, '06255dc46f70ba54']
[861, '3b10eb5b714d4caf']
[993, 'be4638cf78c6c118']

RK 3
[156, '200311f7c4745a2a']
[436, '7c162a02f10ccc7a']
[588, 'b9ed7d99370d319b']
[800, '8da7a86d6f457676']
[968, '96663c3cb19857ed']


```

Looks like we found quite a few collisions, let's line them up to the same index. The synced index will be the maximum of the mininum indices of every found round key collision.

```py
iii = list(range(36,36000+1,36))
mininds = [i[0][0] for i in found_RKs]

sync_ind = max(mininds)
sync_rks = []

for i in range(4):

    ki = found_RKs[i][0][1]

    for _ in range( sum( [ 1 for i in range(iii[mininds[i]]+1, iii[max(mininds)]+1) if i % (4*12) == 0 ] ) ):

        ki = sha256(ki.encode()).hexdigest()[:16]

    sync_rks += [ki]

print(sync_ind, sync_rks)
```
```
362 ['a6a3185e68def646', '7068f3322c6c8d77', 'd2647070b21eedc4', '30bff585f280bc2a']
```

Now that we have a synced set of round keys, we can just iterate them to the beginning of the flag encryption and XOR its output with the encrypted flag!

```py
# Setting up a local copy with the recover synced round keys
rec_jsg = JSG()

# Set round keys
rec_jsg.RKs = sync_rks

# Set index
rec_jsg.i = (sync_ind+1)*3*12

# Set state
rec_jsg.state = rec_jsg.slicer(sync_rks[ (rec_jsg.i // rec_jsg.spacing) % 4 ])

# Line it up to the flag encryption
rec_stream = rec_jsg.stream((1200-sync_ind-1)*8)
assert jsg.i == rec_jsg.i

# Little check if we have done it correctly
print(jsg.RKs)
print(rec_jsg.RKs)
```
```
['eb2f659d698b2da2', 'a82f725c8ef7297f', '8873205e2e629afd', '3060628f9dab8001']
['eb2f659d698b2da2', 'a82f725c8ef7297f', '8873205e2e629afd', '3060628f9dab8001']
```

```py
assert jsg.xorstream(b'insert_flag_here') == rec_jsg.xorstream(b'insert_flag_here')
```

Ta-da!
```
flag{C0ngr4tul4t10ns_y0u_h4v3_w0n_th3_G4m3_0f_L1f3!}
```

-----
Thanks for reading! <3

~ Polymero
