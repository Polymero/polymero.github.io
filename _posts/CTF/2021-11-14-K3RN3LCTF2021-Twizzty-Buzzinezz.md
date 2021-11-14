---
title: K3RN3LCTF 2021 - Twizzty Buzzinezz
category: CTF
tags: crypto XOR beginner
hidden_tags: my-challenge
excerpt_separator: <!--more-->
---

Cryptography -- 100 pts (116 solves) -- Chall author: Polymero (me)

_"Some bees convinced me to invest in their new cryptosystem. They zzzaid their new XOR keyzztream would revolutionizzze the crypto market. However, they quickly buzzed away so all I have is this weird flyer they dropped. Luckily it has some source code on the back."_  
_"Have I just really been scammed by some bees??"_

<!--more-->

**Encrypted Flag:** `632a0c6d68a7e5683601394c4be457190f7f7e4ca3343205323e4ca072773c177e6e`

**Note:** The flyer is not needed to solve the challenge, it's just for fun.

Files: [honeycomb.py](https://github.com/Kasimir123/K3RN3LCTF-2021/blob/main/downloadable/Twizzty-Buzzinezz/honeycomb.py), [honeycomb_flyer.png](https://github.com/Kasimir123/K3RN3LCTF-2021/blob/main/downloadable/Twizzty-Buzzinezz/honeycomb_flyer.png)

This challenge was part of our very first CTF, [K3RN3LCTF 2021](https://ctftime.org/event/1438).


## Exploration

The provided code and flyer strongly hint at a simple XOR cipher. It seems a base 6-byte key is rotated to create an effective key size of 36 bytes, i.e. the key only repeats itself after 36 bytes. Although this is larger than the flag itself and would therefore create a 'perfect' OTP, the security of the key is still only 6 bytes.


## Exploitation

The HoneyComb cell takes a 6-byte key to produce a XOR stream which, in theory, has a key size of 36 bytes. However, it is very easy to predict once one understands how the stream is generated. With the knowledge of the flag format 'flag{\_\_\_}', 5 of the 6 key bytes are easily recovered. A simple brute-force over a 1-byte space (256) yields the correct flag.

```py
encrypted_flag = bytes.fromhex("632a0c6d68a7e5683601394c4be457190f7f7e4ca3343205323e4ca072773c177e6e")

# Knowing the flag format we can recover five key bytes easily
five_recovered_key_bytes = bytes([encrypted_flag[i] ^ b'flag{'[i] for i in range(5)])

# Which leaves us with 256 possibilities for the final key byte, let's use some brute-force!
for final_key_byte in range(256):
    
    full_key = five_recovered_key_bytes + bytes([final_key_byte])
    
    # Create a keystream from our key using the procedure from the flyer
    key_stream = bytes([full_key[(i - i//6) % 6] for i in range(len(encrypted_flag))])
    
    # Try decrypting the flag
    decrypted_flag = bytes([key_stream[i] ^ encrypted_flag[i] for i in range(len(encrypted_flag))])
    
    # Make sure all bytes are within the flag alphabet
    flag_alphabet = list(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789{_}")
    
    if all([c in flag_alphabet for c in decrypted_flag]):
        print(decrypted_flag.decode())
```

```
flag{7umpl3_XtR_but_31th_4_0w1zzt}
flag{6tmpl3_XuR_but_21th_4_1w1zzt}
flag{5wmpl3_XvR_but_11th_4_2w1zzt}
flag{4vmpl3_XwR_but_01th_4_3w1zzt}
flag{3qmpl3_XpR_but_71th_4_4w1zzt}
flag{2pmpl3_XqR_but_61th_4_5w1zzt}
flag{1smpl3_XrR_but_51th_4_6w1zzt}
flag{0rmpl3_XsR_but_41th_4_7w1zzt}
flag{w5mpl3_X4R_but_s1th_4_pw1zzt}
flag{v4mpl3_X5R_but_r1th_4_qw1zzt}
flag{u7mpl3_X6R_but_q1th_4_rw1zzt}
flag{t6mpl3_X7R_but_p1th_4_sw1zzt}
flag{s1mpl3_X0R_but_w1th_4_tw1zzt}
flag{r0mpl3_X1R_but_v1th_4_uw1zzt}
flag{q3mpl3_X2R_but_u1th_4_vw1zzt}
flag{p2mpl3_X3R_but_t1th_4_ww1zzt}
```

From the above results it should be easy to recognise the true flag.

Ta-da!
```
flag{s1mpl3_X0R_but_w1th_4_tw1zzt}
```

-----
Thanks for reading! <3

~ Polymero