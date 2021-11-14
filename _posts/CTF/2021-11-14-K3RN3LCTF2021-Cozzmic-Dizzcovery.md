---
title: K3RN3LCTF 2021 - Cozzmic Dizzcovery
category: CTF
tags: crypto XOR fuzzing
hidden_tags: my-challenge
excerpt_separator: <!--more-->
---

Cryptography -- 499 pts (3 solves) -- Chall author: Polymero (me)

_"See that comb over there? It came from that meteorite I mentioned yesterday.
Take a look at this, if I send bytes in, different bytes come out!
Then there's this button that seems to just produce random bytes... 
I'm absolutely stumped :S"_

<!--more-->

nc ctf.k3rn3l4rmy.com 2239

Files: [pandorascomb.py](https://github.com/Kasimir123/K3RN3LCTF-2021/blob/main/server-files/cozzmic-dizzcovery/PandorasComb.py)

This challenge was part of our very first CTF, [K3RN3LCTF 2021](https://ctftime.org/event/1438).


## Exploration

On the surface players are presented with a schematic of the comb and a short explanation of how it works.

```
|
|  "Here, this is that Comb I was talking about..."
|
|
|           15                           26
|             \  17    18     19    20  /
|    14   16   \ |     |       |     | /   21   25
|      \  |     \|     |       |     |/     |  /
|       \ |      |_____|       |_____|      | /
|   13   \|      /     \       /     \      |/   24
|     \   |_____/       \_____/       \_____|   /
|      \  /     \       /     \       /     \  /
|       \/       \_____/       \_____/       \/
|   12   \       /     \       /     \       /   23
|     \   \_____/       \_____/       \_____/   /
|      \  /     \       /     \       /     \  /
|       \/       \_____/       \_____/       \/
|   11  /\       /     \       /     \       /\  22
|     \/  \_____/       \_____/       \_____/  \/
|     /\  /     \       /     \       /     \  /\
|   10  \/       \_____/       \_____/       \/  31
|       /\       /     \       /     \       /\
|      /  \_____/       \_____/       \_____/  \
|     /   /     \       /     \       /     \   \
|    9   /       \_____/       \_____/       \   30
|       /\       /     \       /     \       /\
|      /  \_____/       \_____/       \_____/  \
|     /   |     \       /     \       /     |   \
|    8   /|      \_____/       \_____/      |\   29
|       / |      |     |       |     |      | \
|      /  |     /|     |       |     |\     |  \
|     7   0    / |     |       |     | \    5   28
|             /  1     2       3     4  \
|            6                           27
|
|
|
|  "It seems any byte-ray we send in, interacts with the vertices of the Comb."
|  "At every vertex, the ray XORs itself with the internal state of the Comb at said vertex."
|  "So, we have new_state = new_ray = ray ^ state."
|
|   "The numbers in the schematic represent the directions from which we can shoot our bytes through the Comb."
|
|
|  "What shall we do with it?"
|
|   [1] Send a byte
|   [2] Press the button
|   [3] Shake the Comb (angrily)
|   [4] Run away
|
```

We can send arbitrary bytes along arbitrary bytes through the box, as many times as we want.

```
|
|  "What do you want to send and where?" - (direction, byte) e.g. (1, 255)
|
|  >> (2, 190)
|
|  And out comes: 85
|
```

Pressing the button will send the flag bytes along randomly chosen paths and reveals the outgoing byte-values to us.

```
|
|  "Alright, here goes nothing..."
|
|   (5, 133)
|   (0, 188)
|   (4, 36)
|   (5, 167)
|   (4, 46)
|   (2, 244)
|   (1, 233)
|   (1, 159)
|   (2, 29)
|   (2, 125)
|   (0, 111)
|   (3, 56)
|   (0, 52)
|   (2, 135)
|   (5, 85)
|   (0, 196)
|   (5, 205)
|   (2, 53)
|   (3, 64)
|   (3, 192)
|   (1, 102)
|   (1, 18)
|   (2, 16)
|   (5, 144)
|   (4, 133)
|   (3, 0)
|   (1, 202)
|   (1, 204)
|   (4, 191)
|   (4, 209)
|   (2, 38)
|   (0, 241)
|   (5, 249)
|   (0, 232)
|   (1, 148)
|   (0, 232)
|   (3, 141)
|   (2, 241)
|   (2, 94)
|   (0, 82)
|   (5, 99)
|   (1, 169)
|   (3, 90)
|   (3, 108)
|   (1, 239)
|   (2, 168)
|   (2, 5)
|   (4, 172)
|   (5, 218)
|
```

Let us dive into the source code of this cosmic mystery box.

```py
class PandorasComb:
    def __init__(self,key_62):
        if type(key_62) == str:
            key_62 = bytes.fromhex(key_62)
        self.key = key_62
        key_62 = list(key_62)
        self.state = [[' ']+key_62[:9]+[' '],key_62[9:20],key_62[20:31],
                       key_62[31:42],key_62[42:53],[' ']+key_62[53:]+[' ']]
        
    def shoot(self, indir, ray, verbose=False):
        shoot_dic = {
            0  : [[0,1],[0,2],[0,3],[0,4],[0,5],[0,6],[0,7],[0,8],[0,9]],
            1  : [[1,0],[1,1],[1,2],[1,3],[1,4],[1,5],[1,6],[1,7],[1,8],[1,9],[1,10]],
            2  : [[2,0],[2,1],[2,2],[2,3],[2,4],[2,5],[2,6],[2,7],[2,8],[2,9],[2,10]],
            3  : [[3,0],[3,1],[3,2],[3,3],[3,4],[3,5],[3,6],[3,7],[3,8],[3,9],[3,10]],
            4  : [[4,0],[4,1],[4,2],[4,3],[4,4],[4,5],[4,6],[4,7],[4,8],[4,9],[4,10]],
            5  : [[5,1],[5,2],[5,3],[5,4],[5,5],[5,6],[5,7],[5,8],[5,9]],
            6  : [[1,0],[2,0],[2,1],[3,1],[3,2],[4,2],[4,3],[5,3],[5,4]],
            7  : [[0,1],[1,1],[1,2],[2,2],[2,3],[3,3],[3,4],[4,4],[4,5],[5,5],[5,6]],
            8  : [[0,2],[0,3],[1,3],[1,4],[2,4],[2,5],[3,5],[3,6],[4,6],[4,7],[5,7],[5,8]],
            9  : [[0,4],[0,5],[1,5],[1,6],[2,6],[2,7],[3,7],[3,8],[4,8],[4,9],[5,9]],
            10 : [[0,6],[0,7],[1,7],[1,8],[2,8],[2,9],[3,9],[3,10],[4,10]],
            11 : [[0,4],[0,3],[1,3],[1,2],[2,2],[2,1],[3,1],[3,0],[4,0]],
            12 : [[0,6],[0,5],[1,5],[1,4],[2,4],[2,3],[3,3],[3,2],[4,2],[4,1],[5,1]],
            13 : [[0,8],[0,7],[1,7],[1,6],[2,6],[2,5],[3,5],[3,4],[4,4],[4,3],[5,3],[5,2]],
            14 : [[0,9],[1,9],[1,8],[2,8],[2,7],[3,7],[3,6],[4,6],[4,5],[5,5],[5,4]],
            15 : [[1,10],[2,10],[2,9],[3,9],[3,8],[4,8],[4,7],[5,7],[5,6]]
        }
        if indir > 15:
            indir %= 16
            path = shoot_dic[indir]
            for i in range(len(shoot_dic[indir])):
                ray ^= self.state[path[-(i+1)][0]][path[-(i+1)][1]]
                self.state[path[-(i+1)][0]][path[-(i+1)][1]] = ray
        else:
            path = shoot_dic[indir]
            for i in range(len(path)):
                ray ^= self.state[path[i][0]][path[i][1]]
                self.state[path[i][0]][path[i][1]] = ray
        if verbose:
            print(self.state)
        return ray

PB = PandorasComb(os.urandom(62))
```

The source code does not reveal anything we weren't already told. The ray travels along the vertices of the chosen path and XORs with the state byte-value until it reaches the end of the box. Both the state and the ray byte-values are updated upon XORing.

All in all, we have found the following **key observations**.

- We are allowed to shoot as many test bytes as we want.
- The script uses only XOR operations and therefore the XOR identities will likely be crucial in solving this challenge.


## Exploitation

Our approach will consist of the following steps.

1. Recover the full internal state of the box.
2. Using a secondary box to 'brute-force' the flag.

The crux here is that shooting rays through the box is actually a cyclic operation. After 16 consecutive rays along the same path, the path is reset to its original state. So let's shoot 16 rays through all rows of the box and check whether the final state is equivalent to the initial state.

```py
#!/usr/bin/env python3

# IMPORTS
import os
import random

# LOCAL IMPORTS
from PandorasComb_Class import PandorasComb 
from flags import flag_pandoras_box as FPB

# SOLUTION
# Set up a Comb
PC = PandorasComb(os.urandom(62))

# Get initial state (for check)
initial_state = PC.state
print(initial_state)

# Cycle length
n = 16

# Get all the rays
run_0 = [PC.shoot(0, 0) for _ in range(n)]
run_1 = [PC.shoot(1, 0) for _ in range(n)]
run_2 = [PC.shoot(2, 0) for _ in range(n)]
run_3 = [PC.shoot(3, 0) for _ in range(n)]
run_4 = [PC.shoot(4, 0) for _ in range(n)]
run_5 = [PC.shoot(5, 0) for _ in range(n)]

# Get current state (for check)
current_state = PC.state
print(current_state)

# Check
assert initial_state == current_state
```

Awesome! Now we can use some XOR math to arrive at equations for both the 11- and 9-bytes long rows. More specifically, let us check out what happens inside the box for an 11-byte row. Note that the input is always a zero-byte and the output is equivalent to the final state value 'x11'.

| x1 | x2 | x3 | x4 | x5 | x6 | x7 | x8 | x9 | x10 | x11 |
| ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- |
| 1 | 1 2 | 1 2 3 | 1 2 3 4 | 1 2 3 4 5 | 1 2 3 4 5 6 | 1 2 3 4 5 6 7 | 1 2 3 4 5 6 7 8 | 1 2 3 4 5 6 7 8 9 | 1 2 3 4 5 6 7 8 9 10 | 1 2 3 4 5 6 7 8 9 10 11 |
| 1 | 2   | 1 3   | 2 4     | 1 3 5     | 2 4 6       | 1 3 5 7       | 2 4 6 8         | 1 3 5 7 9         | 2 4 6 8 10           | 1 3 5 7 9 11            |
| 1 | 1 2 | 2 3   | 3 4     | 1 4 5     | 1 2 5 6     | 2 3 6 7       | 3 4 7 8         | 1 4 5 8 9         | 1 2 5 6 9 10         | 2 3 6 7 10 11           |
| 1 | 2   | 3     | 4       | 1 5       | 2 6         | 3 7           | 4 8             | 1 5 9             | 2 6 10               | 3 7 11                  |
| 1 | 1 2 | 1 2 3 | 1 2 3 4 | 2 3 4 5   | 3 4 5 6     | 4 5 6 7       | 5 6 7 8         | 1 6 7 8 9         | 1 2 7 8 9 10         | 1 2 3 8 9 10 11         |
| 1 | 2   | 1 3   | 2 4     | 3 5       | 4 6         | 5 7           | 6 8             | 1 7 9             | 2 8 10               | 1 3 9 11                |
| 1 | 1 2 | 2 3   | 3 4     | 4 5       | 5 6         | 6 7           | 7 8             | 1 8 9             | 1 2 9 10             | 2 3 10 11               |
| 1 | 2   | 3     | 4       | 5         | 6           | 7             | 8               | 1 9               | 2 10                 | 3 11                    |
| 1 | 1 2 | 1 2 3 | 1 2 3 4 | 1 2 3 4 5 | 1 2 3 4 5 6 | 1 2 3 4 5 6 7 | 1 2 3 4 5 6 7 8 | 2 3 4 5 6 7 8 9   | 3 4 5 6 7 8 9 10     | 4 5 6 7 8 9 10 11       |
| 1 | 2   | 1 3   | 2 4     | 1 3 5     | 2 4 6       | 1 3 5 7       | 2 4 6 8         | 3 5 7 9           | 4 6 8 10             | 5 7 9 11                |
| 1 | 1 2 | 2 3   | 3 4     | 1 4 5     | 1 2 5 6     | 2 3 6 7       | 3 4 7 8         | 4 5 8 9           | 5 6 9 10             | 6 7 10 11               |
| 1 | 2   | 3     | 4       | 1 5       | 2 6         | 3 7           | 4 8             | 5 9               | 6 10                 | 7 11                    |
| 1 | 1 2 | 1 2 3 | 1 2 3 4 | 2 3 4 5   | 3 4 5 6     | 4 5 6 7       | 5 6 7 8         | 6 7 8 9           | 7 8 9 10             | 8 9 10 11               |
| 1 | 2   | 1 3   | 2 4     | 3 5       | 4 6         | 5 7           | 6 8             | 7 9               | 8 10                 | 9 11                    |
| 1 | 1 2 | 2 3   | 3 4     | 4 5       | 5 6         | 6 7           | 7 8             | 8 9               | 9 10                 | 10 11                   |
| 1 | 2   | 3     | 4       | 5         | 6           | 7             | 8               | 9                 | 10                   | 11                      |

As you can see, the internal state is cyclic with a period of 'just' 16 inputs! Moreover, we can now recover the 11-state rows by collecting the first 11 outputs (written as A-K) as follows.

$$ x1 = A C I K $$

$$ x2 = A B I J $$

$$ x3 = A B C I J K $$

$$ x4 = A B C D E F G H $$

$$ x5 = B D F H $$

$$ x6 = C D G H $$

$$ x7 = D H $$

$$ x8 = E F G H $$

$$ x9 = A C F H I K $$

$$ x10 = A B G H I J $$

$$ x11 = A B C H I J K $$

We can do apply the same technique to recover the 9-byte rows and end up with the following.

$$ x1 = A I $$

$$ x2 = A B C D E F H $$

$$ x3 = B D F H $$

$$ x4 = C D G H $$

$$ x5 = D H $$

$$ x6 = E F G H $$

$$ x7 = F H $$

$$ x8 = G H $$

$$ x9 = A H I $$

Or in code:

```py
# Recover the initial state
def rec_run_9(run: list):
    return [run[0]^run[8], 
            run[0]^run[1]^run[2]^run[3]^run[4]^run[5]^run[6]^run[7],
            run[1]^run[3]^run[5]^run[7], 
            run[2]^run[3]^run[6]^run[7], 
            run[3]^run[7],
            run[4]^run[5]^run[6]^run[7], 
            run[5]^run[7], 
            run[6]^run[7], 
            run[0]^run[7]^run[8]]

def rec_run_11(run: list):
    return [run[0]^run[2]^run[8]^run[10], 
            run[0]^run[1]^run[8]^run[9], 
            run[0]^run[1]^run[2]^run[8]^run[9]^run[10],
            run[0]^run[1]^run[2]^run[3]^run[4]^run[5]^run[6]^run[7], 
            run[1]^run[3]^run[5]^run[7],
            run[2]^run[3]^run[6]^run[7], 
            run[3]^run[7], 
            run[4]^run[5]^run[6]^run[7],
            run[0]^run[2]^run[5]^run[7]^run[8]^run[10], 
            run[0]^run[1]^run[6]^run[7]^run[8]^run[9],
            run[0]^run[1]^run[2]^run[7]^run[8]^run[9]^run[10]]

state_0 = rec_run_9(run_0)
state_1 = rec_run_11(run_1)
state_2 = rec_run_11(run_2)
state_3 = rec_run_11(run_3)
state_4 = rec_run_11(run_4)
state_5 = rec_run_9(run_5)

print(state_0,state_1,state_2,state_3,state_4,state_5)
```

With a reconstructed internal state of the box, we can simply iterate over the possible inputs (along the correct path) to find the input that yields the correct output.

```py
key_rec = state_0+state_1+state_2+state_3+state_4+state_5

# Make FLAG (press the button)
indirs = []
outbyt = []
for i,byt in enumerate(FPB):
    indirs.append(int(os.urandom(1)[0]/256*36))
    outbyt.append(PC.shoot(indirs[i], byt))

print(indirs)
print(outbyt)

# Make second Comb object with recovered state
# And iteratively (brute-force) the flag back
flag = ''
for _ in range(len(outbyt)):
    i = len(flag)
    while True:
        inbyt = random.choice(list('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_}{'))
        PCrec = PandorasComb(key_rec)
        for j in range(i):
            PCrec.shoot(indirs[j], ord(flag[j]))
        try_out = PCrec.shoot(indirs[i], ord(inbyt))
        if try_out == outbyt[i]:
            flag += inbyt
            print(flag)
            break

# Print flag
print(flag)
```

Ta-da!

```
flag{0h_b01_y0u_ju5t_H4D_t0_0p3n_P4nd0r4s_B0x_d1dnt_y0u}
```

-----
Thanks for reading! <3

~ Polymero