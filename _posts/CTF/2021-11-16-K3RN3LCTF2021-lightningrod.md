---
title: K3RN3LCTF 2021 - lightningrod
category: CTF
tags: rev brute-force
hidden_tags: my-challenge
excerpt_separator: <!--more-->
---

Reverse Engineering -- 499 pts (3 solves) -- Chall author: Polymero (me)

_"Warning: Weather Control Device detected! **ZAP ZAP** [insert conscript_death.mp3 here]"_

_"Note: there is a typo in the flag, sorry >m<."_

<!--more-->

nc ctf.k3rn3l4rmy.com 2245

Files: [lightningrod](https://github.com/Kasimir123/K3RN3LCTF-2021/blob/main/downloadable/lightningrod/lightningrod), [burned.crisp](https://github.com/Kasimir123/K3RN3LCTF-2021/blob/main/downloadable/lightningrod/burned.crisp)

Source code (not provided during CTF): [lightningrod.C](https://github.com/Kasimir123/K3RN3LCTF-2021/blob/main/source-code/lightningrod/lightningrod.c)

This challenge was part of our very first CTF, [K3RN3LCTF 2021](https://ctftime.org/event/1438).


## Exploration

We are given a binary `lightningrod` and a seemingly random dump file `burned.crisp`. Plugging the binary into a decompiler we find three functions. Let us take a look at them one by one.

```C
undefined8 main(undefined8 param_1,long param_2)

{
  undefined uVar1;
  FILE *pFVar2;
  size_t __size;
  uchar *__ptr;
  void *__ptr_00;
  int local_1c;
  
  pFVar2 = fopen(*(char **)(param_2 + 8),"rb");
  fseek(pFVar2,0,2);
  __size = ftell(pFVar2);
  __ptr = (uchar *)malloc(__size);
  rewind(pFVar2);
  fread(__ptr,1,__size,pFVar2);
  fclose(pFVar2);
  __ptr_00 = (void *)rumble(__ptr,__size);
  local_1c = 0;
  while ((long)local_1c < (long)(((__size + 2) / 3) * 4 + -1)) {
    uVar1 = strike(*(uchar *)((long)__ptr_00 + (long)local_1c));
    *(undefined *)((long)local_1c + (long)__ptr_00) = uVar1;
    local_1c = local_1c + 1;
  }
  pFVar2 = fopen("burned.crisp","wb");
  fwrite(__ptr_00,1,((__size + 2) / 3) * 4,pFVar2);
  fclose(pFVar2);
  free(__ptr);
  return 0;
}
```

We see that the function `main()` opens a file, reads it, and runs it through one of the other functions called `rumble()`. The output is then one-by-one put into the final function `strike()`, where the output replaces the input array value. Finally, it writes the output array to the dump file `burned.crisp`.

```C
void * rumble(uchar *param_1,ulong param_2)

{
  long lVar1;
  void *pvVar2;
  ulong uVar3;
  long local_18;
  ulong local_10;
  
  lVar1 = ((param_2 + 2) / 3) * 4;
  pvVar2 = malloc(lVar1 + 1);
  *(undefined *)(lVar1 + (long)pvVar2) = 0;
  local_10 = 0;
  local_18 = 0;
  while (local_10 < param_2) {
    if (local_10 + 1 < param_2) {
      uVar3 = (ulong)CONCAT11(param_1[local_10],param_1[local_10 + 1]);
    }
    else {
      uVar3 = (ulong)param_1[local_10] << 8;
    }
    if (local_10 + 2 < param_2) {
      uVar3 = (ulong)param_1[local_10 + 2] | uVar3 << 8;
    }
    else {
      uVar3 = uVar3 << 8;
    }
    *(char *)(local_18 + (long)pvVar2) =
         "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[uVar3 >> 0x12];
    *(char *)((long)pvVar2 + local_18 + 1) =
         "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
         [(uint)(uVar3 >> 0xc) & 0x3f];
    if (local_10 + 1 < param_2) {
      *(char *)((long)pvVar2 + local_18 + 2) =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
           [(uint)(uVar3 >> 6) & 0x3f];
    }
    else {
      *(undefined *)((long)pvVar2 + local_18 + 2) = 0x3d;
    }
    if (local_10 + 2 < param_2) {
      *(char *)((long)pvVar2 + local_18 + 3) =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[(uint)uVar3 & 0x3f];
    }
    else {
      *(undefined *)((long)pvVar2 + local_18 + 3) = 0x3d;
    }
    local_10 = local_10 + 3;
    local_18 = local_18 + 4;
  }
  return pvVar2;
}
```

Looking into the function `rumble()` we see multiple strings that contain the full url-safe base64 alphabet. Combined with the memory allocation ('malloc()') of $((x + 2) / 3) * 4$ bytes, where $x$ is the original byte array length, points us towards a simple base64 encoding function. If still unsure, some quick googling should result in similar functions.

```C
byte strike(uchar param_1)

{
  byte bVar1;
  byte bVar2;
  int iVar3;
  byte local_1c;
  uint local_c;
  
  local_c = 0;
  local_1c = param_1;
  while ((int)local_c < 0x17) {
    bVar1 = state[ini];
    bVar2 = bVar1 ^ local_1c;
    state[ini] = bVar2;
    if (bVar1 < local_1c) {
      ini = ini + 0xb;
    }
    else {
      ini = ini + 10;
    }
    if ((local_c & 1) == 0) {
      iVar3 = ((int)local_c / 2) * -0x15 + ini + -0xb;
      if (iVar3 == -1) {
        ini = ini + 10;
      }
      if (iVar3 == 10) {
        ini = ini + -10;
      }
    }
    ini = ini % 0xf2;
    local_c = local_c + 1;
    local_1c = bVar2;
  }
  return local_1c;
}
```

This is where the magic happens. The function `strike()` takes a single byte and runs a loop for 23 iterations. Within this loop it XORs the input byte with the byte in the state array at index `ini`, which appears to be a global variable (not defined within this function). Both the state byte and the input byte are set to the XOR result before going to the next iteration. Furthermore, the index value `ini` is adjusted depending on the values of the current input byte and state byte. More specifically, it depends on whether or not the current input byte is smaller or larger than the state byte. Interesting here is to see that the index value `ini` is modded with 242 at the end of every iteration. Together with the index steps of 10 and 12 and the check for odd row numbers, this suggests we are in fact dealing with a state array that is supposed to mimic some kind of 2D board with interlaced rows of lengths 11 and 10. As our input 'drops' through the board it bounces left and right depending on the $<$ and $>$ checks.

To give a visual representation of the algorithm, it looks like this.

![](/assets/ctf/new_lightning_storm.gif)


## Exploitation

In order to recover the original input file from the `burned.crisp` dump file, we will have to recreate our own version of the algorithm. What follows is a Python implementation of the algorithm within the binary. Note that I included a 'fake' function that tests the result for an input byte but does not actually adjust the state array, this will come in handy later on.

```py
class Hachinko:
    def __init__(self, width, height, random=False):
        self.width = width
        self.height = 2*height+1
        if random:
            self.state = [[i for i in os.urandom(width)]]
        else:
            self.state = [[0 for _ in range(width)]]
        for _ in range(height):
            if random:
                self.state += [[i for i in os.urandom(width-1)]]
                self.state += [[i for i in os.urandom(width)]]
            else:
                self.state += [[0 for _ in range(width-1)]]
                self.state += [[0 for _ in range(width)]]
        self.i = width//2
            
    def drop(self, ray):
        inp = self.i
        #self.i = (self.i + 1) % self.width
        inps = [inp]
        for i in range(self.height):
            pin = self.state[i][inp]
            new_ray = pin ^ ray
            self.state[i][inp] = new_ray
            if ray <= pin:
                inp += (-1 + i % 2)
            if ray > pin:
                inp += (i % 2)
            inp %= (self.width - 1 + i % 2)
            inps += [inp]
            ray = new_ray
        self.i = inps[-1]
        return ray, inps
    
    def fake_drop(self, ray):
        inp = self.i
        for i in range(self.height):
            pin = self.state[i][inp]
            new_ray = pin ^ ray
            if ray <= pin:
                inp += (-1 + i % 2)
            if ray > pin:
                inp += (i % 2)
            inp %= (self.width - 1 + i % 2)
            ray = new_ray
        return ray
```

Now that we have a working Python implementation we can simply try to recover the original file one base64 encoded character at a time. We iterate over input characters and check whether or not the output character matches with our `burned.crisp` dump file, using the `fake_drop()` function. In order to not get lost in the non-negligible amount of false positives, it is important to implement backtracking, i.e. allow the algorithm to go back a step when a step exhausts its possibilities. I did this using the following code, but there are multiple ways to go about this for sure. _Note that this script comes up with multiple possible original inputs, however their small differences don't actually matter._

```py
size = 11

with open('burned.crisp','rb') as f:
    ENC = f.read()
    f.close()

ALP = list(rb'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-')

potential_flags = []
REC  = [0] * len(ENC)
k = 0

T0 = time.time()
while True:
    
    try:
    
        if k == -1:
            raise KeyboardInterrupt
            break

        if REC[k] > len(ALP) - 1:
            REC[k] = 0
            REC[k-1] += 1
            k -= 1
            continue

        ho = Hachinko(size,size)
        for i in range(k):
            ho.drop(ALP[REC[i]])

        #print(len(potential_flags), bytes(ALP[j] for j in REC))
        #print()
        print('{}  {} / {}         '.format(len(potential_flags),k,len(ENC)),end='\r',flush=True)

        for i in range(REC[k],len(ALP)):

            out = ho.fake_drop(ALP[i])

            if out == ENC[k]:

                if k == len(ENC) - 1:
                    REC[k] = i
                    potential_flags += [bytes([ALP[j] for j in REC])]
                
                else:

                    REC[k] = i
                    k += 1
                    break

            if i >= len(ALP) - 1:
                REC[k] = 0
                REC[k-1] += 1
                k -= 1
                
    except KeyboardInterrupt:
        print('\n\n-------- POTENTIAL FLAGS --------\n')
        for i in potential_flags:
            print(i)
        print('\n')
        break

T1 = time.time()

print('It took {:.2f} sec\n'.format(T1-T0))
```

Converting the resulting input base64 encoded data into bytes and storing it as a file should reveal it is in fact the following JPEG image.

![](/assets/ctf/legitflag.jpg)

Ta-da!
```
flag{l1ght1ng_n3v3r_str1k3s_th3_s4m3_f00l_tw1c3_r1ght?}
```

-----
Thanks for reading! <3

~ Polymero