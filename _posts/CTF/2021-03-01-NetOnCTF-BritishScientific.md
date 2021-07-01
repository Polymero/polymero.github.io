---
title: NetOn CTF 2021 - BritishScientific
category: CTF
tags: Write-up Playfair
excerpt_separator: <!--more-->
---

Crypto -- 242 pts (11 solves) -- Chall author: Wozen

Playfair cipher with hinted key in challenge flavourtext.

<!--more-->

## Challenge

![](/assets/ctf/Crypto%20-%20BritishScientific.png)

This challenge is surprisingly straightforward, we are provided with the following quote in a txt file
```
Viewing the laws of the electric circuit from the point at which 
the labours of Ohm has placed us, there is scarcely any branch of 
experimental science in which so many and such various phenomena 
are expressed by formulae of such simplicity and generality...

QRRXDRPCKESRSNSWWY
```
Google tells us that the quote comes from Charles Wheatstone, who also invented the Playfair cipher! So the encrypted txt at the bottom is likely to be encoded in a playfair cipher. However, to decipher it, we need a 5x5 'key' matrix.

## Solution

The challenge also tells us that 'He always signs with his name and surname...'. This led me to believe he used the matrix as follows
```
C H A R L
E S W T O
N B D F G
I K M P Q
U V X Y Z
```
Indeed he did as deciphering the code with the above 'key' matrix nicely gives us our flag
```
NETON{PLAYFAIRISTHEBESTX}
```