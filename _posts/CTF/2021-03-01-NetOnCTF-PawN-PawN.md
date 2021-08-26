---
title: NetOn CTF 2021 - PawN PawN
category: CTF
tags: crypto
hidden_tags: write-up
excerpt_separator: <!--more-->
---

Cryptography -- 188 pts (29 solves) -- Chall author: eljoselillo7

Some morse and chess board encodings.

<!--more-->

## Challenge

![](/assets/ctf/Crypto%20-%20PawN%20PawN.png)

## Solution

This challenge provides us with two files, an WAV sound file and a password protected zip file. The WAV file clearly contains morse code that says
```
the zip password is 75757575
```
With this, we unlock the zip file to find a txt file containing some weird codes.
```
8/1P4P1/1PP3P1/1P1P2P1/1P2P1P1/1P3PP1/1P4P1/8 w - - 0 1
8/1PPPPP2/1P6/1P6/1PPPPP2/1P6/1PPPPP2/8 w - - 0 1
8/1PPPPPP1/1PPPPPP1/3PP3/3PP3/3PP3/3PP3/8 w - - 0 1
8/1PPPPPP1/1P4P1/1P4P1/1P4P1/1P4P1/1PPPPPP1/8 w - - 0 1
8/1P4P1/1PP3P1/1P1P2P1/1P2P1P1/1P3PP1/1P4P1/8 w - - 0 1
5P2/3PP3/3P4/3P4/2PP4/3P4/3PP3/5P2 w - - 0 1
8/1PPPPPP1/1P6/1P6/1P6/1P6/1PPPPPP1/8 w - - 0 1
8/1P4P1/1P4P1/1PPPPPP1/1P4P1/1P4P1/1P4P1/8 w - - 0 1
8/1PPPPPP1/1P6/1P6/1PPPPPP1/1P6/1PPPPPP1/8 w - - 0 1
8/1PPPPPP1/1P6/1P6/1P6/1P6/1PPPPPP1/8 w - - 0 1
8/1P2P3/1P1P4/1PP5/1P1P4/1P2P3/1P3P2/8 w - - 0 1
8/8/8/8/8/8/1PPPPPP1/8 w - - 0 1
8/1P4P1/1PP2PP1/1P1PP1P1/1P1PP1P1/1P4P1/1P4P1/8 w - - 0 1
8/3PP3/2P2P2/1P4P1/1PPPPPP1/1P4P1/1P4P1/8 w - - 0 1
8/1PPPPPP1/1PPPPPP1/3PP3/3PP3/3PP3/3PP3/8 w - - 0 1
8/1PPPPP2/1P6/1P6/1PPPPP2/1P6/1PPPPP2/8 w - - 0 1
3P4/4PP2/5P2/5P2/5PP1/5P2/4PP2/3P4 w - - 0 1
```
I recognised this to be a kind of chess code to display board setups, and a quick Google search confirmed this. Every line represents a single chess board, with eight segments, separated by a '/', each with 8 spaces. The spaces can be empty, represented by the numbers, or occupied by a piece, in which case there is a 'P'.

If we create these boards, we find something peculiar... a flag!

![](/assets/ctf/Pawn%20-%20Boards.png)

```
NETON{CHECK_MATE}
```