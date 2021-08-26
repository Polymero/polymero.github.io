---
title: NetOn CTF 2021 - Gotta catch em flag
category: CTF
tags: GBA misc
hidden_tags: write-up
excerpt_separator: <!--more-->
---

Misc -- 248 pts (6 solves) -- Chall author: Troyano

A flag hidden inside a Pokémon game, more like Pogémon amirite...

<!--more-->

## Challenge

![](/assets/ctf/Misc%20-%20Gotta%20catch%20em%20flag.png)

## Solution

With such a title, I'm expecting some kind of link to Pokémon, which would be amazing :). Anyway, we are given a simple JPG image, nothing suspicous so far. However, a quick binwalk tells us otherwise
```sh
$ binwalk NETON.jpg 
```
```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
30            0x1E            TIFF image data, big-endian, offset of first image directory: 8
476           0x1DC           Copyright string: "Copyright (c) 1998 Hewlett-Packard Company"
122067        0x1DCD3         RAR archive data, version 5.x

```
Mmh... a RAR file attached to the image, okay. Let's extract it. Now we find a File.zip which is password protected :c, and a folder called 'EmuCR-no$gba-w'. An GBA emulator of some sorts??? Are we actually going to play Pokémon, that would be great. Hey, there's a Pokémon Fire Red save file in here. After sneaking in a ROM file, and booting up the emulator, we are greeted by a lovely surprise

![](/assets/ctf/Catch%20-%20Save.png)

![](/assets/ctf/Catch%20-%20Team.png)

Alright, sure thing! Let's look at our box.

![](/assets/ctf/Catch%20-%20Guacamole.png)

![](/assets/ctf/Catch%20-%20Fries.png)

So the password for the zip is '334355GUACAMOLEFRIES', lovely! In it, we find Flag.txt containing our flag safely encoded in base64... but not for long!
```
NETON{7h3_r34l_fl46_15_h3r3}
```