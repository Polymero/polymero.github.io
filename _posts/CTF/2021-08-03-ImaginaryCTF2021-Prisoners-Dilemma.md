---
title: ImaginaryCTF 2021 - Prisoner's Dilemma
category: CTF
tags: misc jail
hidden_tags: write-up
excerpt_separator: <!--more-->
---

Misc -- 200 pts (63 solves) -- Chall author: Robin_Jadoul

A fun little VIM jail. Most of our ways out are blocked by mapping the necessary keys to nothing. Even if we do get out, the connection is immediately broken. Luckily, there is still a way we can get to ex-mode to escape.

<!--more-->

Check out write-ups by my teammates on [K3RN3L4RMY.com](http://k3rn3l4rmy.com/writeups)

## Exploration

![](/assets/ctf/PrisonersDilemma_chall.png)

We are given a SSH key and address. Upon connecting we are immediately dumped into VIM, a console text editor. Seems like we have violated the Law. We couldn't pay the court a fine and have to serve our sentance. On top of that, our stolen flags are now forfeit T_T. Poor references aside, most of our ways to escape this VIM jail have been blocked by remapping the ':', 'Q', and '!' keys to nothing. We will have to do without those. 

At first I thought we could simply type in 'flag.txt' and use 'gf' to open said file, but as the challenge description stated, there is no 'flag.txt'. Only another file, with an unknown filename.

We need to find a way to get to ex(ecution)-mode within VIM...

## Exploitation

Usually one would use 'Q' for that, but this has been blocked. As I read through some help files on the internet I encountered another key mapping that might prove useful here, 'gQ'. Although I did not expect it to work due to the remapping of 'Q', I was desperate enough to give it a try regardless. And... it worked! _(please don't ask me why :p)_

Now that we got to ex-mode, we simply open a shell using
```
:/bin/bash
```
and ta-da. We. Are. In. Let's cat that flag!
```
bash-5.0$ ls
0696b44f21ad9d1f.ext  run.sh
bash-5.0$ cat 0696b44f21ad9d1f.ext 
ictf{how_did_you_do_it?_I_us3d_the_=_register}
```

Ta-da!
```
ictf{how_did_you_do_it?_I_us3d_the_=_register}
```
