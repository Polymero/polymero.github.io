---
title: San Diego CTF 2021 - Desmos Pro
category: CTF
tags: math rev
hidden_tags: write-up
excerpt_separator: <!--more-->
---

Reversing -- 799 pts (5 solves) -- Chall author: k3v1n

Math lock created in Desmos. Reversable through mathematical investigation.

<!--more-->

## Challenge

![](/assets/ctf/DesmosPro.png)

We are linked to an online Desmos file (see link above), where we are greeted by a red square. If we are able to turn the red square to green, we are able to retrieve the flag.

![](/assets/ctf/DesmosProChall.png)

## Solution

Upon inspection we find that in order to turn the square green we need to find the correct sequence _p_, consisting of 144 elements in {0,1,2,3}. Clearly not brute-forcable :c.

The criteria for the colouring of the square reveal that we need to find _p_ such that _C_=0,
```
C=\left|X\left(l\right)-x_{f}\right|+\left|Y\left(l\right)-y_{f}\right|+\sum_{j=0}^{l}M\left(g\left(0,X\left(j\right),x_{max}-1\right),g\left(0,Y\left(j\right),y_{max}-1\right)\right)
```
From the above we can see that all three elements have to be zero in order for _C_ to become zero. The first element, with the _X_ function, implies that our _p_ sequence needs to have 10 more 1's than 3's, whereas the second element, with the _Y_ function, implies that our _p_ sequence needs to have 10 more 2's than 0's. However, this on its own is still not enough to start brute-forcing our way through. The trick to this challenge is to understand the third element, the scary looking sum. For the sum to be zero, all individual call to _M_ should return zero as it can only return 0 or 1. Interestingly, we note that _M_ is dependent on sequential calls of _X_ and _Y_, hence the order of _p_ seems to matter too.

Knowing all of this, we can set-up a plan. Let us try to investigate the possible outcomes of _M_ given values of _X_ and _Y_. We know that it starts of with l=0, so _X_=0 and _Y_=20, and ends with l=144, so _X_=10 and _Y_=10. When we plot _M_ as a function of both _X_ and _Y_ outputs we find some kind of maze!

![](/assets/ctf/DesmosProMaze.png)

Like mentioned before, we start at _X_=0, _Y_=20 (green dot) and need to end up at _X_=10, _Y_=10 (red dot) in 144 steps. Through testing with the _X_ and _Y_ functions we find that the values of _p_ correspond to moving through the maze in a certain direction following 0: right, 1: down, 2: left, 3: up. We can now find our solution sequence of _p_ to be
```py
[2,2,1,1,0,0,1,1,2,2,1,1,0,0,1,1,1,1,2,2,3,3,2,2,2,2,3,3,3,3,3,3,2,2,2,2,2,2,3,3,2,2,1,1,2,2,2,2,1,1,2,2,1,1,1,1,0,0,0,0,0,0,1,1,0,0,3,3,0,0,0,0,1,1,0,0,0,0,1,1,2,2,1,1,1,1,0,0,1,1,2,2,2,2,3,3,2,2,1,1,2,2,1,1,2,2,2,2,2,2,2,2,3,3,0,0,0,0,0,0,3,3,2,2,2,2,2,2,3,3,3,3,0,0,0,0,0,0,0,0,0,0,3,3]
```
from which we retrieve our flag to be
```
sdctf{440778777}
```
Ta-da!