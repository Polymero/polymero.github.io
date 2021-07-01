---
title: NetOn CTF 2021 - Run Run Run
category: CTF
tags: Write-up Scripting Web
excerpt_separator: <!--more-->
---

Scripting -- 215 pts (22 solves) -- Chall author: X4v1l0k

Scripting to solve randomised equations on a website.

<!--more-->

## Challenge

![](/assets/ctf/Coding%20-%20Run%20Run%20Run.png)

## Solution

So this site shows a simple equation and challenges us to send the answer, encoded in an MD5 hash, before the time runs out. Doing it by hand is not an option... Furthermore, it seems like the equation is always of the form A * B - C, were all of the variables are 3-digit integers. So we can just set-up an easy static Python script, using the requests and hashlib libraries. _Note that the equation on the site does not refresh upon request, but on a small time interval. This allows us to first request the page (GET) and then send the answer back to the server (POST), as long as we supply it our cookie as well (!)_
```py
#!/usr/bin/env python

# Imports
import requests
import hashlib

# Headers
headers = {
	"Connection": "keep-alive",
	"Cookie": "PHPSESSID=mfn12kjrqc85sb83rf0v0dm5af"
}

# Request page
push = requests.get("http://167.99.129.209:7777/index.php",headers=headers)

# Extract the equation 
strsum = push.text[196:211]
print strsum

# Compute the answer of the equation
res = int(strsum[0:3]) * int(strsum[6:9]) - int(strsum[12:15])
print res

# Get the MD5 hash
md5 = hashlib.md5(str(res)).hexdigest()
print md5

data = {
	"md5": md5
}

# Send it back
push = requests.post("http://167.99.129.209:7777/index.php",headers=headers,data=data)

print push.text
```
Within the printed HTML we find our flag, along with a nice compliment
```
Nice script! Take your flag: NETON{ScR1pT1ng_5a9522b8a3a9d3e2a3bf373803fa8e6c}
```