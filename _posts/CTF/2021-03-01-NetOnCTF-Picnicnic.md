---
title: NetOn CTF 2021 - Picnicnic
category: CTF
tags: web cookies
hidden_tags: write-up
excerpt_separator: <!--more-->
---

Web -- 222 pts (20 solves) -- Chall author: eljoselillo7

Simple cookie trail containing base64 encoded pieces of the flag.

<!--more-->

## Challenge

![](/assets/ctf/Web%20-%20Picnicnic.png)

## Solution

Upon visiting the given website we are greeted with four appetising pictures of some cookies. Yum! However, there is a fifth. If we inspect the page (F-12) and check the 'Storage' tab we see another cookie, named 'flag' with the value 'TkVUT057MHV'. This looks a lot like base64 encoding, and indeed we find
```
NETON{0u
```

However, this is only a part of the flag...
Deleting our cookie and refreshing the connection just gives us the same cookie.
What about visiting through curl and sending this cookie with us. (Or setting the cookie value in your browser through inspect.)

```sh
$ curl -v --cookie "flag=TkVUT057MHV" http://167.99.129.209:8001
```
*Remember to use the verbose option '-v' in order to see the cookie information.*

Suddenly, our cookie value has changed! In fact, we can do this process four times to find all four pieces of the flag.

In base64 encoding
```
TkVUT057MHV  
yX2MwMGtpZV
NfNHJlXzR3Z
XMwbWUhfQ==
```
which gives us the flag
```
NETON{0ur_c00kieS_4re_4wes0me!}
```