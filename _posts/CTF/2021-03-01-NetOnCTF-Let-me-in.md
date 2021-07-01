---
title: NetOn CTF 2021 - Let me in!
category: CTF
tags: Write-up Web
excerpt_separator: <!--more-->
---

Web -- 245 pts (9 solves) -- Chall author: X4v1l0k

Captchas connected to PHP session cookies are not a secure idea, so let's break in!

<!--more-->

## Challenge

![](/assets/ctf/Web%20-%20Let%20me%20in!.png)

## Solution

An empty page, with just a taunting 'Try to catch me!'... Pff, dare provoke me? Alright, alright. Let's see what you do _click_ nothing... Hah?
Upon inspection it sends us to flag.php, but visiting it immediately sends us back to index.php... Let's curl!

```sh
$ curl http://167.99.129.209:8002/flag.php
```
reveals the structure of flag.php
```html
<html>
        <head>
                <title>Try to catch the flag!</title>
        </head>
        <body>
                <form method="POST">
                        <p>
                                <label for="captcha">Please Enter the Captcha Text</label><br />
                                <img src="captcha.php" alt="CAPTCHA" class="captcha-image">
                        </p>
                        <p>
                                <input type="text" id="captcha" name="captcha_challenge">
                                <input type="submit" value="Send">
                        </p>
                </form>
        </body>
</html>
```
So it actually sends us to captcha.php instead of index.php. Okay, let's curl once more to find... gibberish... oh. Visiting the URL with a browser gives us a captcha image. Mmh, how do we feed this captcha code to the HTML form. Every time we request (refresh) the page, we get a new captcha... How about this: we empty out our cookie jar and visit captcha.php to get a captcha image and a PHP session cookie. Now let's curl both the captcha code and the session cookie to captcha.php

```sh
$ curl -d captcha_challenge=d1ctXg --cookie "PHPSESSID=eh9nn1eko8aj2oe88d9oj542ec" http://167.99.129.209:8002/flag.php
```

Succes! Within the returned HTML we find

```
Nice evade! Take the flag: <b>NETON{7c49af83a2a68304273a8d330cebd93c}</b>
```

_Other combinations of captcha codes and PHP session ID cookies also work!_