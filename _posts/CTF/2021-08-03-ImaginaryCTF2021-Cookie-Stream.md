---
title: ImaginaryCTF 2021 - Cookie Stream
category: CTF
tags: Write-up Web AES-CTR Bit-flip Cookies
excerpt_separator: <!--more-->
---

Web -- 150 pts (86 solves) -- Chall author: Eth007

A classic example of how not to use a cookie-based login system for your webpage, how not to hash stored passwords, and how not to create passwords to begin with... A singular un-salted hashed password is easy to recognise and reverse. Being able to login succesfully to a non-admin account we steal its cookie and bit-flip our way to the admin page!

<!--more-->

Check out write-ups by my teammates on [K3RN3L4RMY.com](http://k3rn3l4rmy.com/writeups)

## Exploration

![](/assets/ctf/CookieStream_chall.png)

On first glance the website shows nothing but a login page. But on second glance, it does too... So let's instead have a look at the provided back-end code.

Immediately we can see a small hard-coded 'user-database' with singular un-salted SHA512 hashed passwords.
```py
users = {
    'admin' : '240964a7a2f1b057b898ef33c187f2c2412aa4d849ac1a920774fd317000d33ebb8b0064834ed1f8a74763df4e95cd8c8be3a154b46929c3969ce323db69b81f',
    'ImaginaryCTFUser' : '87197acc4657e9adcc2e4e24c77268fa5b95dea2867eacd493a0478a0c493420bfb2280c7e4e579a604e0a243f74a36a8931edf71b088add09537e54b11ce326',
    'Eth007' : '444c67bb7d9d56580e0a2fd1ad00c535e465fc3ca9558e8333512fe65ff971a3dfb6b08f48ea4f91f8e8b55887ec3f0d7634a8df98e636a4134628c95a8f0ebf',
    'just_a_normal_user' : 'b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86',
    'firepwny' : '6adee5baa5ad468ac371d40771cf2e83e3033f91076f158d2c8d5d7be299adfce15247067740edd428ef596006d6eaa843b36cc109618e0a1cae843b6eed5c29',
    ':roocursion:' : '7f5310d2675c09c1b274f7642bf4979b2ce642515551a7617d155033e77ecfd53dede33ee541adde2f1072739696d0138d1b2f90c9ecc596095fa43b759e9baa',
}

def check(username, password):
    if username not in users.keys():
        return False
    if sha512(password.encode()).hexdigest() == users[username]:
        return True
```

Doing a quick reverse lookup of the hashes we find 4 out of the 6 passwords. _Please never, ever, ever, ever, store passwords this way. Pinky swear!_

```py
users = {
    'admin' : '',
    'ImaginaryCTFUser' : 'idk',
    'Eth007' : 'supersecure',
    'just_a_normal_user' : 'password',
    'firepwny' : 'pwned',
    ':roocursion:' : '',
}
```

Now that we can login, we can steal one of the user's cookies, which are created using a constant key and AES-CTR.

```py
@app.route('/backend', methods=['GET', 'POST'])
def backend():
    if request.method == 'POST':
        if not check(request.form['username'], request.form['password']):
            return 'Wrong username/password.'
        resp = make_response(redirect('/home'))
        nonce = urandom(8)
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce) # my friend told me that cbc had some weird bit flipping attack? ctr sounds way cooler anyways
        cookie = hexlify(nonce + cipher.encrypt(pad(request.form['username'].encode(), 16)))
        resp.set_cookie('auth', cookie)
        return resp
    else:
        return make_response(redirect('/home'))

@app.route('/home', methods=['GET'])
def home():
    nonce = unhexlify(request.cookies.get('auth')[:16])
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    username = unpad(cipher.decrypt(unhexlify(request.cookies.get('auth')[16:])), 16).decode()
    if username == 'admin':
        flag = open('flag.txt').read()
        return render_template('fun.html', username=username, message=f'Your flag: {flag}')
    else:
        return render_template('fun.html', username=username, message='Only the admin user can view the flag.')
```

AES-CTR is a stream cipher! All (unauthenticated) stream ciphers are malleable, i.e. susceptible to a bit-flipping attack. A stream cipher will produce the exact same keystream every time the same key and nonce are used. Therefore all we have to do is capture a valid cookie encrypted using the server's key, and XOR it such that the underlying plain text becomes whatever we need to get in. So let's get flipping!

## Exploitation

A user's cookie is structered (in hex) as follows.
```
nonce | AES_CTR( PAD( username ) )
```
For our guy 'just_a_normal_user', this would become
```
nonce | AES_CTR( b'just_a_normal_user\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e' )
```
Because a stream cipher simply XORs its key stream with the data it wants to encrypt, we can recover the keystream by XORing a stolen cookie with the known plain text. We logged into their account and stole their cookie. Nom nom!
```
6812284b5ba1dd61 | eed72265a689b7809673193143e3896fdc03610ce858a3b9941ae08bdfd8dca5
```

This means that for the nonce '6812284b5ba1dd61' we now know the keystream that will be generated using the server's key.
```
stolen_cookie ^ pad('just_a_normal_user') = 84a25111f9e8e8eef90174502fbcfc1cb9716f02e656adb79a14ee85d1d6d2ab
```

Finally, for our forged cookie (are those even edible? :S) we XOR the recovered keystream with our payload. _Note that we only need the first half of our recovered keystream as 'admin' is shorter than the AES block size of 16 bytes._

```
rec_keystream ^ pad('admin') = e5c63c7897e3e3e5f20a7f5b24b7f717
```
Combine it with the nonce and send it on its way to login as the admin!
```
6812284b5ba1dd61e5c63c7897e3e3e5f20a7f5b24b7f717
```

Ta-da!
```
ictf{d0nt_r3us3_k3ystr34ms_b72bfd21}
```
