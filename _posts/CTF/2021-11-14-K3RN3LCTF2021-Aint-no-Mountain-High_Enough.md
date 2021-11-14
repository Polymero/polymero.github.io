---
title: K3RN3LCTF 2021 - Ain't no Mountain High Enough
category: CTF
tags: crypto linear-algebra
hidden_tags: my-challenge
excerpt_separator: <!--more-->
---

Cryptography -- 500 pts (1 solve) -- Chall author: Polymero (me)

_"Hills are easy to climb, but mountains? Hoho, they sure are something else!"_

<!--more-->

nc ctf.k3rn3l4rmy.com 2238

**Note:** Wrap the flag with flag format (`flag{}`)

Files: [mountaincipher.py](https://github.com/Kasimir123/K3RN3LCTF-2021/blob/main/server-files/aint-no-mountain/mountaincipher.py), [server.py](https://github.com/Kasimir123/K3RN3LCTF-2021/blob/main/server-files/aint-no-mountain/server.py)

This challenge was part of our very first CTF, [K3RN3LCTF 2021](https://ctftime.org/event/1438).

## Exploration

On the surface players are presented with an encryption and decryption service running Mountain Cipher. Used parameters and the current state of the key cube can also be inspected.

```
|
|
|         ___ ___ ___        _________                                          _
|       /   /   /   /\      (_________)                           _            (_)
|      /___/___/___/  \      _   _   _    ___    _   _   ____   _| |_   _____   _   ____
|     /   /   /   /\  /\    | | |_| | |  / _ \  | | | | |  _ \ (_   _) (____ | | | |  _ \
|    /___/___/___/  \/  \   | |     | | | |_| | | |_| | | | | |  | |_  / ___ | | | | | | |
|   /   /   /   /\  /\  /\  |_|     |_|  \___/  |____/  |_| |_|   \__) \_____| |_| |_| |_|
|  /___/___/___/  \/  \/  \
|  \   \   \   \  /\  /\  /  _______   _           _
|   \___\___\___\/  \/  \/  (_______) (_)         | |
|    \   \   \   \  /\  /    _         _   ____   | |__    _____    ____
|     \___\___\___\/  \/    | |       | | |  _ \  |  _ \  | ___ |  / ___)
|      \   \   \   \  /     | |_____  | | | |_| | | | | | | ____| | |
|       \___\___\___\/       \______) |_| |  __/  |_| |_| |_____) |_|
|                                         |_|
|
|
|  Welcome to the Mountain Cipher Encryption Service!
|
|    Current version: 1.0 (Insert Challenge)
|
|
|  MENU:
|   [0] Show info
|   [1] Inspect key cube
|   [2] Insert FLAG slice
|
|   [3] Encrypt
|   [4] Decrypt
|
|   [5] Exit
|
|  >> 0
|
|
|  Mountain Cipher Encryption Service (MCES) v1.0
|
|    "Hills are easy to climb, but mountains? Hoho, they sure are something else!"
|
|  KEY CUBE
|   Dimensions (n): 5x5x5
|   Prime Modulus (p): 251
|
|  CIPHER TEXT
|   Matrix Output: True
|   Hex Output: True
|
|  Challenge: recover the FLAG by inserting it into the KEY CUBE.
|
|
|  MENU:
|   [0] Show info
|   [1] Inspect key cube
|   [2] Insert FLAG slice
|
|   [3] Encrypt
|   [4] Decrypt
|
|   [5] Exit
|
|  >> 1
|
|
|                                     Key Cube (5x5x5)
|                                    ___ ___ ___ ___ ___
|                                  /   /   /   /   /   /\
|                                 /___/___/___/___/___/  \
|                                /   /   /   /   /   /\  /\
|                               /___/___/___/___/___/  \/  \
|                              /   /   /   /   /   /\  /\  /\
|                             /___/___/___/___/___/  \/  \/  \
|                            /   /   /   /   /   /\  /\  /\  /\
|                           /___/___/___/___/___/  \/  \/  \/  \
|                          /   /   /   /   /   /\  /\  /\  /\  /\
|   Message Cuboid --->   /___/___/___/___/___/  \/  \/  \/  \/  \   ---> Cipher Cuboid
|                         \   \   \   \   \   \  /\  /\  /\  /\  /
|                          \___\___\___\___\___\/  \/  \/  \/  \/
|                           \   \   \   \   \   \  /\  /\  /\  /
|                            \___\___\___\___\___\/  \/  \/  \/
|                             \   \   \   \   \   \  /\  /\  /
|                              \___\___\___\___\___\/  \/  \/
|                               \   \   \   \   \   \  /\  /
|                                \___\___\___\___\___\/  \/
|                                 \   \   \   \   \   \  /
|                                  \___\___\___\___\___\/
|                                    |   |   |   |   |
|                                    |   |   |   |   |
|                                    |   |   |   |   |
|                  Current slices:   K1  K2  K3  K4  K5
|
|
|  MENU:
|   [0] Show info
|   [1] Inspect key cube
|   [2] Insert FLAG slice
|
|   [3] Encrypt
|   [4] Decrypt
|
|   [5] Exit
|
|  >>
```

Especially interesting is the possibility of injecting a 5x5 matrix into the cube containing the FLAG characters! But what is this 5x5x5 cube even used for? Let's take a look at the Mountain Cipher source code. In MC_Cipher.py we find some standard matrix operations, involving matrix multiplication, determinant, adjoint, and the transpose.

```py
#-------------------------------------------------------------------------------
# LINEAR ALGEBRA HELPER FUNCTIONS (no numpy.linalg, no sage)
#-------------------------------------------------------------------------------
# Matrix determinant
def det(m):
    if len(m) == 2:
        return m[0][0]*m[1][1] - m[0][1]*m[1][0]
    else:
        return sum( (-1)**(i) * m[0][i] * det( [list(mi[:i]) + list(mi[i+1:]) for mi in m[1:]] ) for i in range(len(m)) )

# Matrix transpose
def trans(m):
    return [[m[j][i] for j in range(len(m))] for i in range(len(m))]

# Matrix adjoint (to calculate the inverse)
def adjoint(m):
    adj = [[0 for _ in range(len(m))] for _ in range(len(m))]
    for i in range(len(m)):
        for j in range(len(m)): 
            adj[i][j] = (-1)**(i+j) * det( [ list(mi[:j])+list(mi[j+1:]) for mi in list(m[:i])+list(m[i+1:]) ] )
    return trans(adj)

# Simple matrix multiplication (mod p)
def matmult(A, B, p):
    assert len(A) == len(B)
    n = len(A)
    C = [[0 for _ in range(n)] for _ in range(n)]
    for ri in range(n):
        for ci in range(n):
            C[ri][ci] = sum( [A[ri][i]*B[i][ci] for i in range(n)] ) % p
    # Return
    return C
```

There are a couple of 'helper' functions used to generate appropriate keys, and to pad and shape any input message into (a list of) 5x5 matrices.

```py
#-------------------------------------------------------------------------------
# CIPHER HELPER FUNCTIONS
#-------------------------------------------------------------------------------
# (u)Random key gen for both public and private keys
def keygen(n, p):
    i = 0
    while i < 100:
        try:
            keycube = [[[int(bytes_to_long(os.urandom(p//256 + 1))/256*p) % p for _ in range(n)] for _ in range(n)] for _ in range(n)]
            keyDINV = [int(inverse(det(k),p)) for k in keycube]
            keyCINV = [[[c*keyDINV[i] % p for c in r] for r in adjoint(k)] for i,k in enumerate(keycube)]
            return keycube, keyCINV[::-1]
        except:
            i += 1
            continue    
    raise ValueError('Key generation failed, try again or try with a different p...')

# Padding and msg matrixfier
def pad(msg, n):
    # Bytestrings only pls
    if type(msg) == str:
        msg = msg.encode()
    # Apply padding
    while (len(msg) % (n*n) != 0):
        msg += os.urandom(1)
    # Matrixfy and return
    return [[list(i[j:j+n]) for j in range(0,n*n,n)] for i in [msg[k:k+n*n] for k in range(0,len(msg),n*n)]]
```

Finally, we encounter the encryption and decryption functions. The used methods are very similar to the classic Hill cipher, yet we have a key 'cube' consisting of 5 key matrices all used sequentially on each 5x5 input matrix. Note that using 5 key matrices does not improve the security of the cipher at all as they can just be collapsed into a single key matrix, bringing the Mountain Cipher back to the classic Hill cipher.

```py
#-------------------------------------------------------------------------------
# MOUNTAIN CIPHER
#-------------------------------------------------------------------------------
# Mountain Cipher Encryption Function
def encMC(msg, n, p, key=None, verbose=False):
    # Create key if none given
    if key is None:
        key, _ = keygen(n, p)   
    # Convert msg to matrix
    if type(msg) != list:
        msg = pad(msg, n)
    # For all nxn msg matrices
    ct = []
    for mi in msg:
        # Hill-cipher encrypt with every key matrix
        for i in range(n):
            mi = matmult(key[i], mi, p)
        # Add result to ciphertext
        ct += [mi]
    # Debug
    if verbose:
        print('Key Cube\n',key, '\n')
        print('Message Cube\n',msg, '\n')
        print('Cipher Cube\n',ct, '\n')
        if p < 256:
            print('Msg\n',bytes([i for j in [i for j in msg for i in j] for i in j]), '\n')
            print('Cip\n',bytes([i for j in [i for j in ct for i in j] for i in j]), '\n')
    # Return ciphertext in hex
    if False and all(i < 256 for i in [i for j in [i for j in ct for i in j] for i in j]):
        return bytes([i for j in [i for j in ct for i in j] for i in j]).hex()
    else:
        return ct

# Mountain Cipher Decryption Function
def decMC(cip, n, p, key):
    # Transform cipher text
    if type(cip) == str:
        cip = bytes.fromhex(cip)
    if type(cip) != list:
        cip = pad(cip, n)
    # Decryption key from key
    detinvs = [int(inverse(det(k),p)) for k in key[::-1]]
    deckey = [[[c*detinvs[i] % p for c in r] for r in adjoint(k)] for i,k in enumerate(key[::-1])]
    # Get decryption through encryption with decryption key
    return encMC(cip, n, p, key=deckey, verbose=False)
```

All in all, we have found the following **key observations**.

- We are dealing with a '3D' variant of the classic Hill cipher, with 5 key matrices instead of just 1.
- We can replace one of the key matrices with the flag matrix at will.
- The server will let us encrypt and decrypt any data we want.


## Exploitation

Our approach will consist of the following steps.

1. Call a single encryption of a 5x5 input matrix for every possible key cube configuration.
2. Set up a system of linear matrix equations.
3. Solve the above system for the FLAG matrix.

By calling the server to encrypt a single input matrix for every key cube configuration we receive the following system of matrix equations.

$$ C_0 = K_5 K_4 K_3 K_2 K_1 M_0 $$

$$ C_1 = K_5 K_4 K_3 K_2  F  M_1 $$

$$ C_2 = K_5 K_4 K_3  F  K_1 M_2 $$

$$ C_3 = K_5 K_4  F  K_2 K_1 M_3 $$

$$ C_4 = K_5  F  K_3 K_2 K_1 M_4 $$

$$ C_5 =  F  K_4 K_3 K_2 K_1 M_5 $$

Right, so let's start solving! We start with rewriting $C_3$ to

$$ K_5 K_4 F K_2 K_1 = C_3 M_3^{-1}. $$

Then we can rewrite $C_0$ twice to

$$ K_5 K_4 = C_0 M_0^{-1} K_1^{-1} K_2^{-1} K_3^{-1} $$

$$ K_2 K_1 = K_3^{-1} K_4^{-1} K_5^{-1} C_0 M_0^{-1} $$

and substitute it in our previous results to find

$$ K_1^{-1} K_2^{-1} K_3^{-1} F K_3^{-1} K_4^{-1} K_5^{-1} = M_0 C_0^{-1} C_3 M_3^{-1} M_0 C_0^{-1}. $$

Next we can use $C_4$ and $C_2$ as

$$ K_1^{-1} K_2^{-1} K_3^{-1} = M_4 C_4^{-1} K_5 F $$

$$ K_3^{-1} K_4^{-1} K_5^{-1} = F K_1 M_2 C_2^{-1} $$

to further develop our previous result to get

$$ K_5 F^3 K_1 = C_4 M_4^{-1} M_0 C_0^{-1} C_3 M_3^{-1} M_0 C_0^{-1} C_2 M_2^{-1}. $$

Getting closer! Now we will use $C_0$ twice again as

$$ K_5 = C_0 M_0^{-1} K_1^{-1} K_2^{-1} K_3^{-1} K_4^{-1} $$

$$ K_1 = K_2^{-1} K_3^{-1} K_4^{-1} K_5^{-1} C_0 M_0^{-1} $$

to derive

$$ K_1^{-1} K_2^{-1} K_3^{-1} K_4^{-1} F^3 K_2^{-1} K_3^{-1} K_4^{-1} K_5^{-1} = M_0 C_0^{-1} C_4 M_4^{-1} M_0 C_0^{-1} C_3 M_3^{-1} M_0 C_0^{-1} C_2 M_2^{-1} M_0 C_0^{-1}. $$

Alright, final step! Now let's use $C_1$ and $C_5$ rewritten as

$$ K_1^{-1} K_2^{-1} K_3^{-1} K_4^{-1} = M_5 C_5^{-1} F $$

$$ K_2^{-1} K_3^{-1} K_4^{-1} K_5^{-1} = F M_1 C_1^{-1} $$

to arrive at a function for F independent of any key matrices

$$ F^5 = C_5 M_5^{-1} M_0 C_0^{-1} C_4 M_4^{-1} M_0 C_0^{-1} C_3 M_3^{-1} M_0 C_0^{-1} C_2 M_2^{-1} M_0 C_0^{-1} C_1 M_1^{-1}. $$

_Note that we can simplify this quite a bit by just setting all input matrices to the identity matrix._

Yay! Ah, wait... It's a power of the FLAG matrix, what do we do now? Well, through the power of linear algebra we can diagonalise $F^5$ as

$$ F^5 = X D X^{-1}, $$

where $X$ contains the eigenvectors of $F^5$ as columns, and $D$ the eigenvalues on its diagonal. Taking modular square roots of a general matrix is not a trivial thing, yet for a diagonal matrix this turns out to be quite simple. So we can finally recover the flag by solving

$$ F = X D^{1/5} X^{-1}. $$

Here is some example sage script for the final part.

```py
# Get eigenvectors to form columns of the X matrix
X = Matrix(GF(263),[flag5.eigenvectors_right()[i][1][0] for i in range(5)]).T
Xinv = X.inverse()

# Get eigenvalues to form the diagonal D5 matrix
D5 = Matrix(GF(263),[[0]*i + [flag5.eigenvalues()[i]] + [0]*(4-i) for i in range(5)])

# Assert found decomposition is correct
assert flag5 == X*D5*Xinv

# Take 5th rooth of diagonal matrix (trivial) to recover the flag eigenvalues
flag_eigval = [GF(263)(i).nth_root(5) for i in flag5.eigenvalues()]

# Build new diagonal matrix
D = Matrix(GF(263),[[0]*i + [flag_eigval[i]] + [0]*(4-i) for i in range(5)])

# Assert found eigenvalues create the flag matrix
flag_rec = X*D*Xinv
assert flag == flag_rec

# Print flag
print(bytes([i for j in flag_rec for i in j]))
```

Ta-da!
```
flag{n0_m0uNtAin_2_hIGh_F0R_u!}
```

-----
Thanks for reading! <3

~ Polymero