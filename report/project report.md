# Network Security Project - Attack textbook RSA

119033910103 黄竑儒

## Introduction

In the project, we attempt to implement textbook RSA algorithm by ourselves. Based on the textbook RSA algorithm we implemented, we try to perform CCA2 attack according to [[1] Jefferey et.al,2018](#reference). Finally we will try to defend the CCA2 attack by using OAEP key padding algorithm.

## Part 1 - Textbook RSA Algorithm

In this part, we will implement textbook RSA algorithm (without any padding). RSA is one of the first public-key cryptosystems and is widely used for secure data transimission. To apply textbook RSA algorithm, we first need to generate RSA key pairs. The **key generation algorithm** is as follows:

1. randomly select two large prime (with specific bit size) $p$ and $q$, compute $n = p \times q$. 
2. compute the Carmichael's totient function $m = \lambda(n) = (p-1) \times (q-1)$. 
3. choose an integer $e$ such that $e \in (1, m)$ and $gcd(e,  m) = 1$. Usually $e = 65537$ is a common choice.
4. determine $d$ add $d \equiv e ^{-1}$ (mod $m$), that is $d$ is the modular multiplicative inverse of $e$ modulo $m$.
5. release $(n, e)$ as public key and keep secrect $(n, d)$ as the private key.

There are some worth-mentioning implementation details. 

### Primality Check for Large Integers

The first step of key generation algorithm is to select two large prime $p$ and $q$. The *prime number theorem* states that $\frac{n}{\ln n}$ is a good approximation of the number of prime numbers that is less than or equal to $n$. Therefore, the probability that a randomly chosen number is prime is $\frac{1}{\ln n}$. This theorem gives us a hint that to select two large prime $p$ and $q$, the most effective way is **firstly sample a large number and check whether it is prime**. 

To check whether a randomly sampled integer is prime, one might use the following code:

```python
def is_prime(num: int) -> bool:
    for i in range(2, int(math.sqrt(num))):
        if num % i == 0:
            return False
    return True
```

This is the trivial solution to check prime and its time complexity is O($\sqrt  n$), which is unacceptable when $n$ is hundreds of bit long. The common key size for RSA is $1024$ bit so that both of $p$ and $q$ should be at least $512$ bit. Instead, we will use [[2] Miller-Rabin algorithm](#reference) to check whether the chosen number is prime. The running time of this algorithm is O($k\log^3 n$), where $n$ is the number tested for primality and $k$ is the number of rounds performed. We set $k = 128$ in the code.

### Extended Eculidean Algorithm

In the 4th step, the modular multiplicative inverse $d$ can be determined using [[3] Extended Euclidean Algorithm](#refenrence). 

> It follows that both extended Euclidean algorithms are widely used in [cryptography](https://en.wikipedia.org/wiki/Cryptography). In particular, the computation of the [modular multiplicative inverse](https://en.wikipedia.org/wiki/Modular_multiplicative_inverse) is an essential step in the derivation of key-pairs in the [RSA](https://en.wikipedia.org/wiki/RSA_(algorithm)) public-key encryption method.

In short, we can find the solution pair $(x, y)$ of equation $ax + by = gcd(a, b)$ using this algorithm. In the RSA setting, $(a, b) = (e, m)$. Since $e$ and $m$ are coprime, $gcd(e, m) = 1$. We only need $d = x$ so we can discard $y$. However, usually we will obtain a negative $x$, that is $x < 0$. But for computation convenience, we want $x$ be positive. Fortunately, $x \equiv x + k\times m$ in modulo and therefore we can obtain a positive $x = d$. 

The key generation code is as follows:

```python
def generate_key_pairs(self) -> Tuple[int, int]:
    """
    generate public and private key pairs.

    store the private key and public key.
    only return the public key
    """
    # randomly sample two large prime p and q
    p = utils.sample_prime_with_bit_size(self.size // 2)
    q = utils.sample_prime_with_bit_size(self.size - self.size // 2)
    n = p * q

    # compute the Euler function as m
    m = (p-1) * (q-1)

    # randomly pick an integer e that is relatively prime to m
    e = 65537 if 65537 < m else 11

    # compute integer d s.t. ed - 1 = km
    d, _ = utils.ext_euclid(e, m)

    # keep secret the private key and release the public key
    self.public_key = (n, e)
    self.private_key = (n, d)
    return (n, e)
```

### Encryption and Decryption

Now that we have generate the key pair, we can apply RSA algorithm to sensitive data. Without loss of generality, we just consider ``str`` and ``int`` data. For any given data, we firstly break it into blocks of data with fixed size 8bit (1 byte). This block data can be guaranteed to be less than $n$ and grant us the ability of dealing with arbitrary large data. The test data we used is stored in *test.txt*. 

The result of encryption and decryption of different key size is listed as follows:

![naive_rsa](imgs\naive_rsa.png)

We can see that our self-implemented RSA algorithm work as we expected. One interestng obseveration is that as the key size increases, the time for encryption and decryption also increase. The increment for decryption time is much more significant than the encryption. Because after integer obtained by moduling $n$ is very large and we need to do large power operation when decrypting it. The observation also tells us why we only use RSA to encrypt small size of data, like AES key discussed in the next section, in practice due to its significant time load. 

## Part 2 - CCA2 attack

In this part we will perform a CCA2 attack on textbook RSA. Textbook RSA is elegant but lack semantic security. An adaptive chosen-ciphertext attack (CCA2) is an interactive form of chosen-ciphertext attack in which an attacker sends a number of ciphertexts to be decrypted, then uses the results of these decryptions to select subsequent ciphertexts. 

### Client-server Communication Model

Before implementing the CCA2 attack, we firstly build up a client-server communication model. In this communication, the client will

1.  generate a $128$-bit AES session key for the session
2. encrypt this session key using a $1024$-bit RSA public key
3. use the AES session key to encrypt the WUP requset
4. send RSA-encrypted AES session key and the encrypted WUP request to the server

The server will

1. decrypt the RSA-encrypted AES key it received from the client
2. choose the least significant 128 bits of the plaintext to be the AES session key
3. decrypt the WUP request using the AES session key
4. send an AES-encrypted response if the WUP request is valid

In our implementation, each client has its own RSA object that maintain the RSA key pairs. The server will register a client and store the client's RSA key pairs before communication. 

The original WUP request is somewaht complicated and tedious. We simplify it as the follow formats:

``| content - 1024 bytes | mac - 7 bytes | imei - 7 bytes | SHA - 64 bytes | ``

We add $64$ bytes SHA at the end of the request. If the check sum is valid, we regard the WUP request as valid. The client-server model test result is as follows:

![client-server](imgs\client-server.png)

If the server think the WUP request is valid, it will return true and print out the content of that WUP. 

### CCA2 attack

The assumption of this attack is that no key padding such as OAEP is used when encrypting the AES key with RSA. Because of this, we are able to leverage the malleability of RSA to perform a chosen ciphertext attack to guess the AES key one bit at a time. Another assumption is that the server will only use the least 128 bit of the encrypted AES key plaintext as the key to decrpyt the message. This is a little bit weird because usually the AES key is 128bit. After it is decrypted correctly, it should be also 128bit. I can't think of any situations that the correctly decrypted AES key is longer than 128 bit except that the situation where we are hacking the key.

The adversary knows RSA public key, a RSA-encrypted AES key and an AES-encrypted WUP request. The adversary guess one bit of the AES key at a time. This part of code is as follows and we give detail comments on the code.

```python
        for b in range(127, -1, -1):
            # assume that the encode way is naive encoding
            # according to the fundamental property of multiplication
            # in modular arithmetic, we should compute C_b for each
            # block of this data.
            C_b = [c * ((1 << b*e) % n) % n for c in C]

            # after leftshift, the aes key will be longer than 128 bit.
            # recall that the server only use the least 128bit as the AES key.
            # we mask the least 128bit here.
            aes_key = utils.bit_mask(128) & (k_b << b)
            aes = AES.new(aes_key.to_bytes(16, 'big'))

            # send a dummy WUP request to obtain the server's attitude
            # towards the current hacked aes key.
            wups = WUP("I want to hack your aes key", self.mac, self.imei)
            encrypted_wups = [aes.encrypt(wup) for wup in wups]

            req = [(victim_id, C_b, wup) for wup in encrypted_wups]

            # update the hacked aes key according to server's respondence.
            k_b = (1-server.process_request(req)) << (127-b) | k_b
```

The hacking result is shown as follows:

![cca2](imgs\cca2.png)

The lines on the top are respondence from the server. We can see that somtimes the dummy WUP request is valid while sometimes it is not. Combine it all we can hack the victim AES key at the bottom line and the further reveal the victim plain text.

## Part 3 - OAEP-RSA Algorithm

As we mentioned before, textbook RSA is vulnerable to attacks. One feasible way to defend CCA2 attack in section 2 is to using OAEP key padding algorithm. In cryptography, [[4] Optimal Asymmetric Encryption Padding (OAEP)](#reference) is a padding scheme often used together with RSA encryption.

Recall that in section 1, we cut off the plaintext into blocks with fixed size 8bit. Specifically, for an integer, we cut off the least 8bit of this integer and rightshift 8bit until the integer become $0$. For a string, we just cut off it into characters since in python each chracter is 8bit(1 byte) long. We can recover the plaintext by just reversing all of the mention steps.

```python
    def naive_encode(self, plain_text: Union[str, int]) -> List[int]:
        if type(plain_text) is str:
            res = [b for b in str.encode(plain_text)]
        else:
            res = []
            mask = bit_mask(8)
            while plain_text:
                res.append(plain_text & mask)
                plain_text >>= 8
        return res
    
    def naive_decode(self, decode_type: str, plain_text: List[int]) -> Union[str, int]:
        if decode_type == "str":
            return bytearray(plain_text).decode()
        else:
            pt_ = 0
            for num in plain_text[::-1]:
                pt_ = (pt_ << 8) | num
            return pt_
```

The merit of this preprocessing is in two folds:

* we can handle arbitrary large data theoretically without worrying about the contraint that $m < n$.
* unify different type of plaintext as an integer with fix size, which give convenience for other advanced preprocessing methods, like OAEP.

 Now we can implement OAEP following the algorithm described in the reference. The code is as follows:

```python
    def oaep_encode(self, plain_text: Union[str, int]) -> List[int]:
        """Do OAEP encoding on the basic of naive encoding
        """
        plain_text = self.naive_encode(plain_text)
        oaep_plain_text = []
        for chunk in plain_text:
            m = chunk << self.oaep_k1
            r = randint_with_bit_size(self.oaep_k0)

            X = m ^ self.cryptographic_hash_function(r)
            Y = r ^ self.cryptographic_hash_function(X)

            oaep_plain_text.append((X << self.oaep_k0) | Y)

        return oaep_plain_text

    def oaep_decode(self, decode_type: str, plain_text: List[int]) -> List[int]:
        """OAEP decoding
        """
        oaep_decoded_plain_text = []
        for chunk in plain_text:
            Y = chunk & bit_mask(self.oaep_k0)
            X = chunk >> self.oaep_k0

            r = Y ^ self.cryptographic_hash_function(X)
            m = (X ^ self.cryptographic_hash_function(r)) >> self.oaep_k1

            oaep_decoded_plain_text.append(m)

        return self.naive_decode(decode_type, oaep_decoded_plain_text)
```

We can confirm that the OAEP encoding work along with the RSA algorithm. OAEP can guarantee two goals:

* add an element of randomness (the random sample integer $r$ in the above code) which can be used to convert a deterministic encryption scheme into a probabilistic scheme.
* prevent partial decryption of ciphertexts by ensuring that an adversary cannot recover any portion of the plaintext without being able to invert the trapdoor one-way permutation.

In the CCA2 attack, the adversary only knows the RSA public key, an RSA-encrypted AES key and an AES-encrypted WUP request. However, to fully recover the OAEP-RSA encrypted AES key, it need to know $k_0$ and $k_1$ so that it can recover $X$ and $Y$. The adversary also need to know the hash function used in OAEP setting to further recover $m$ and $r$. In my opinion, the OAEP can be regarded as another encryption layer before RSA encryption. The CCA2 attack we discussed above only attacks the RSA layer so it can do nothing to the OAEP part, which in turn guarantee the AES key is safe.

We can see that all of the attempted dummy WUP request to hack a OAEP-RSA encrypted AES key is invalid and the final hacking result is failure.

![oaep_hack](imgs\oaep_hack.png)

## Conclusion

In this project, we implemented textbook RSA algorithm by ourselves. We perform a CCA2 attack on the implemented textbook RSA algorithm to recognize the semantic vulnerability . At the last part we implement OAEP-RSA algorithm to defend the mentioned CCA2 attack. 

## Reference

[1]	[Jeffery Knockel, Thomas Ristenpart, Jedidiah Crandall. 2018. *When Textbook RSA is Used to Protect the Privacy of Hundreds of Millions of Users*](https://arxiv.org/abs/1802.03367)

[2]	[Miller-Rabin algorithm]([https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Complexity](https://en.wikipedia.org/wiki/Miller–Rabin_primality_test#Complexity))

[3]	[Extended Euclidean Algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm)

[4]	[Optimal Asymmetric Encryption Padding](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding)







