# Network Security Project - Attack textbook RSA

## Part 1

**Goal**: Implement the textbook RSA algorithm (without any padding)

The code for this part is mainly in [rsa.py](https://github.com/Huanghongru/Network-security-course-project/blob/master/rsa.py) and it is able to:

* **Generate** a random RSA key pair with a given key size (e.g., 1024bit)
* **Encrypt** a plaintext with the public key
* **Decrypt** a ciphertext with the private key

## Part 2

**Goal**: Perform a CCA2 attack on textbook RSA. The attak is **to gradually reveal** information about an encrypted message, or about the decryption key iteself.

In this attack, the server knows **RSA key pair** and **AES key**. The adversary knows **RSA public key**, **RSA-encrypted AES key** and **an AES-encrypted WUP request**. More detail can be found on this [paper](https://arxiv.org/pdf/1802.03367.pdf).

The code for this part is mainly in [client\_server.py](https://github.com/Huanghongru/Network-security-course-project/blob/master/client_server.py) and [attacker.py](https://github.com/Huanghongru/Network-security-course-project/blob/master/attacker.py). They are able to:

* Simulate the server-client communication.
* Generate history message and they are guaranteed to include RSA-encrypted AES key and an AES-encrypted request.
* Present the attack process to obtain the AES key and further decrypt the encrypted request.

## Part 3

**Goal**: defend the attack by implementing a RSA-OAEP algorithm. 

The code for this part is mainly in [utils.py](https://github.com/Huanghongru/Network-security-course-project/blob/master/utils.py#L119). It is able to add the OAEP padding module to the textbook RSA implementation.

Feel free to run:

```Bash
python main.py
```

to see all of the required results.
