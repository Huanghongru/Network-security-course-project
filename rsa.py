import sys
import time
import utils
import random

from typing import Tuple, List, Dict, Union

class RSA(object):
    def __init__(self, bit_size: int = 1024, verbose=False) -> None:
        self.size = int(bit_size)
        self.verbose = verbose

        assert self.size > 4, "key size bit too small, it should be at least 4"

        self.public_key = None
        self.private_key = None

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

        self.public_key = (n, e)
        self.private_key = (n, d)
        return (n, e)

    def encrypt(self, plain_text: str) -> List[int]:
        """ 
        Encrypt a piece of plain text into cipher text.
        Firstly obtian the utf-8 value of each character in the str.
        We compute the cipher number of each utf-8 value.
        """
        n, e = self.public_key
        bs = [b for b in str.encode(plain_text)]

        t1 = time.time()
        cipher_text = [pow(u, e, n) for u in bs]
        t2 = time.time()

        if self.verbose:
            print("| encrypt {}bytes plain text in {:.3f}s".format(
                sys.getsizeof(plain_text), t2-t1))
        return cipher_text

    def decrypt(self, cipher_text: List[int]) -> str:
        """
        Decrypt a piece of cipher text using the private key

        To deal with negative d in private key,
        Use pow() to quickly compute c ^ d % n.
        """
        n, d = self.private_key
        
        t1 = time.time()
        plain_text = [pow(c, d, n) for c in cipher_text]
        t2 = time.time()
        
        if self.verbose:
            print("| decrypt {}bytes cipher text in {:.3f}s".format(
                sys.getsizeof(cipher_text), t2-t1))
        return bytearray(plain_text).decode()
        

def test_rsa():
    sizes = [32, 252, 512, 1024, 2048]
    for size in sizes:
        r = RSA(size, verbose=True)
        pk = r.generate_key_pairs()
        print("| Test RSA algorithm with key size {}bit".format(size))
        with open("test.txt", "r") as f:
            for text in f.readlines():
                text = text.strip()
                ct = r.encrypt(text)
                pt = r.decrypt(ct)
                assert pt == text, "failed"
        print("| All test passed!")

