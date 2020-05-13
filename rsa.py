import random, hashlib
import sys, time, utils

from typing import Tuple, List, Dict, Union

class RSA(object):
    def __init__(self, 
                 bit_size: int = 1024, 
                 verbose=False, 
                 encode_method: str = "oaep"
    ) -> None:
        self.size = int(bit_size)
        assert self.size >= 512, "key size bit too small, it should be at least 256 bit and must be 2^n bit"
        self.verbose = verbose

        self.public_key = None
        self.private_key = None

        self.encoder = utils.DataEncoder()
        assert encode_method in self.encoder.code_type, "invalid encode type"
        self.encode_method = encode_method

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

    def encrypt(self, plain_text: Union[str, int]) -> List[int]:
        """ 
        Encrypt a piece of plain text into cipher text.
        
        Firstly obtian the utf-8 value of each character in the str.
        We compute the cipher number of each utf-8 value. In this way,
        the chunk size can be regarded as 1 byte.

        Args:
        ----
            plain_text: the plain_text to be encrypted, can be str or int
        """
        n, e = self.public_key
        
        if self.encode_method == "naive":
            bs = self.encoder.naive_encode(plain_text)
        if self.encode_method == "oaep":
            bs = self.encoder.oaep_encode(plain_text)

        t1 = time.time()
        cipher_text = [pow(u, e, n) for u in bs]
        t2 = time.time()

        if self.verbose:
            print("| encrypt {}bytes plain text in {:.3f}s".format(
                sys.getsizeof(plain_text), t2-t1))
        return cipher_text

    def decrypt(self, cipher_text: List[int], decode_type: str) -> Union[str, int]:
        """
        Decrypt a piece of cipher text using the private key

        To deal with negative d in private key,
        Use pow() to quickly compute c ^ d % n.

        We are not sure the decoding way of the plain text
        so we just return bytes.
        """
        n, d = self.private_key
        
        t1 = time.time()
        plain_text = [pow(c, d, n) for c in cipher_text]
        t2 = time.time()
        
        if self.verbose:
            print("| decrypt {}bytes cipher text in {:.3f}s".format(
                sys.getsizeof(cipher_text), t2-t1))
        if self.encode_method == "naive":
            plain_text = self.encoder.naive_decode(decode_type, plain_text)
        if self.encode_method == "oaep":
            plain_text = self.encoder.oaep_decode(decode_type, plain_text)
        return plain_text
        

def test_rsa(rsa_encode_method):
    sizes = [512, 1024, 2048]
    for size in sizes:
        r = RSA(size, verbose=True, encode_method=rsa_encode_method)
        pk = r.generate_key_pairs()
        print("| Test RSA algorithm with key size {}bit".format(size))
        with open("test.txt", "r") as f:
            for text in f.readlines():
                text_type, text = text.strip().split('\t')
                if text_type != "str":
                    text = eval(text)
                ct = r.encrypt(text)
                pt = r.decrypt(ct, text_type)
                assert pt == text, "failed"
        print("| All test passed!")


def test_oaep_encode_and_decode():
    encoder = utils.DataEncoder()
    testsets = [
        ["str", "hello world hello world"],
        ["str", "wei cheng yong xiao is a good person."],
        ["int", 34253623],
        ["int", 2342345844594389],
    ]
    for test_type, test_case in testsets:
        l = encoder.oaep_encode(test_case)
        ll = encoder.oaep_decode(test_type, l)
        print(test_case)
        print(ll)
        assert ll == test_case, "failed"

