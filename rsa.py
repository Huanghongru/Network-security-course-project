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

        self.public_key = (n, e)
        self.private_key = (n, d)
        return (n, e)

    def oaep_encode(self, plain_text: Union[str, int]) -> Union[str, int]:
        if type(plain_text) is int:
            m = plain_text << self.oaep_k1
            r = utils.randint_with_bit_size(self.oaep_k0)
            
            X = m ^ self.oaep_G(r)
            Y = r ^ self.oaep_H(X)
            plain_text = (X << self.oaep_k0) | Y
        else:
            m = plain_text + "0" * (self.oaep_k1 // 8)
        return plain_text

    def oaep_decode(self, decode_type: str) -> Union[str, int]:
        pass

    def chunk_encode(self, plain_text: Union[str, int]) -> List[int]:
        """
        encode the plain text into chunks of data.
        these data are represented as integers.
        """
        encoded_plain_text = []
        if type(plain_text) is str:
            for i in range(0, len(plain_text), self.chunk_size // 8):
                chunk = plain_text[i: min(len(plain_text), i + self.chunk_size // 8)]#.encode()
                print(chunk)
                encoded_plain_text.append(int.from_bytes(chunk, 'big'))
        else:
            while plain_text:
                encoded_plain_text.append(plain_text & utils.bit_mask(self.chunk_size))
                plain_text >>= self.chunk_size
        return encoded_plain_text

    def chunk_decode(self, decode_type: str, decrypted_text: List[int]) -> Union[str, int]:
        """
        decode the decrypted text to its corresponding type
        """
        if decode_type == "str":
            plain_text = bytearray(decrypted_text).decode()
        else:
            plain_text = 0
            print(len(decrypted_text))
            for num in decrypted_text[::-1]:
                plain_text = (plain_text << self.chunk_size) | num
        return plain_text

    def naive_encode(self, plain_text: Union[str, int]) -> List[int]:
        if type(plain_text) is str:
            res = [b for b in str.encode(plain_text)]
        else:
            res = []
            mask = utils.bit_mask(self.size)
            while plain_text:
                res.append(plain_text & mask)
                plain_text >>= self.size
        return res

    def naive_decode(self, decode_type: str, plain_text: List[int]) -> Union[str, int]:
        if decode_type == "str":
            return bytearray(plain_text).decode()
        else:
            pt_ = 0
            for num in plain_text[::-1]:
                pt_ = (pt_ << self.size) | num
            return pt_

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
        

<<<<<<< HEAD
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

# test_rsa()

# test_oaep_encode_and_decode()
