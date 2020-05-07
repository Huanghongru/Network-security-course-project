import utils
import random

from typing import Tuple, List, Dict, Union

class RSA(object):
    def __init__(self, bit_size: int = 1024) -> None:
        self.size = int(bit_size)

    def generate_key_pairs(self) -> List[Tuple[int, int]]:
        """
        generate public and private key pairs.
        """
        # randomly sample two large prime p and q
        p = utils.sample_prime_with_bit_size(self.size // 2)
        q = utils.sample_prime_with_bit_size(self.size - self.size // 2)
        n = p * q

        # compute the Euler function as m
        m = (p-1) * (q-1)

        # randomly pick an integer e that is relatively prime to m
        e = utils.sample_prime_with_upper_bound(m)

        # compute integer d s.t. ed - 1 = km
        d, _ = utils.ext_euclid(e, m)

        # public key: (n, e)
        # private key: (n, d)
        return [(n, e), (n, d)]

    def encrypt(self, plain_text: str) -> str:
        pass

    def decrypt(self, cipher_text: str) -> str:
        pass
