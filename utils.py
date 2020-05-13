import os, math, time, hashlib
from random import randrange, getrandbits, randint
from typing import Tuple, Union, List

def is_prime(n: int, k: int=128):
    """
    Miller-Rabin algorithm

    see here: https://medium.com/@prudywsh/how-to-generate-big-prime-numbers-miller-rabin-49e6e6af32fb

    It is a random algorithm to check whether a large (e.g. 1024bit) number 
    is prime. The running time is O(klog^3 n)
    """
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False

    s = 0
    r = n-1
    while r & 1 == 0:
        s += 1
        r //= 2

    # perform k rounds
    for _ in range(k):
        a = randrange(2, n-1)
        x = pow(a, r, n)
        if x != 1 and x != n-1:
            j = 1
            while j < s and x != n-1:
                x = pow(x, 2, n)
                if x == 1:
                    return False
                j += 1
            if x != n-1:
                return False
    return True

def randint_with_bit_size(size: int) -> int:
    """sample a random int with given bit size.
    the significant bit is guaranteed to be one
    """
    p = getrandbits(size)
    p |= (1 << size-1)
    return p

def get_prime_candidate(size: int) -> int:
    """sample a prime candidate, which must be odd
    """
    return randint_with_bit_size(size) | 1

def byte_size(num: int) -> int:
    return num.bit_length() // 8 + 1

def bit_mask(size: int) -> int:
    mask = 0
    for _ in range(size):
        mask = (mask << 1) + 1
    return mask

def sample_prime_with_bit_size(size: int, silence=True) -> int:
    num = get_prime_candidate(size)

    sample_times = 0
    t1 = time.time()
    while not is_prime(num):
        num = get_prime_candidate(size)
        sample_times += 1
    t2 = time.time()
    if not silence:
        print("total sample times: {}, average judge time: {:.3f}".format(
            sample_times, (t2 - t1) / sample_times
        ))
    return num

def sample_prime_with_upper_bound(upper_bound: int, silence=True) -> int:
    num = randint(2, upper_bound)

    sample_times = 0
    t1 = time.time()
    while not is_prime(num):
        num = randint(2, upper_bound)
        sample_times += 1
    t2 = time.time()
    if not silence:
        print("total sample times: {}, average judge time: {:.3f}s".format(
            sample_times, (t2 - t1) / sample_times
        ))
    return num

def ext_euclid(a: int, b: int) -> Tuple[int, int]:
    """ Extented Euclidian Algorithm
    details see here: https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm

    usually we want x > 0, we can convert it to equivalent integer like this:
    https://crypto.stackexchange.com/questions/10805/how-does-one-deal-with-a-negative-d-in-rsa
    """
    s_old, s = 1, 0
    t_old, t = 0, 1
    r_old, r = a, b
    if b == 0:
        return (1, 0)
    else:
        while r != 0:
            q = r_old // r
            r_old, r = r, r_old - q * r
            s_old, s = s, s_old - q * s
            t_old, t = t, t_old - q * t

    x, y = s_old, t_old

    # obtian a positive x
    x %= b
    while x < 0:
        x += b
    return (x, y)

def exp_by_square(x: int, n: int) -> int:
    """
    compute x ^ n in O(logn).

    Not used. python built-in function pow() is enough and more effective.
    """
    if n == 1:
        return x
    if n % 2:
        return x * exp_by_square(x ** 2, (n-1) // 2)
    else:
        return exp_by_square(x ** 2, n // 2)

class DataEncoder(object):
    """
    This class handle the format of the input and output of
    the cryptography functions.
    """
    def __init__(self):
        # OAEP setting
        self.oaep_k0 = 128 # bit
        self.oaep_k1 = 120 # bit

        self.code_type = ["naive", "oaep"]

    def cryptographic_hash_function(self, x: int) -> int:
        """
        the input and output of hashlib are both `bytes`.
        it is hard to deal with it so i convert it to int
        """
        h = hashlib.md5()

        x = x.to_bytes(128, 'big')
        h.update(x)
        return int.from_bytes(h.digest(), 'big')

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
