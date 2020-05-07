import os, math, time
from random import randrange, getrandbits, randint
from typing import Tuple

def is_prime(n: int, k: int=128):
    """
    Miller-Rabin algorithm

    see here: https://medium.com/@prudywsh/how-to-generate-big-prime-numbers-miller-rabin-49e6e6af32fb

    It is a random algorithm to check whether a large (e.g. 1024bit) number 
    is prime. The running time is about O(1)
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

def gen_prime_cand(size):
    p = getrandbits(size)
    p |= (1 << size-1) | 1
    return p

def sample_prime_with_bit_size(size: int, silence=True) -> int:
    num = gen_prime_cand(size)

    sample_times = 0
    t1 = time.time()
    while not is_prime(num):
        num = gen_prime_cand(size)
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
    return (s_old, t_old)
