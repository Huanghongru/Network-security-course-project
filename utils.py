import os, math, time
from random import randrange, getrandbits

def is_prime(n, k=128):
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

def sample_prime(size: int) -> int:
    num = gen_prime_cand(size)

    sample_times = 0
    t1 = time.time()
    while not is_prime(num):
        num = gen_prime_cand(size)
        sample_times += 1
    t2 = time.time()
    print("total sample times: {}, average judge time: {:.3f}".format(
        sample_times, (t2 - t1) / sample_times
    ))
    return num
