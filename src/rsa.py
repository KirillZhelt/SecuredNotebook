import random
from math import gcd

def xgcd(a, b):
    x, old_x = 0, 1
    y, old_y = 1, 0
    while (b != 0):
        quotient = a // b
        a, b = b, a - quotient * b
        old_x, x = x, old_x - quotient * x
        old_y, y = y, old_y - quotient * y
    return a, old_x, old_y

def miller_rabin(num, k=200):
    if num < 2: 
        return False
    if num == 2 or num == 3:
        return True
    if not num&1: 
        return False
    d = num - 1
    s = 0
    while d % 2 == 0:
        d = d // 2
        s += 1

    for _ in range(k):
        a = random.randint(2, num - 2)
        v = pow(a, d, num)
        if v != 1: 
            i = 0
            while v != (num - 1):
                if i == s - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % num
    return True

def generate_prime(n_bits=256, n_tests=1000):
    while True:
        n = random.getrandbits(n_bits)
        n |= 1
        if miller_rabin(n, n_tests) and n.bit_length() == n_bits:
            return n

def generate_pq(n_bits=256):
    p, q = generate_prime(n_bits), generate_prime(n_bits)
    return (p,q)

def generate_keys(n_bits=256):
    (p,q) = generate_pq(n_bits)
    n = p*q
    phi = (p-1)*(q-1)
    while True:
        e = random.randint(2,phi)
        if gcd(e,phi) == 1: break
    _gcd, d, y = xgcd(e,phi)
    if d < 0: d+=phi
    return ((e,n),(d,n))

def encrypt(session_key, open_key):
    (e,n) = open_key
    return pow(session_key, e, n)


def decrypt(encrypted_session_key, closed_key):
    (d,n) = closed_key
    return pow(encrypted_session_key, d, n)
