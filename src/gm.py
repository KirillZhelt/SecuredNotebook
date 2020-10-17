import random
from math import gcd
from functools import reduce

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
    while p == q:
        p  = generate_prime(n_bits)
    return (p,q)

def generate_keys(n_bits=256):
    (p,q) = generate_pq(n_bits)
    n = p*q
    y = pseudosquare(p, q)
    return ((n, y),(p, q))

def jacobi(a, n):
    if a == 0:
        return 0
    if a == 1:
        return 1
    e = 0
    a1 = a
    while a1 % 2 == 0:
        e += 1
        a1 =a1// 2
    assert 2**e * a1 == a
    s = 0
    if e % 2 == 0:
        s = 1
    elif n % 8 in {1, 7}:
        s = 1
    elif n % 8 in {3, 5}:
        s = -1
    if n % 4 == 3 and a1 % 4 == 3:
        s *= -1
    n1 = n % a1
    if a1 == 1:
        return s
    else:
        return s * jacobi(n1, a1)

def quadratic_non_residue(p):
    a = 0
    while jacobi(a, p) != -1:
        a = random.randint(1, p)
    return a

def gauss_crt(a, m):
    modulus = reduce(lambda a,b: a*b, m)
    multipliers = []
    for m_i in m:
        M = modulus // m_i
        gcd, inverse, y = xgcd(M, m_i)
        multipliers.append(inverse * M % modulus)
 
    result = 0
    for multi, a_i in zip(multipliers, a):
        result = (result + multi * a_i) % modulus
    return result

def pseudosquare(p, q):
    a = quadratic_non_residue(p)
    b = quadratic_non_residue(q)
    return gauss_crt([a, b], [p, q])

def encrypt(session_key, open_key):
    bin_session_key = format(session_key, 'b').zfill(128)
    encrypted_bits = []
    n, y = open_key
    for bit in bin_session_key:
        x = random.randint(0, n)
        if bit == "0":
            encrypted_bits.append(pow(x,2,n))
        else:
            encrypted_bits.append((y*x**2)%n)
    return encrypted_bits

def decrypt(encrypted_session_key_list, closed_key):
    p, q = closed_key
    session_key_bin_str = ""
    for i in encrypted_session_key_list:
        if jacobi(i, p) == 1:
            session_key_bin_str += "0"
        else:
            session_key_bin_str += "1"
    return int(session_key_bin_str, 2)
