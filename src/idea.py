import random

BLOCK_LEN = 64

def get_8_keys(s, bit_len=128):
    return [int(s[i:i+8],2) for i in range(0, bit_len, 16)]

def get_all_keys(n):
    keys = []
    bin_n = format(n, 'b').zfill(128)
    keys.extend(get_8_keys(bin_n))
    for i in range(5):
        bin_n = "".join([bin_n[25:], bin_n[0:24]])
        keys.extend(get_8_keys(bin_n))
    bin_n = "".join([bin_n[25:], bin_n[0:24]])
    keys.extend(get_8_keys(bin_n, 64))
    return keys

def generate_key(n_bits=128):
    n = random.getrandbits(n_bits)
    n |= 1
    return n

def custom_mul(x, y, n):
    res = (x*y) % n
    return n-1 if res == 0 else res

def encrypt_block(keys, plain_text_block):
    d1, d2, d3, d4 = [int(plain_text_block[i:i+16],2) for i in range(0, len(plain_text_block), 16)]
    for i in range(8):
        a = custom_mul(d1, keys[i*6], 65537)
        b = (d2 + keys[i*6 + 1]) % 65536
        c = (d3 + keys[i*6 + 2]) % 65536
        d = custom_mul(d4, keys[i*6 + 3], 65537)
        e = a ^ c
        f = b ^ d

        d1 = a ^ custom_mul(custom_mul((f+e)%65536, keys[i*6 + 4], 65537), keys[i*6 + 5], 65537)
        d2 = c ^ custom_mul(custom_mul((f+e)%65536, keys[i*6 + 4], 65537), keys[i*6 + 5], 65537)
        d3 = b ^ ((custom_mul(e, keys[i*6 + 4], 65537) + custom_mul((f + custom_mul(e, keys[i*6+4], 65537)) % 65536, keys[i*6+5] ,65537)) % 65536)
        d4 = d ^ ((custom_mul(e, keys[i*6 + 4], 65537) + custom_mul((f + custom_mul(e, keys[i*6+4], 65537)) % 65536, keys[i*6+5] ,65537)) % 65536)
    
    d1_res = custom_mul(d1, keys[-4], 65537)
    d2_res = (d3 + keys[-3]) % 65536
    d3_res = (d2 + keys[-2]) % 65536
    d4_res = custom_mul(d4, keys[-1], 65537)
    return "".join([format(d, 'b').zfill(16) for d in [d1_res, d2_res, d3_res, d4_res ]])

def string_from_bits(bin_str):
    return "".join(chr(int(bin_str[i:i+8],2)) for i in range(0, len(bin_str)-7, 8))

def string_to_bits(_str):
    return "".join((bin(ord(c))[2:]).zfill(8) for c in _str)
	

def encrypt(text, key):
    bin_str = string_to_bits(text)
    bin_str += "0"
    while len(bin_str) % BLOCK_LEN != 0:
        bin_str += "1"
    keys = get_all_keys(key)
    encrypt_text = ""
    k0 = format(generate_key(BLOCK_LEN), 'b').zfill(BLOCK_LEN)
    init_v = k0
    for i in range(0, len(bin_str), BLOCK_LEN):
        k0 = encrypt_block(keys, k0)
        encrypt_text += format(int(k0,2) ^ int(bin_str[i:i+BLOCK_LEN],2), 'b').zfill(BLOCK_LEN)
    return encrypt_text, init_v


def decrypt(text, key, initialization_vector):
    keys = get_all_keys(key)
    decrypt_text = ""
    for i in range(0, len(text), BLOCK_LEN):
        initialization_vector = encrypt_block(keys, initialization_vector)
        decrypt_text += format(int(initialization_vector,2) ^ int(text[i:i+64],2), 'b').zfill(64)
    return string_from_bits(decrypt_text[:decrypt_text.rfind("0")])

