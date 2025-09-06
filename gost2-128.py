# python gost2-128.py
# or
# python3 gost2-128.py

import struct

# 64-bit unsigned mask
MASK64 = (1 << 64) - 1

# 4096-bit key for 64 * 64-bit subkeys
n1 = 512

# Global state for hashing
x1 = 0
x2 = 0
h2 = [0] * n1
h1 = [0] * (n1 * 3)


def init():
    """Initialize hashing state."""
    global x1, x2, h2, h1
    x1 = 0
    x2 = 0
    h2 = [0] * n1
    h1 = [0] * (n1 * 3)


def hashing(t1, b6):
    """MD2II hashing function to prepare 4096-bit key (faithful 8-bit behavior)."""
    global x1, x2, h1, h2
    s4 = [
        13,199,11,67,237,193,164,77,115,184,141,222,73,38,147,36,
        150,87,21,104,12,61,156,101,111,145,119,22,207,35,198,37,
        171,167,80,30,219,28,213,121,86,29,214,242,6,4,89,162,110,175,
        19,157,3,88,234,94,144,118,159,239,100,17,182,173,238,68,16,79,
        132,54,163,52,9,58,57,55,229,192,170,226,56,231,187,158,70,224,
        233,245,26,47,32,44,247,8,251,20,197,185,109,153,204,218,93,178,
        212,137,84,174,24,120,130,149,72,180,181,208,255,189,152,18,143,
        176,60,249,27,227,128,139,243,253,59,123,172,108,211,96,138,10,
        215,42,225,40,81,65,90,25,98,126,154,64,124,116,122,5,1,168,83,
        190,131,191,244,240,235,177,155,228,125,66,43,201,248,220,129,
        188,230,62,75,71,78,34,31,216,254,136,91,114,106,46,217,196,92,
        151,209,133,51,236,33,252,127,179,69,7,183,105,146,97,39,15,205,
        112,200,166,223,45,48,246,186,41,148,140,107,76,85,95,194,142,
        50,49,134,23,135,169,221,210,203,63,165,82,161,202,53,14,206,
        232,103,102,195,117,250,99,0,74,160,241,2,113
    ]
    b4 = 0
    while b6:
        while b6 and x2 < n1:
            b5 = t1[b4] & 0xFF
            b4 += 1
            h1[x2 + n1] = b5
            h1[x2 + (n1 * 2)] = (b5 ^ (h1[x2] & 0xFF)) & 0xFF
            # Keep 8-bit behavior for index and stored byte
            x1 = (h2[x2] ^ s4[(b5 ^ x1) & 0xFF]) & 0xFF
            h2[x2] = x1
            x2 += 1
            b6 -= 1

        if x2 == n1:
            b2 = 0
            x2 = 0
            for b3 in range(n1 + 2):
                for b1 in range(n1 * 3):
                    # b2 is used as an index: must stay 0..255
                    b2 = (h1[b1] ^ s4[b2 & 0xFF]) & 0xFF
                    h1[b1] = b2
                b2 = (b2 + b3) & 0xFF



def end(h4):
    """Finalize hashing and produce final 4096-bit key."""
    n4 = n1 - x2
    h3 = [n4] * n4
    hashing(h3, n4)
    hashing(h2, len(h2))
    for i in range(n1):
        h4[i] = h1[i]


def create_keys(h4):
    """Create 64 * 64-bit subkeys from 4096-bit hash."""
    key = [0] * 64
    k = 0
    for i in range(64):
        for _ in range(8):
            key[i] = ((key[i] << 8) + (h4[k] & 0xff)) & MASK64
            k += 1
    return key


# S-boxes k1..k16 (same as in C)
k1 = [0x4, 0xA, 0x9, 0x2, 0xD, 0x8, 0x0, 0xE, 0x6, 0xB, 0x1, 0xC, 0x7, 0xF, 0x5, 0x3]
k2 = [0xE, 0xB, 0x4, 0xC, 0x6, 0xD, 0xF, 0xA, 0x2, 0x3, 0x8, 0x1, 0x0, 0x7, 0x5, 0x9]
k3 = [0x5, 0x8, 0x1, 0xD, 0xA, 0x3, 0x4, 0x2, 0xE, 0xF, 0xC, 0x7, 0x6, 0x0, 0x9, 0xB]
k4 = [0x7, 0xD, 0xA, 0x1, 0x0, 0x8, 0x9, 0xF, 0xE, 0x4, 0x6, 0xC, 0xB, 0x2, 0x5, 0x3]
k5 = [0x6, 0xC, 0x7, 0x1, 0x5, 0xF, 0xD, 0x8, 0x4, 0xA, 0x9, 0xE, 0x0, 0x3, 0xB, 0x2]
k6 = [0x4, 0xB, 0xA, 0x0, 0x7, 0x2, 0x1, 0xD, 0x3, 0x6, 0x8, 0x5, 0x9, 0xC, 0xF, 0xE]
k7 = [0xD, 0xB, 0x4, 0x1, 0x3, 0xF, 0x5, 0x9, 0x0, 0xA, 0xE, 0x7, 0x6, 0x8, 0x2, 0xC]
k8 = [0x1, 0xF, 0xD, 0x0, 0x5, 0x7, 0xA, 0x4, 0x9, 0x2, 0x3, 0xE, 0x6, 0xB, 0x8, 0xC]
k9 = [0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1]
k10 = [0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF]
k11 = [0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0]
k12 = [0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB]
k13 = [0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC]
k14 = [0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0]
k15 = [0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7]
k16 = [0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2]

# Precomputed byte substitution tables
k175 = [0] * 256
k153 = [0] * 256
k131 = [0] * 256
k109 = [0] * 256
k87 = [0] * 256
k65 = [0] * 256
k43 = [0] * 256
k21 = [0] * 256


def kboxinit():
    """Build byte-at-a-time substitution tables."""
    for i in range(256):
        k175[i] = (k16[i >> 4] << 4) | k15[i & 15]
        k153[i] = (k14[i >> 4] << 4) | k13[i & 15]
        k131[i] = (k12[i >> 4] << 4) | k11[i & 15]
        k109[i] = (k10[i >> 4] << 4) | k9[i & 15]
        k87[i] = (k8[i >> 4] << 4) | k7[i & 15]
        k65[i] = (k6[i >> 4] << 4) | k5[i & 15]
        k43[i] = (k4[i >> 4] << 4) | k3[i & 15]
        k21[i] = (k2[i >> 4] << 4) | k1[i & 15]


def rol64(value, bits):
    """Rotate left a 64-bit integer."""
    return ((value << bits) & MASK64) | (value >> (64 - bits))


def f(x):
    """Non-linear function with S-box substitution and rotation."""
    y = (x >> 32) & 0xFFFFFFFF
    z = x & 0xFFFFFFFF
    y = ((k87[(y >> 24) & 0xFF] << 24) |
         (k65[(y >> 16) & 0xFF] << 16) |
         (k43[(y >> 8) & 0xFF] << 8) |
         (k21[y & 0xFF]))
    z = ((k175[(z >> 24) & 0xFF] << 24) |
         (k153[(z >> 16) & 0xFF] << 16) |
         (k131[(z >> 8) & 0xFF] << 8) |
         (k109[z & 0xFF]))
    x = ((y << 32) | (z & 0xFFFFFFFF)) & MASK64
    return rol64(x, 11)


def gostcrypt(inp, key):
    """Encrypt one 128-bit block (two 64-bit words)."""
    ngost1, ngost2 = inp
    k = 0
    for _ in range(32):
        ngost2 ^= f((ngost1 + key[k]) & MASK64)
        k += 1
        ngost1 ^= f((ngost2 + key[k]) & MASK64)
        k += 1
    return [ngost2 & MASK64, ngost1 & MASK64]


def gostdecrypt(inp, key):
    """Decrypt one 128-bit block (two 64-bit words)."""
    ngost1, ngost2 = inp
    k = 63
    for _ in range(32):
        ngost2 ^= f((ngost1 + key[k]) & MASK64)
        k -= 1
        ngost1 ^= f((ngost2 + key[k]) & MASK64)
        k -= 1
    return [ngost2 & MASK64, ngost1 & MASK64]


if __name__ == "__main__":
    kboxinit()
    print("GOST2-128 by Alexander PUKALL 2016")
    print("128-bit block, 4096-bit subkeys, 64 rounds\n")

    # Example 1
    init()
    text = b"My secret password!0123456789abc"
    hashing(list(text), 32)
    h4 = [0] * n1
    end(h4)
    key = create_keys(h4)
    plain = [0xFEFEFEFEFEFEFEFE, 0xFEFEFEFEFEFEFEFE]
    print(f"Key 1: {text.decode()}")
    print(f"Plaintext  1: {plain[0]:016X}{plain[1]:016X}")
    cipher = gostcrypt(plain, key)
    print(f"Encryption 1: {cipher[0]:016X}{cipher[1]:016X}")
    decrypted = gostdecrypt(cipher, key)
    print(f"Decryption 1: {decrypted[0]:016X}{decrypted[1]:016X}\n")

    # Example 2
    init()
    text = b"My secret password!0123456789ABC"
    hashing(list(text), 32)
    end(h4)
    key = create_keys(h4)
    plain = [0x0000000000000000, 0x0000000000000000]
    print(f"Key 2: {text.decode()}")
    print(f"Plaintext  2: {plain[0]:016X}{plain[1]:016X}")
    cipher = gostcrypt(plain, key)
    print(f"Encryption 2: {cipher[0]:016X}{cipher[1]:016X}")
    decrypted = gostdecrypt(cipher, key)
    print(f"Decryption 2: {decrypted[0]:016X}{decrypted[1]:016X}\n")

    # Example 3
    init()
    text = b"My secret password!0123456789abZ"
    hashing(list(text), 32)
    end(h4)
    key = create_keys(h4)
    plain = [0x0000000000000000, 0x0000000000000001]
    print(f"Key 3: {text.decode()}")
    print(f"Plaintext  3: {plain[0]:016X}{plain[1]:016X}")
    cipher = gostcrypt(plain, key)
    print(f"Encryption 3: {cipher[0]:016X}{cipher[1]:016X}")
    decrypted = gostdecrypt(cipher, key)
    print(f"Decryption 3: {decrypted[0]:016X}{decrypted[1]:016X}\n")
    
    
    # GOST2-128 by Alexander PUKALL 2016
    # 128-bit block, 4096-bit subkeys, 64 rounds

    # Key 1: My secret password!0123456789abc
    # Plaintext  1: FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE
    # Encryption 1: 8CA4C196B773D9C9A00AD3931F9B2B09
    # Decryption 1: FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE

    # Key 2: My secret password!0123456789ABC
    # Plaintext  2: 00000000000000000000000000000000
    # Encryption 2: 96AB544910861D5B22B04FC984D80098
    # Decryption 2: 00000000000000000000000000000000

    # Key 3: My secret password!0123456789abZ
    #Plaintext  3: 00000000000000000000000000000001
    # Encryption 3: ACF914AC22AE2079390BC240ED51916F
    # Decryption 3: 00000000000000000000000000000001
    #
