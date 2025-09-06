# python gost2-128-gcm.py
# or
# python3 gost2-128-gcm.py

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ---------------------- No-echo password input ----------------------
# (Python note: use getpass for no-echo password input.)

import os
import sys
import struct
import time
import errno
import argparse
from getpass import getpass

# ---------------------- Portable secure random ----------------------
# (Python note: os.urandom is used; if it fails, we fall back to a weak RNG as LAST RESORT.)

def secure_random_bytes(length: int) -> bytes:
    try:
        return os.urandom(length)
    except Exception:
        return None  # handled by fallback

# Last-resort weak RNG (only if all above fail)
def fallback_weak_rng(length: int) -> bytes:
    # WARNING: This is NOT cryptographically secure.
    import random
    random.seed(int(time.time()))
    return bytes([random.getrandbits(8) & 0xFF for _ in range(length)])

def get_iv_16() -> bytes:
    b = secure_random_bytes(16)
    if b is not None:
        return b
    # fallback
    sys.stderr.write("WARNING: secure RNG unavailable; using weak srand(time(NULL)) fallback.\n")
    return fallback_weak_rng(16)

# ---------------------- GOST2-128 cipher ----------------------

# typedef uint64_t word64;  (Python note: int is unbounded; mask to 64-bit where needed.)
MASK64 = (1 << 64) - 1

n1 = 512  # /* 4096-bit GOST2-128 key for 64 * 64-bit subkeys */

# C globals: int x1,x2,i_; unsigned char h2[n1]; unsigned char h1[n1*3];
# (Python note: keep module-level state to match original behavior.)
x1 = 0
x2 = 0
h2 = bytearray(n1)
h1 = bytearray(n1 * 3)

def init_hashing():
    global x1, x2, h2, h1
    x1 = 0
    x2 = 0
    for i in range(n1):
        h2[i] = 0
    for i in range(n1 * 1):  # original loops fill only first n1 for h1 here; but code later touches up to n1*3
        h1[i] = 0
    # Python note: ensure whole h1 is zeroed to be safe.
    for i in range(n1, n1 * 3):
        h1[i] = 0

def hashing(t1: bytes, b6: int):
    """
    static void hashing(unsigned char t1[], size_t b6) { ... }
    """
    global x1, x2, h2, h1
    s4 = bytes([
        13,199,11,67,237,193,164,77,115,184,141,222,73,38,147,36,150,87,21,104,12,61,156,101,111,145,
        119,22,207,35,198,37,171,167,80,30,219,28,213,121,86,29,214,242,6,4,89,162,110,175,19,157,
        3,88,234,94,144,118,159,239,100,17,182,173,238,68,16,79,132,54,163,52,9,58,57,55,229,192,
        170,226,56,231,187,158,70,224,233,245,26,47,32,44,247,8,251,20,197,185,109,153,204,218,93,178,
        212,137,84,174,24,120,130,149,72,180,181,208,255,189,152,18,143,176,60,249,27,227,128,139,243,253,
        59,123,172,108,211,96,138,10,215,42,225,40,81,65,90,25,98,126,154,64,124,116,122,5,1,168,83,190,
        131,191,244,240,235,177,155,228,125,66,43,201,248,220,129,188,230,62,75,71,78,34,31,216,254,136,91,
        114,106,46,217,196,92,151,209,133,51,236,33,252,127,179,69,7,183,105,146,97,39,15,205,112,200,166,
        223,45,48,246,186,41,148,140,107,76,85,95,194,142,50,49,134,23,135,169,221,210,203,63,165,82,161,
        202,53,14,206,232,103,102,195,117,250,99,0,74,160,241,2,113
    ])
    b1 = b2 = b3 = b4 = b5 = 0
    b4 = 0
    # Python note: in Python, bytes indexing yields int; write back with & 0xFF for byte arrays.
    while b6:
        while b6 and x2 < n1:
            b6 -= 1
            b5 = t1[b4]
            b4 += 1
            h1[x2 + n1] = b5
            h1[x2 + (n1 * 2)] = b5 ^ h1[x2]
            x_val = b5 ^ x1
            x1 = h2[x2] = (h2[x2] ^ s4[x_val]) & 0xFF
            x2 += 1
        if x2 == n1:
            b2 = 0
            x2 = 0
            for b3 in range(n1 + 2):
                for b1 in range(n1 * 3):
                    b2 = h1[b1] = (h1[b1] ^ s4[b2]) & 0xFF
                b2 = (b2 + b3) % 256

def end_hash(h4: bytearray):
    """
    static void end_hash(unsigned char h4[n1]) { ... }
    """
    global x2, h2, h1
    h3 = bytearray(n1)
    n4 = n1 - x2
    for i in range(n4):
        h3[i] = n4 & 0xFF
    hashing(h3, n4)
    hashing(h2, len(h2))
    for i in range(n1):
        h4[i] = h1[i]

def create_keys(h4: bytes):
    """
    /* create 64 * 64-bit subkeys from h4 hash */
    static void create_keys(unsigned char h4[n1], word64 key[64]) { ... }
    """
    key = [0] * 64
    k = 0
    for i in range(64):
        v = 0
        for z in range(8):
            v = ((v << 8) + (h4[k] & 0xFF)) & MASK64
            k += 1
        key[i] = v
    return key

# S-boxes / tables
k1_  = [0x4,0xA,0x9,0x2,0xD,0x8,0x0,0xE,0x6,0xB,0x1,0xC,0x7,0xF,0x5,0x3]
k2_  = [0xE,0xB,0x4,0xC,0x6,0xD,0xF,0xA,0x2,0x3,0x8,0x1,0x0,0x7,0x5,0x9]
k3_  = [0x5,0x8,0x1,0xD,0xA,0x3,0x4,0x2,0xE,0xF,0xC,0x7,0x6,0x0,0x9,0xB]
k4_  = [0x7,0xD,0xA,0x1,0x0,0x8,0x9,0xF,0xE,0x4,0x6,0xC,0xB,0x2,0x5,0x3]
k5_  = [0x6,0xC,0x7,0x1,0x5,0xF,0xD,0x8,0x4,0xA,0x9,0xE,0x0,0x3,0xB,0x2]
k6_  = [0x4,0xB,0xA,0x0,0x7,0x2,0x1,0xD,0x3,0x6,0x8,0x5,0x9,0xC,0xF,0xE]
k7_  = [0xD,0xB,0x4,0x1,0x3,0xF,0x5,0x9,0x0,0xA,0xE,0x7,0x6,0x8,0x2,0xC]
k8_  = [0x1,0xF,0xD,0x0,0x5,0x7,0xA,0x4,0x9,0x2,0x3,0xE,0x6,0xB,0x8,0xC]
k9_  = [0xC,0x4,0x6,0x2,0xA,0x5,0xB,0x9,0xE,0x8,0xD,0x7,0x0,0x3,0xF,0x1]
k10_ = [0x6,0x8,0x2,0x3,0x9,0xA,0x5,0xC,0x1,0xE,0x4,0x7,0xB,0xD,0x0,0xF]
k11_ = [0xB,0x3,0x5,0x8,0x2,0xF,0xA,0xD,0xE,0x1,0x7,0x4,0xC,0x9,0x6,0x0]
k12_ = [0xC,0x8,0x2,0x1,0xD,0x4,0xF,0x6,0x7,0x0,0xA,0x5,0x3,0xE,0x9,0xB]
k13_ = [0x7,0xF,0x5,0xA,0x8,0x1,0x6,0xD,0x0,0x9,0x3,0xE,0xB,0x4,0x2,0xC]
k14_ = [0x5,0xD,0xF,0x6,0x9,0x2,0xC,0xA,0xB,0x7,0x8,0x1,0x4,0x3,0xE,0x0]
k15_ = [0x8,0xE,0x2,0x5,0x6,0x9,0x1,0xC,0xF,0x4,0xB,0x0,0xD,0xA,0x3,0x7]
k16_ = [0x1,0x7,0xE,0xD,0x0,0x5,0x8,0x3,0x4,0xF,0xA,0x6,0x9,0xC,0xB,0x2]

k175 = [0]*256
k153 = [0]*256
k131 = [0]*256
k109 = [0]*256
k87  = [0]*256
k65  = [0]*256
k43  = [0]*256
k21  = [0]*256

def kboxinit():
    for i in range(256):
        k175[i] = ((k16_[i >> 4] << 4) | k15_[i & 15]) & 0xFF
        k153[i] = ((k14_[i >> 4] << 4) | k13_[i & 15]) & 0xFF
        k131[i] = ((k12_[i >> 4] << 4) | k11_[i & 15]) & 0xFF
        k109[i] = ((k10_[i >> 4] << 4) | k9_[i & 15]) & 0xFF
        k87[i]  = ((k8_[i >> 4]  << 4) | k7_[i & 15]) & 0xFF
        k65[i]  = ((k6_[i >> 4]  << 4) | k5_[i & 15]) & 0xFF
        k43[i]  = ((k4_[i >> 4]  << 4) | k3_[i & 15]) & 0xFF
        k21[i]  = ((k2_[i >> 4]  << 4) | k1_[i & 15]) & 0xFF

def f_gost(x: int) -> int:
    y = (x >> 32) & 0xFFFFFFFF
    z = x & 0xFFFFFFFF
    y = ((k87[(y >> 24) & 255] << 24) |
         (k65[(y >> 16) & 255] << 16) |
         (k43[(y >> 8) & 255] << 8) |
         (k21[y & 255])) & 0xFFFFFFFF
    z = ((k175[(z >> 24) & 255] << 24) |
         (k153[(z >> 16) & 255] << 16) |
         (k131[(z >> 8) & 255] << 8) |
         (k109[z & 255])) & 0xFFFFFFFF
    x = ((y << 32) | z) & MASK64
    return ((x << 11) | (x >> (64 - 11))) & MASK64

def gostcrypt(in2, key):
    """
    static void gostcrypt(const word64 in[2], word64 out[2], word64 key[64]) { ... }
    """
    a = in2[0] & MASK64
    b = in2[1] & MASK64
    k = 0
    for _ in range(32):
        b ^= f_gost((a + key[k]) & MASK64)
        b &= MASK64
        k += 1
        a ^= f_gost((b + key[k]) & MASK64)
        a &= MASK64
        k += 1
    return (b & MASK64, a & MASK64)

def gostdecrypt(in2, key):
    """
    static void gostdecrypt(const word64 in[2], word64 out[2], word64 key[64]) { ... }
    """
    a = in2[0] & MASK64
    b = in2[1] & MASK64
    k = 63
    for _ in range(32):
        b ^= f_gost((a + key[k]) & MASK64)
        b &= MASK64
        k -= 1
        a ^= f_gost((b + key[k]) & MASK64)
        a &= MASK64
        k -= 1
    return (b & MASK64, a & MASK64)

# ---------------------- GCM helpers (128-bit ops) ----------------------

# typedef struct { uint64_t hi, lo; } be128; /* big-endian logical 128-bit */
# (Python note: represent as tuple (hi, lo), both 64-bit ints.)
def load_be128(b: bytes):
    """
    static be128 load_be128(const unsigned char b[16]) { ... }
    """
    hi = ((b[0] << 56) | (b[1] << 48) | (b[2] << 40) | (b[3] << 32) |
          (b[4] << 24) | (b[5] << 16) | (b[6] << 8) | b[7]) & MASK64
    lo = ((b[8] << 56) | (b[9] << 48) | (b[10] << 40) | (b[11] << 32) |
          (b[12] << 24) | (b[13] << 16) | (b[14] << 8) | b[15]) & MASK64
    return (hi, lo)

def store_be128(x, outb: bytearray):
    """
    static void store_be128(be128 x, unsigned char b[16]) { ... }
    """
    hi, lo = x
    outb[0]  = (hi >> 56) & 0xFF; outb[1]  = (hi >> 48) & 0xFF
    outb[2]  = (hi >> 40) & 0xFF; outb[3]  = (hi >> 32) & 0xFF
    outb[4]  = (hi >> 24) & 0xFF; outb[5]  = (hi >> 16) & 0xFF
    outb[6]  = (hi >> 8)  & 0xFF; outb[7]  = hi & 0xFF
    outb[8]  = (lo >> 56) & 0xFF; outb[9]  = (lo >> 48) & 0xFF
    outb[10] = (lo >> 40) & 0xFF; outb[11] = (lo >> 32) & 0xFF
    outb[12] = (lo >> 24) & 0xFF; outb[13] = (lo >> 16) & 0xFF
    outb[14] = (lo >> 8)  & 0xFF; outb[15] = lo & 0xFF

def be128_xor(a, b):
    return ((a[0] ^ b[0]) & MASK64, (a[1] ^ b[1]) & MASK64)

def be128_shr1(v):
    """
    /* right shift by 1 bit (big-endian logical value) */
    """
    hi, lo = v
    new_lo = ((lo >> 1) | ((hi & 1) << 63)) & MASK64
    new_hi = (hi >> 1) & MASK64
    return (new_hi, new_lo)

def be128_shl1(v):
    """
    /* left shift by 1 bit */
    """
    hi, lo = v
    new_hi = ((hi << 1) | (lo >> 63)) & MASK64
    new_lo = (lo << 1) & MASK64
    return (new_hi, new_lo)

def gf_mult(X, Y):
    """
    /* GF(2^128) multiplication per SP 800-38D, right-shift method */
    """
    Z = (0, 0)
    V = Y
    # R = 0xE1000000000000000000000000000000 (big-endian)
    R = (0xE100000000000000, 0x0000000000000000)
    for _ in range(128):
        msb = X[0] & 0x8000000000000000
        if msb:
            Z = be128_xor(Z, V)
        lsb = V[1] & 1
        V = be128_shr1(V)
        if lsb:
            V = be128_xor(V, R)
        X = be128_shl1(X)
    return Z

def ghash_update(Y_ref, H, block16: bytes):
    """
    /* GHASH update: Y <- (Y ^ X) * H */
    """
    X = load_be128(block16)
    Y = be128_xor(Y_ref[0], X)
    Y = gf_mult(Y, H)
    Y_ref[0] = Y  # use list for pass-by-reference semantics

def gost_encrypt_block(inp16: bytes, key):
    """
    /* Encrypt a single 16-byte block with GOST2-128 */
    """
    inw0 = ((inp16[0] << 56) | (inp16[1] << 48) | (inp16[2] << 40) | (inp16[3] << 32) |
            (inp16[4] << 24) | (inp16[5] << 16) | (inp16[6] << 8) | inp16[7]) & MASK64
    inw1 = ((inp16[8] << 56) | (inp16[9] << 48) | (inp16[10] << 40) | (inp16[11] << 32) |
            (inp16[12] << 24) | (inp16[13] << 16) | (inp16[14] << 8) | inp16[15]) & MASK64
    out0, out1 = gostcrypt((inw0, inw1), key)
    out = bytearray(16)
    out[0]  = (out0 >> 56) & 0xFF; out[1]  = (out0 >> 48) & 0xFF
    out[2]  = (out0 >> 40) & 0xFF; out[3]  = (out0 >> 32) & 0xFF
    out[4]  = (out0 >> 24) & 0xFF; out[5]  = (out0 >> 16) & 0xFF
    out[6]  = (out0 >> 8)  & 0xFF; out[7]  = out0 & 0xFF
    out[8]  = (out1 >> 56) & 0xFF; out[9]  = (out1 >> 48) & 0xFF
    out[10] = (out1 >> 40) & 0xFF; out[11] = (out1 >> 32) & 0xFF
    out[12] = (out1 >> 24) & 0xFF; out[13] = (out1 >> 16) & 0xFF
    out[14] = (out1 >> 8)  & 0xFF; out[15] = out1 & 0xFF
    return bytes(out)

def compute_H(key):
    """
    /* Compute H = E_K(0^128) */
    """
    zero = bytes(16)
    return gost_encrypt_block(zero, key)

def inc32(ctr: bytearray):
    """
    /* inc32 on the last 32 bits of a 128-bit counter (big-endian) */
    """
    c = ((ctr[12] << 24) | (ctr[13] << 16) | (ctr[14] << 8) | ctr[15]) & 0xFFFFFFFF
    c = (c + 1) & 0xFFFFFFFF
    ctr[12] = (c >> 24) & 0xFF
    ctr[13] = (c >> 16) & 0xFF
    ctr[14] = (c >> 8) & 0xFF
    ctr[15] = c & 0xFF

def derive_J0(iv: bytes, Hbe):
    """
    /* Derive J0 from IV (generic case when IV != 12 bytes) */
    """
    # Y = 0
    Y_ref = [(0, 0)]
    block = bytearray(16)
    off = 0
    ivlen = len(iv)
    while ivlen - off >= 16:
        ghash_update(Y_ref, Hbe, iv[off:off+16])
        off += 16
    if ivlen - off > 0:
        for i in range(16):
            block[i] = 0
        block[:ivlen - off] = iv[off:]
        ghash_update(Y_ref, Hbe, bytes(block))
    for i in range(16):
        block[i] = 0
    ivbits = (ivlen * 8) & ((1 << 64) - 1)
    block[8]  = (ivbits >> 56) & 0xFF
    block[9]  = (ivbits >> 48) & 0xFF
    block[10] = (ivbits >> 40) & 0xFF
    block[11] = (ivbits >> 32) & 0xFF
    block[12] = (ivbits >> 24) & 0xFF
    block[13] = (ivbits >> 16) & 0xFF
    block[14] = (ivbits >> 8) & 0xFF
    block[15] = ivbits & 0xFF
    ghash_update(Y_ref, Hbe, bytes(block))
    J0 = bytearray(16)
    store_be128(Y_ref[0], J0)
    return bytes(J0)

def ghash_lengths_update(Y_ref, Hbe, aad_bits: int, c_bits: int):
    """
    /* Prepares GHASH lengths block for AAD(empty) and C(lenC) */
    """
    lenblk = bytearray(16)
    # [len(AAD)]_64 || [len(C)]_64 in bits, both big-endian
    # aad is zero, bytes 0..7 already zero
    lenblk[8]  = (c_bits >> 56) & 0xFF
    lenblk[9]  = (c_bits >> 48) & 0xFF
    lenblk[10] = (c_bits >> 40) & 0xFF
    lenblk[11] = (c_bits >> 32) & 0xFF
    lenblk[12] = (c_bits >> 24) & 0xFF
    lenblk[13] = (c_bits >> 16) & 0xFF
    lenblk[14] = (c_bits >> 8) & 0xFF
    lenblk[15] = c_bits & 0xFF
    ghash_update(Y_ref, Hbe, bytes(lenblk))

def ct_memcmp(a: bytes, b: bytes) -> int:
    """
    /* Constant-time tag comparison */
    """
    r = 0
    for x, y in zip(a, b):
        r |= (x ^ y)
    return r  # 0 if equal

# ---------------------- File name helpers ----------------------
def add_suffix_gost2(inname: str) -> str:
    return f"{inname}.gost2"

def strip_suffix_gost2(inname: str) -> str:
    suf = ".gost2"
    if inname.endswith(suf):
        return inname[:-len(suf)]
    else:
        return f"{inname}.dec"

# ---------------------- High-level encrypt/decrypt ----------------------

BUF_CHUNK = 4096

def encrypt_file(infile: str, outfile: str, key):
    try:
        fi = open(infile, "rb")
    except OSError as e:
        print(f"open input: {e}", file=sys.stderr)
        return -1
    try:
        fo = open(outfile, "wb")
    except OSError as e:
        print(f"open output: {e}", file=sys.stderr)
        fi.close()
        return -1

    # Compute H and J0
    H = compute_H(key)
    Hbe = load_be128(H)

    iv = get_iv_16()

    # Write IV (16 bytes)
    try:
        fo.write(iv)
    except OSError as e:
        print(f"write IV: {e}", file=sys.stderr)
        fi.close(); fo.close()
        return -1

    J0 = derive_J0(iv, Hbe)

    # S = GHASH over ciphertext (starts at 0)
    S_ref = [(0, 0)]

    # Counter starts from inc32(J0)
    ctr = bytearray(J0)
    inc32(ctr)

    total_c_bytes = 0

    try:
        while True:
            inbuf = fi.read(BUF_CHUNK)
            if not inbuf:
                break
            off = 0
            r = len(inbuf)
            while off < r:
                ks = gost_encrypt_block(bytes(ctr), key)
                inc32(ctr)
                n = 16 if (r - off) >= 16 else (r - off)

                pblk = bytearray(16)  # pad with zeros for XOR
                pblk[:n] = inbuf[off:off+n]

                cblk = bytearray(16)
                for i in range(n):
                    cblk[i] = pblk[i] ^ ks[i]
                if n < 16:
                    for i in range(n, 16):
                        cblk[i] = 0  # pad for GHASH

                # Update GHASH with ciphertext block
                ghash_update(S_ref, Hbe, bytes(cblk))

                # Write ciphertext bytes (only n bytes)
                fo.write(cblk[:n])

                total_c_bytes += n
                off += n
    except OSError as e:
        print(f"I/O error: {e}", file=sys.stderr)
        fi.close(); fo.close()
        return -1

    # S <- S ⊗ H with lengths block (AAD=0, C=total_c_bytes)
    ghash_lengths_update(S_ref, Hbe, 0, total_c_bytes * 8)

    # Tag T = E_K(J0) XOR S
    EJ0 = gost_encrypt_block(J0, key)
    Sbytes = bytearray(16)
    store_be128(S_ref[0], Sbytes)
    Tag = bytes([(EJ0[i] ^ Sbytes[i]) & 0xFF for i in range(16)])

    # Write TAG
    try:
        fo.write(Tag)
    except OSError as e:
        print(f"write TAG: {e}", file=sys.stderr)
        fi.close(); fo.close()
        return -1

    fi.close()
    fo.close()
    print("Encryption completed. Wrote IV + ciphertext + tag.")
    return 0

def decrypt_file(infile: str, outfile: str, key):
    try:
        fi = open(infile, "rb")
    except OSError as e:
        print(f"open input: {e}", file=sys.stderr)
        return -1

    try:
        fi.seek(0, os.SEEK_END)
        fsz = fi.tell()
        fi.seek(0, os.SEEK_SET)
    except OSError as e:
        print(f"seek: {e}", file=sys.stderr)
        fi.close()
        return -1

    if fsz < 16 + 16:
        print("File too small (needs at least IV+TAG).", file=sys.stderr)
        fi.close()
        return -1
    remaining = fsz

    try:
        iv = fi.read(16)
        if len(iv) != 16:
            print("read IV: unexpected EOF", file=sys.stderr)
            fi.close()
            return -1
    except OSError as e:
        print(f"read IV: {e}", file=sys.stderr)
        fi.close()
        return -1
    remaining -= 16

    if remaining < 16:
        print("Missing tag.", file=sys.stderr)
        fi.close()
        return -1
    ciph_len = remaining - 16

    try:
        fo = open(outfile, "wb")
    except OSError as e:
        print(f"open output: {e}", file=sys.stderr)
        fi.close()
        return -1

    # Compute H and J0 as in encryption
    H = compute_H(key)
    Hbe = load_be128(H)
    J0 = derive_J0(iv, Hbe)

    # GHASH S over ciphertext
    S_ref = [(0, 0)]

    # CTR starts at inc32(J0)
    ctr = bytearray(J0)
    inc32(ctr)

    left = ciph_len

    try:
        while left > 0:
            to_read = BUF_CHUNK if left > BUF_CHUNK else int(left)
            buf = fi.read(to_read)
            if len(buf) != to_read:
                print("read C: unexpected EOF", file=sys.stderr)
                fi.close(); fo.close()
                return -1

            r = len(buf)
            off = 0
            while off < r:
                ks = gost_encrypt_block(bytes(ctr), key)
                inc32(ctr)
                n = 16 if (r - off) >= 16 else (r - off)

                cblk = bytearray(16)
                cblk[:n] = buf[off:off+n]

                # GHASH over ciphertext block (padded)
                ghash_update(S_ref, Hbe, bytes(cblk))

                pblk = bytearray(n)
                for i in range(n):
                    pblk[i] = cblk[i] ^ ks[i]

                fo.write(pblk)

                off += n
            left -= r
    except OSError as e:
        print(f"I/O error: {e}", file=sys.stderr)
        fi.close(); fo.close()
        return -1

    try:
        Tag = fi.read(16)
        if len(Tag) != 16:
            print("read TAG: unexpected EOF", file=sys.stderr)
            fi.close(); fo.close()
            return -1
    except OSError as e:
        print(f"read TAG: {e}", file=sys.stderr)
        fi.close(); fo.close()
        return -1

    fi.close()
    fo.close()

    # Finalize GHASH with lengths
    c_bits = ciph_len * 8
    ghash_lengths_update(S_ref, Hbe, 0, c_bits)

    # Compute expected tag: E_K(J0) XOR S
    EJ0 = gost_encrypt_block(J0, key)
    Stmp = bytearray(16)
    store_be128(S_ref[0], Stmp)
    Tcalc = bytes([(EJ0[i] ^ Stmp[i]) & 0xFF for i in range(16)])

    diff = ct_memcmp(Tag, Tcalc)
    if diff == 0:
        print("Authentication: OK")
        return 0
    else:
        print("Authentication: FAILED")
        return 1  # non-zero to indicate failure

# ---------------------- Derive GOST2-128 subkeys from password ----------------------
def derive_key_from_password(pwd: str):
    """
    /* Follow the original code's hashing pipeline to build h4 then subkeys */
    """
    h4 = bytearray(n1)
    init_hashing()
    hashing(pwd.encode('utf-8'), len(pwd.encode('utf-8')))
    end_hash(h4)
    return create_keys(h4)

# ---------------------- Main ----------------------
def usage(prog: str):
    """
    static void usage(const char *prog) {
        fprintf(stderr, "Usage: %s c|d <input_file>\n", prog);
    }
    """
    print(f"Usage: {prog} c|d <input_file>", file=sys.stderr)

def main(argv=None):
    if argv is None:
        argv = sys.argv
    if len(argv) != 3:
        usage(argv[0])
        return 2

    mode = argv[1]
    infile = argv[2]

    # Password input (no echo)
    pwd = getpass("Enter password: ")
    if pwd is None:
        print("Failed to read password.", file=sys.stderr)
        return 2

    # Init GOST2 tables and derive subkeys from password
    kboxinit()
    key = derive_key_from_password(pwd)

    # Zero password variable after use (best effort)
    # (Python note: strings are immutable; we just drop the reference.)
    del pwd

    # Build output file name
    if mode.lower().startswith('c'):
        outfile = add_suffix_gost2(infile)
        rc = encrypt_file(infile, outfile, key)
        return 0 if rc == 0 else 1
    elif mode.lower().startswith('d'):
        outfile = strip_suffix_gost2(infile)
        rc = decrypt_file(infile, outfile, key)
        return 0 if rc == 0 else 1
    else:
        usage(argv[0])
        return 2

if __name__ == "__main__":
    sys.exit(main())
