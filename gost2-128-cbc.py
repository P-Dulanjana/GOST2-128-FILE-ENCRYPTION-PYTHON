# File encryption with GOST2-128 in CBC mode.
# python gost2-128-cbc.py
# or
# python3 gost2-128-cbc.py

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This is a faithful Python port of gost2-128-cbc.c

import os
import sys
import errno
import time
import struct
from getpass import getpass
from typing import Tuple

# =========================
#      GOST2-128 CORE
# =========================

# typedef uint64_t word64;
# In Python, integers are arbitrary precision; we mask to 64-bit where needed.
MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF

n1 = 512  # 4096-bit GOST2-128 key for 64 * 64-bit subkeys

x1 = 0
x2 = 0
i_g = 0
h2 = bytearray(n1)
h1 = bytearray(n1 * 3)

def init_gost_keyhash():
    global x1, x2, h2, h1
    x1 = 0
    x2 = 0
    for i in range(n1):
        h2[i] = 0
    for i in range(n1):
        h1[i] = 0

def hashing(t1: bytes, b6: int):
    """
    Port of the MD2II hashing routine used to derive 4096-bit material.
    """
    global x1, x2, h2, h1
    s4 = bytes([
        13,199,11,67,237,193,164,77,115,184,141,222,73,38,147,36,150,87,21,104,12,61,156,101,111,145,
        119,22,207,35,198,37,171,167,80,30,219,28,213,121,86,29,214,242,6,4,89,162,110,175,19,157,3,88,234,94,144,118,159,239,100,17,182,173,238,
        68,16,79,132,54,163,52,9,58,57,55,229,192,170,226,56,231,187,158,70,224,233,245,26,47,32,44,247,8,251,20,197,185,109,153,204,218,93,178,
        212,137,84,174,24,120,130,149,72,180,181,208,255,189,152,18,143,176,60,249,27,227,128,139,243,253,59,123,172,108,211,96,138,10,215,42,225,40,81,
        65,90,25,98,126,154,64,124,116,122,5,1,168,83,190,131,191,244,240,235,177,155,228,125,66,43,201,248,220,129,188,230,62,75,71,78,34,31,216,
        254,136,91,114,106,46,217,196,92,151,209,133,51,236,33,252,127,179,69,7,183,105,146,97,39,15,205,112,200,166,223,45,48,246,186,41,148,140,107,
        76,85,95,194,142,50,49,134,23,135,169,221,210,203,63,165,82,161,202,53,14,206,232,103,102,195,117,250,99,0,74,160,241,2,113
    ])
    b4 = 0
    while b6:
        while b6 and x2 < n1:
            b5 = t1[b4]
            b4 += 1
            b6 -= 1
            h1[x2 + n1] = b5
            h1[x2 + (n1*2)] = b5 ^ h1[x2]
            x1 = h2[x2] ^ s4[(b5 ^ x1) & 0xFF]
            h2[x2] = x1
            x2 += 1
        if x2 == n1:
            b2 = 0
            x2 = 0
            for b3 in range(n1 + 2):
                for b1 in range(n1 * 3):
                    b2 = h1[b1] ^ s4[b2]
                    h1[b1] = b2
                b2 = (b2 + b3) % 256

def end_gost_keyhash(h4: bytearray):
    """
    Finalize the hash and write n1 bytes into h4.
    """
    global x2, h2, h1
    h3 = bytearray(n1)
    n4 = n1 - x2
    for j in range(n4):
        h3[j] = n4 & 0xFF
    hashing(h3, n4)
    hashing(h2, len(h2))
    for j in range(n1):
        h4[j] = h1[j]

def create_keys(h4: bytes):
    """
    create 64 * 64-bit subkeys from h4 hash
    """
    key = [0]*64
    k = 0
    for i in range(64):
        v = 0
        for z in range(8):
            v = ((v << 8) | (h4[k] & 0xFF)) & MASK64
            k += 1
        key[i] = v
    return key

k1  = bytes([0x4,0xA,0x9,0x2,0xD,0x8,0x0,0xE,0x6,0xB,0x1,0xC,0x7,0xF,0x5,0x3])
k2  = bytes([0xE,0xB,0x4,0xC,0x6,0xD,0xF,0xA,0x2,0x3,0x8,0x1,0x0,0x7,0x5,0x9])
k3  = bytes([0x5,0x8,0x1,0xD,0xA,0x3,0x4,0x2,0xE,0xF,0xC,0x7,0x6,0x0,0x9,0xB])
k4  = bytes([0x7,0xD,0xA,0x1,0x0,0x8,0x9,0xF,0xE,0x4,0x6,0xC,0xB,0x2,0x5,0x3])
k5  = bytes([0x6,0xC,0x7,0x1,0x5,0xF,0xD,0x8,0x4,0xA,0x9,0xE,0x0,0x3,0xB,0x2])
k6  = bytes([0x4,0xB,0xA,0x0,0x7,0x2,0x1,0xD,0x3,0x6,0x8,0x5,0x9,0xC,0xF,0xE])
k7  = bytes([0xD,0xB,0x4,0x1,0x3,0xF,0x5,0x9,0x0,0xA,0xE,0x7,0x6,0x8,0x2,0xC])
k8  = bytes([0x1,0xF,0xD,0x0,0x5,0x7,0xA,0x4,0x9,0x2,0x3,0xE,0x6,0xB,0x8,0xC])

k9  = bytes([0xC,0x4,0x6,0x2,0xA,0x5,0xB,0x9,0xE,0x8,0xD,0x7,0x0,0x3,0xF,0x1])
k10 = bytes([0x6,0x8,0x2,0x3,0x9,0xA,0x5,0xC,0x1,0xE,0x4,0x7,0xB,0xD,0x0,0xF])
k11 = bytes([0xB,0x3,0x5,0x8,0x2,0xF,0xA,0xD,0xE,0x1,0x7,0x4,0xC,0x9,0x6,0x0])
k12 = bytes([0xC,0x8,0x2,0x1,0xD,0x4,0xF,0x6,0x7,0x0,0xA,0x5,0x3,0xE,0x9,0xB])
k13 = bytes([0x7,0xF,0x5,0xA,0x8,0x1,0x6,0xD,0x0,0x9,0x3,0xE,0xB,0x4,0x2,0xC])
k14 = bytes([0x5,0xD,0xF,0x6,0x9,0x2,0xC,0xA,0xB,0x7,0x8,0x1,0x4,0x3,0xE,0x0])
k15 = bytes([0x8,0xE,0x2,0x5,0x6,0x9,0x1,0xC,0xF,0x4,0xB,0x0,0xD,0xA,0x3,0x7])
k16 = bytes([0x1,0x7,0xE,0xD,0x0,0x5,0x8,0x3,0x4,0xF,0xA,0x6,0x9,0xC,0xB,0x2])

k175 = bytearray(256)
k153 = bytearray(256)
k131 = bytearray(256)
k109 = bytearray(256)
k87  = bytearray(256)
k65  = bytearray(256)
k43  = bytearray(256)
k21  = bytearray(256)

def kboxinit():
    for i in range(256):
        k175[i] = (k16[i >> 4] << 4) | k15[i & 15]
        k153[i] = (k14[i >> 4] << 4) | k13[i & 15]
        k131[i] = (k12[i >> 4] << 4) | k11[i & 15]
        k109[i] = (k10[i >> 4] << 4) | k9[i & 15]
        k87[i]  = (k8[i >> 4]  << 4) | k7[i & 15]
        k65[i]  = (k6[i >> 4]  << 4) | k5[i & 15]
        k43[i]  = (k4[i >> 4]  << 4) | k3[i & 15]
        k21[i]  = (k2[i >> 4]  << 4) | k1[i & 15]

def rol64(x: int, n: int) -> int:
    x &= MASK64
    return ((x << n) & MASK64) | (x >> (64 - n))

def f_func(x: int) -> int:
    y = (x >> 32) & MASK32
    z = x & MASK32

    y = ((k87[(y >> 24) & 255]  << 24) |
         (k65[(y >> 16) & 255] << 16) |
         (k43[(y >> 8)  & 255] << 8)  |
         (k21[y & 255])) & MASK32

    z = ((k175[(z >> 24) & 255] << 24) |
         (k153[(z >> 16) & 255] << 16) |
         (k131[(z >> 8)  & 255] << 8)  |
         (k109[z & 255])) & MASK32

    x2_ = ((y & MASK32) << 32) | (z & MASK32)
    return rol64(x2_, 11)

def gostcrypt(block_in: Tuple[int, int], key):
    a, b = block_in
    a &= MASK64; b &= MASK64
    k = 0
    for _ in range(32):
        b ^= f_func((a + key[k]) & MASK64)
        b &= MASK64
        k += 1
        a ^= f_func((b + key[k]) & MASK64)
        a &= MASK64
        k += 1
    return (b & MASK64, a & MASK64)

def gostdecrypt(block_in: Tuple[int, int], key):
    a, b = block_in
    a &= MASK64; b &= MASK64
    k = 63
    for _ in range(32):
        b ^= f_func((a + key[k]) & MASK64)
        b &= MASK64
        k -= 1
        a ^= f_func((b + key[k]) & MASK64)
        a &= MASK64
        k -= 1
    return (b & MASK64, a & MASK64)

# =========================
#          SHA-256
# =========================

class sha256_ctx:
    def __init__(self):
        self.state = [0]*8
        self.bitlen = 0  # uint64
        self.data = bytearray(64)
        self.datalen = 0

def ROTRIGHT(a,b): return ((a >> b) | ((a << (32-b)) & MASK32)) & MASK32
def CH(x,y,z):  return ((x & y) ^ ((~x) & z)) & MASK32
def MAJ(x,y,z): return ((x & y) ^ (x & z) ^ (y & z)) & MASK32
def EP0(x):  return (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22)) & MASK32
def EP1(x):  return (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25)) & MASK32
def SIG0(x): return (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x >> 3) & MASK32)) & MASK32
def SIG1(x): return (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x >> 10) & MASK32)) & MASK32

k256 = [
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]

def sha256_transform(ctx: sha256_ctx, data: bytes):
    m = [0]*64
    # big-endian load
    for i in range(16):
        j = 4*i
        m[i] = ((data[j] << 24) | (data[j+1] << 16) | (data[j+2] << 8) | data[j+3]) & MASK32
    for i in range(16, 64):
        m[i] = (SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16]) & MASK32

    a,b,c,d,e,f,g,h = ctx.state

    for i in range(64):
        t1 = (h + EP1(e) + CH(e,f,g) + k256[i] + m[i]) & MASK32
        t2 = (EP0(a) + MAJ(a,b,c)) & MASK32
        h = g
        g = f
        f = e
        e = (d + t1) & MASK32
        d = c
        c = b
        b = a
        a = (t1 + t2) & MASK32

    ctx.state[0] = (ctx.state[0] + a) & MASK32
    ctx.state[1] = (ctx.state[1] + b) & MASK32
    ctx.state[2] = (ctx.state[2] + c) & MASK32
    ctx.state[3] = (ctx.state[3] + d) & MASK32
    ctx.state[4] = (ctx.state[4] + e) & MASK32
    ctx.state[5] = (ctx.state[5] + f) & MASK32
    ctx.state[6] = (ctx.state[6] + g) & MASK32
    ctx.state[7] = (ctx.state[7] + h) & MASK32

def sha256_init(ctx: sha256_ctx):
    ctx.datalen = 0
    ctx.bitlen = 0
    ctx.state[0]=0x6a09e667; ctx.state[1]=0xbb67ae85; ctx.state[2]=0x3c6ef372; ctx.state[3]=0xa54ff53a
    ctx.state[4]=0x510e527f; ctx.state[5]=0x9b05688c; ctx.state[6]=0x1f83d9ab; ctx.state[7]=0x5be0cd19

def sha256_update(ctx: sha256_ctx, data: bytes):
    for b in data:
        ctx.data[ctx.datalen] = b
        ctx.datalen += 1
        if ctx.datalen == 64:
            sha256_transform(ctx, ctx.data)
            ctx.bitlen += 512
            ctx.datalen = 0

def sha256_final(ctx: sha256_ctx) -> bytes:
    i = ctx.datalen
    ctx.bitlen += ctx.datalen * 8

    # Pad
    ctx.data[i] = 0x80
    i += 1
    if i > 56:
        while i < 64:
            ctx.data[i] = 0x00
            i += 1
        sha256_transform(ctx, ctx.data)
        i = 0
    while i < 56:
        ctx.data[i] = 0x00
        i += 1

    # Append length (big-endian)
    bitlen = ctx.bitlen
    for j in range(7, -1, -1):
        ctx.data[i] = (bitlen >> (j*8)) & 0xFF
        i += 1

    sha256_transform(ctx, ctx.data)

    out = bytearray(32)
    for i in range(8):
        out[i*4+0] = (ctx.state[i] >> 24) & 0xFF
        out[i*4+1] = (ctx.state[i] >> 16) & 0xFF
        out[i*4+2] = (ctx.state[i] >> 8) & 0xFF
        out[i*4+3] = ctx.state[i] & 0xFF
    return bytes(out)

# =========================
#       Utilities
# =========================

BLOCK_SIZE = 16
READ_CHUNK  = 64*1024

def be_bytes_to_words(block16: bytes) -> Tuple[int, int]:
    """
    Convert 16 bytes (BE) to two 64-bit words.
    """
    a = 0
    b = 0
    for i in range(8):
        a = ((a << 8) | block16[i]) & MASK64
    for i in range(8, 16):
        b = ((b << 8) | block16[i]) & MASK64
    return a & MASK64, b & MASK64

def be_words_to_bytes(w0: int, w1: int) -> bytes:
    """
    Convert two 64-bit words to 16 bytes (BE).
    """
    out = bytearray(16)
    for i in range(8):
        out[7 - i] = (w0 >> (i*8)) & 0xFF
        out[15 - i] = (w1 >> (i*8)) & 0xFF
    return bytes(out)

def prompt_password(prompt: str) -> str:
    """
    Password prompt with no echo (cross-platform)
    """
    # Using Python's getpass for no-echo input.
    return getpass(prompt)

def generate_iv() -> bytes:
    """
    IV generation with fallback chain
    """
    # Python prefers os.urandom / secrets which already use system RNGs.
    try:
        return os.urandom(BLOCK_SIZE)
    except Exception:
        pass
    # LAST RESORT (not cryptographically strong)
    import random
    random.seed(int(time.time()))
    return bytes([random.getrandbits(8) for _ in range(BLOCK_SIZE)])

def derive_gost_subkeys_from_password(password: str):
    """
    Derive 4096-bit key material from password using MD2II-based hashing,
    then expand to 64 subkeys. Password is treated as bytes (no hex parsing here).
    """
    h4 = bytearray(n1)
    init_gost_keyhash()
    hashing(password.encode('utf-8'), len(password.encode('utf-8')))
    end_gost_keyhash(h4)
    return create_keys(h4)

def pkcs7_pad(buf: bytearray, used: int) -> int:
    """
    PKCS#7 padding. Returns new length after padding, or 0 on error.
    """
    pad = BLOCK_SIZE - (used % BLOCK_SIZE)
    if used + pad > len(buf):
        return 0
    for i in range(pad):
        buf[used + i] = pad
    return used + pad

def pkcs7_unpad(buf: bytearray) -> int:
    """
    Remove PKCS#7 padding from the end of buf. Returns new length (>=0) or 0 on error.
    """
    if len(buf) == 0 or (len(buf) % BLOCK_SIZE) != 0:
        return 0
    pad = buf[-1]
    if pad == 0 or pad > BLOCK_SIZE:
        return 0
    # verify
    for i in range(pad):
        if buf[-1 - i] != pad:
            return 0
    return len(buf) - pad

def has_suffix(name: str, suffix: str) -> bool:
    n = len(name); s = len(suffix)
    if n < s:
        return False
    return name[n - s:] == suffix

def make_output_name_encrypt(inp: str) -> str:
    return f"{inp}.gost2"

def make_output_name_decrypt(inp: str) -> str:
    if has_suffix(inp, ".gost2"):
        return inp[:-6]
    else:
        return f"{inp}.dec"

# =========================
#   CBC Encrypt / Decrypt
# =========================

def cbc_encrypt_stream(fin, fout, subkeys, iv: bytes) -> Tuple[bool, bytes]:
    """
    Write IV (clear), encrypt file in CBC with PKCS#7 padding, then append SHA-256 over ciphertext.
    Returns (err, out_hash)
    """
    # Write IV first (clear)
    try:
        fout.write(iv)
    except Exception:
        return True, b""

    inbuf = bytearray(READ_CHUNK + BLOCK_SIZE)  # extra for padding
    outbuf = bytearray(READ_CHUNK + BLOCK_SIZE)
    prev = bytearray(iv)

    hctx = sha256_ctx(); sha256_init(hctx)

    # Streaming
    # We read until EOF, then do final padding in-memory.
    while True:
        r = fin.read(READ_CHUNK)
        if not r:
            break
        rlen = len(r)
        # process full blocks
        full = (rlen // BLOCK_SIZE) * BLOCK_SIZE
        rem = rlen - full

        # load data into inbuf
        inbuf[:rlen] = r

        # process full blocks
        off = 0
        while off < full:
            # XOR with prev (CBC)
            for i in range(BLOCK_SIZE):
                inbuf[off+i] ^= prev[i]
            w0, w1 = be_bytes_to_words(inbuf[off:off+BLOCK_SIZE])
            c0, c1 = gostcrypt((w0, w1), subkeys)
            outblk = be_words_to_bytes(c0, c1)
            outbuf[off:off+BLOCK_SIZE] = outblk
            prev[:] = outblk
            off += BLOCK_SIZE

        if full:
            fout.write(outbuf[:full])
            sha256_update(hctx, outbuf[:full])

        if rem:
            # keep remainder for final padding step
            tail = inbuf[full:full+rem]
            # read the rest of file now to end then concatenate; simpler: buffer remainder and continue loop
            # but since we loop, just prepend this remainder to next read via carry buffer
            # Here we store it and read next chunk; when next chunk is read, we prepend. For simplicity,
            # accumulate into a temporary buffer and process at the end. We'll handle by keeping a "carry".
            carry = bytearray(tail)
            # Read rest of file into a staging buffer until EOF, then do padding once.
            while True:
                more = fin.read(READ_CHUNK)
                if not more:
                    break
                carry += more
            # Now process carry completely with padding
            used = len(carry)
            carry.extend(b"\x00"*BLOCK_SIZE)
            total = pkcs7_pad(carry, used)
            if total == 0:
                return True, b""
            off = 0
            while off < total:
                for i in range(BLOCK_SIZE):
                    carry[off+i] ^= prev[i]
                w0, w1 = be_bytes_to_words(carry[off:off+BLOCK_SIZE])
                c0, c1 = gostcrypt((w0, w1), subkeys)
                blk = be_words_to_bytes(c0, c1)
                outbuf[off:off+BLOCK_SIZE] = blk
                prev[:] = blk
                off += BLOCK_SIZE
            fout.write(outbuf[:total])
            sha256_update(hctx, outbuf[:total])
            # finalize hash and append
            out_hash = sha256_final(hctx)
            fout.write(out_hash)
            return False, out_hash
        # else: continue read loop

    # Final read produced no rem; need to produce a full padding block
    tail = bytearray(0)
    tail.extend(b"\x00"*BLOCK_SIZE)
    total = pkcs7_pad(tail, 0)
    if total == 0:
        return True, b""
    off = 0
    while off < total:
        for i in range(BLOCK_SIZE):
            tail[off+i] ^= prev[i]
        w0, w1 = be_bytes_to_words(tail[off:off+BLOCK_SIZE])
        c0, c1 = gostcrypt((w0, w1), subkeys)
        blk = be_words_to_bytes(c0, c1)
        outbuf[off:off+BLOCK_SIZE] = blk
        prev[:] = blk
        off += BLOCK_SIZE
    fout.write(outbuf[:total])
    sha256_update(hctx, outbuf[:total])

    out_hash = sha256_final(hctx)
    fout.write(out_hash)
    return False, out_hash

def cbc_decrypt_stream(fin, fout, subkeys) -> Tuple[bool, bool]:
    """
    Stream decryption with SHA-256 verification and PKCS#7 unpadding.
    Returns (err, auth_ok)
    """
    # Determine file size to separate trailing 32-byte hash
    try:
        fin.seek(0, os.SEEK_END)
        fsz = fin.tell()
    except Exception:
        return True, False

    if fsz < (BLOCK_SIZE + 32):
        sys.stderr.write("Error: input too small.\n")
        return True, False

    payload = fsz - 32
    try:
        fin.seek(0, os.SEEK_SET)
    except Exception:
        return True, False

    # Read IV
    iv = fin.read(BLOCK_SIZE)
    if len(iv) != BLOCK_SIZE:
        return True, False

    # Read stored hash (at end)
    try:
        fin.seek(payload, os.SEEK_SET)
    except Exception:
        return True, False
    stored_hash = fin.read(32)
    if len(stored_hash) != 32:
        return True, False

    # Prepare to stream-decrypt ciphertext (between IV and payload end)
    try:
        fin.seek(BLOCK_SIZE, os.SEEK_SET)
    except Exception:
        return True, False
    remaining = payload - BLOCK_SIZE
    if remaining <= 0 or (remaining % BLOCK_SIZE) != 0:
        sys.stderr.write("Error: invalid ciphertext size.\n")
        return True, False

    prev = bytearray(iv)
    hctx = sha256_ctx(); sha256_init(hctx)

    # We'll buffer the last block to remove padding
    while remaining > 0:
        toread = READ_CHUNK if remaining > READ_CHUNK else int(remaining)
        # align to block
        toread -= (toread % BLOCK_SIZE)
        inbuf = fin.read(toread)
        if len(inbuf) != toread:
            return True, False

        # hash ciphertext
        sha256_update(hctx, inbuf)

        outbuf = bytearray(toread)
        off = 0
        while off < toread:
            cpy = inbuf[off:off+BLOCK_SIZE]
            w0, w1 = be_bytes_to_words(cpy)
            p0, p1 = gostdecrypt((w0, w1), subkeys)
            blk = bytearray(be_words_to_bytes(p0, p1))
            for i in range(BLOCK_SIZE):
                blk[i] ^= prev[i]
            prev[:] = cpy
            outbuf[off:off+BLOCK_SIZE] = blk
            off += BLOCK_SIZE

        remaining -= toread
        if remaining > 0:
            fout.write(outbuf)
        else:
            # Last chunk: remove PKCS#7 padding on its last block
            if toread < BLOCK_SIZE:
                return True, False
            keep = toread - BLOCK_SIZE
            if keep:
                fout.write(outbuf[:keep])
            lastblk = bytearray(outbuf[keep:keep+BLOCK_SIZE])
            newlen = pkcs7_unpad(lastblk)
            if newlen == 0 and len(lastblk) != 0:
                sys.stderr.write("Error: invalid padding.\n")
                return True, False
            if newlen:
                fout.write(lastblk[:newlen])

    # Verify hash
    calc_hash = sha256_final(hctx)
    auth_ok = (calc_hash == stored_hash)
    return False, auth_ok

# =========================
#            MAIN
# =========================

def usage(prog: str):
    sys.stderr.write(f"Usage: {prog} c|d <input_file>\n")

def main(argv):
    if len(argv) != 3:
        usage(argv[0])
        return 1
    mode_encrypt = 0
    mode_decrypt = 0
    if argv[1] == "c":
        mode_encrypt = 1
    elif argv[1] == "d":
        mode_decrypt = 1
    else:
        usage(argv[0])
        return 1

    inpath = argv[2]
    outpath = make_output_name_encrypt(inpath) if mode_encrypt else make_output_name_decrypt(inpath)

    # Open files
    try:
        fin = open(inpath, "rb")
    except OSError as e:
        sys.stderr.write(f"Error: cannot open input '{inpath}': {e.strerror}\n")
        return 1
    try:
        fout = open(outpath, "wb")
    except OSError as e:
        sys.stderr.write(f"Error: cannot create output '{outpath}': {e.strerror}\n")
        fin.close()
        return 1

    # Read password (not from CLI)
    password = prompt_password("Enter password: ")

    # Init cipher tables and derive subkeys
    kboxinit()
    subkeys = derive_gost_subkeys_from_password(password)
    # Zero password variable (best effort)
    password = "\0" * len(password)

    err = False
    try:
        if mode_encrypt:
            iv = generate_iv()
            err, hash_out = cbc_encrypt_stream(fin, fout, subkeys, iv)
            if not err:
                print(f"Encryption completed. Output: {outpath}")
        else:
            err, auth_ok = cbc_decrypt_stream(fin, fout, subkeys)
            if not err:
                print(f"Decryption completed. Output: {outpath}")
                print(f"Authentication {'OK' if auth_ok else 'FAILED'}")
    finally:
        fin.close()
        fout.close()

    if err:
        sys.stderr.write("Operation failed due to an error.\n")
        try:
            os.remove(outpath)
        except Exception:
            pass
        return 2
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
