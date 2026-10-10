#!/usr/bin/env python3
"""Single source of truth for test-suite cryptography.

All E2E scripts MUST import curve math from here — never duplicate prime
constants (a past P-vs-N mixup proved how silently that breaks verification).
"""

import base64
import hashlib
import os

# secp256k1: p = 2**256 - 2**32 - 977 (ends ...FFFFFC2F),
#           n = ...BAAEDCE6AF48A03BBFD25E8CD0364141. DO NOT CONFUSE.
K256_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
K256_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
K256_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
          0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
assert K256_P == 2**256 - 2**32 - 977
assert K256_P % 4 == 3

P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
          0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)
P256_A = (P256_P - 3) % P256_P

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b58dec(s):
    n = 0
    for ch in s:
        n = n * 58 + B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + raw


def pt_add(a, b, P, A):
    if a is None:
        return b
    if b is None:
        return a
    x1, y1 = a
    x2, y2 = b
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if a == b:
        s = ((3 * x1 * x1 + A) % P) * pow(2 * y1, P - 2, P) % P
    else:
        s = ((y2 - y1) * pow(x2 - x1, P - 2, P)) % P
    x3 = (s * s - x1 - x2) % P
    return (x3, (s * (x1 - x3) - y1) % P)


def pt_mul(k, pt, P, A):
    r = None
    while k:
        if k & 1:
            r = pt_add(r, pt, P, A)
        pt = pt_add(pt, pt, P, A)
        k >>= 1
    return r


def decompress_k256(comp):
    assert len(comp) == 33 and comp[0] in (2, 3)
    x = int.from_bytes(comp[1:], "big")
    y2 = (pow(x, 3, K256_P) + 7) % K256_P
    y = pow(y2, (K256_P + 1) // 4, K256_P)
    if (y & 1) != (comp[0] & 1):
        y = K256_P - y
    Q = (x, y)
    assert (Q[1] * Q[1] - Q[0] ** 3 - 7) % K256_P == 0, "not on curve"
    return Q


def ecdsa_verify_k256(Q, digest, sig):
    assert len(digest) == 32 and len(sig) == 64
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    assert 1 <= r < K256_N and 1 <= s < K256_N, "range"
    e = int.from_bytes(digest, "big")
    w = pow(s, K256_N - 2, K256_N)
    pt = pt_add(pt_mul((e * w) % K256_N, K256_G, K256_P, 0),
                pt_mul((r * w) % K256_N, Q, K256_P, 0), K256_P, 0)
    assert pt is not None and pt[0] % K256_N == r, "BAD SIGNATURE"


def ecdsa_verify_p256(Q, digest, sig):
    assert len(digest) == 32 and len(sig) == 64
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    assert 1 <= r < P256_N and 1 <= s < P256_N, "range"
    e = int.from_bytes(digest, "big")
    w = pow(s, P256_N - 2, P256_N)
    pt = pt_add(pt_mul((e * w) % P256_N, P256_G, P256_P, P256_A),
                pt_mul((r * w) % P256_N, Q, P256_P, P256_A), P256_P, P256_A)
    assert pt is not None and pt[0] % P256_N == r, "BAD SIGNATURE"


# Backwards-compatible aliases used across the suite.
decompress = decompress_k256


def ecdsa_verify(Q, digest, sig, P=None, N=None, G=None, A=None):
    if P == P256_P or (P is None and N == P256_N):
        return ecdsa_verify_p256(Q, digest, sig)
    return ecdsa_verify_k256(Q, digest, sig)


def es256_sign_p256(digest, priv):
    while True:
        k = int.from_bytes(os.urandom(32), "big") % P256_N or 1
        R = pt_mul(k, P256_G, P256_P, P256_A)
        r = R[0] % P256_N
        if r == 0:
            continue
        s = (pow(k, P256_N - 2, P256_N) * (int.from_bytes(digest, "big") + r * priv)) % P256_N
        if s == 0:
            continue
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def sha256(b):
    return hashlib.sha256(b).digest()


def es256k_sign(digest, priv, low_s=True):
    """Deterministic-shape (random-k) secp256k1 signature, 64-byte compact."""
    assert len(digest) == 32
    while True:
        k = int.from_bytes(os.urandom(32), "big") % K256_N or 1
        R = pt_mul(k, K256_G, K256_P, 0)
        r = R[0] % K256_N
        if r == 0:
            continue
        s = (pow(k, K256_N - 2, K256_N) * (int.from_bytes(digest, "big") + r * priv)) % K256_N
        if s == 0:
            continue
        if low_s and s > K256_N // 2:
            s = K256_N - s
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
