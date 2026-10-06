"""Minimal secp256k1, used only to independently verify reported matches.
Slow and pure Python, which is fine: matches are rare and correctness matters
more than speed here.
"""
P  = 2**256 - 2**32 - 977
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _add(A, B):
    if A is None: return B
    if B is None: return A
    if A[0] == B[0] and (A[1] + B[1]) % P == 0: return None
    if A == B:
        s = 3 * A[0] * A[0] * pow(2 * A[1], P - 2, P) % P
    else:
        s = (B[1] - A[1]) * pow(B[0] - A[0], P - 2, P) % P
    x = (s * s - A[0] - B[0]) % P
    return (x, (s * (A[0] - x) - A[1]) % P)


def mul_g(k):
    k %= N
    if k == 0: return None
    R, Q = None, (GX, GY)
    while k:
        if k & 1: R = _add(R, Q)
        Q = _add(Q, Q)
        k >>= 1
    return R


def compressed(k):
    """Private key int -> 33-byte compressed public key, hex."""
    pt = mul_g(k)
    if pt is None: return None
    x, y = pt
    return ("03" if y & 1 else "02") + "%064x" % x
