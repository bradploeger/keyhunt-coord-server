#!/usr/bin/env python3
"""Build a targets file, optionally planting a key inside a given prefix range.

  # 35000 random decoys plus one real key at prefix||0x0000ABCDEF
  python3 tools/make_test_targets.py --count 35000 \
      --plant A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D:0xABCDEF \
      > targets.txt
"""
import argparse, random, sys

P  = 2**256 - 2**32 - 977
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def add(Pt, Q):
    if Pt is None: return Q
    if Q is None: return Pt
    if Pt[0] == Q[0] and (Pt[1] + Q[1]) % P == 0: return None
    if Pt == Q: s = 3 * Pt[0] * Pt[0] * pow(2 * Pt[1], P - 2, P) % P
    else:       s = (Q[1] - Pt[1]) * pow(Q[0] - Pt[0], P - 2, P) % P
    x = (s * s - Pt[0] - Q[0]) % P
    return (x, (s * (Pt[0] - x) - Pt[1]) % P)

def mul(k, Pt=(Gx, Gy)):
    R = None
    while k:
        if k & 1: R = add(R, Pt)
        Pt = add(Pt, Pt); k >>= 1
    return R

def compressed(k):
    x, y = mul(k % N)
    return ("03" if y & 1 else "02") + "%064x" % x

ap = argparse.ArgumentParser()
ap.add_argument("--count", type=int, default=35000)
ap.add_argument("--plant", action="append", default=[],
                help="PREFIXHEX:OFFSET, e.g. A1B2...:0xABCDEF")
ap.add_argument("--seed", type=int, default=1)
a = ap.parse_args()

random.seed(a.seed)
lines = []
for spec in a.plant:
    pfx, off = spec.rsplit(":", 1)
    unknown = 256 - 4 * len(pfx)
    k = (int(pfx, 16) << unknown) + int(off, 0)
    sys.stderr.write("planted private key %064x\n" % k)
    lines.append(compressed(k))

for _ in range(a.count - len(lines)):
    lines.append(compressed(random.randrange(1, N)))

random.shuffle(lines)
print("\n".join(lines))
