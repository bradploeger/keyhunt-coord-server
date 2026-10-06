#!/usr/bin/env python3
"""Prove the Worker's stdlib-only crypto is byte-for-byte compatible with the
`cryptography`-based protocol.py used by keyhunt-node and keyhunt-gpu.

Two layers:
  1. primitives (khcrypto) vs. `cryptography`: Ed25519, X25519, HKDF-SHA256,
     ChaCha20-Poly1305 -- byte-exact outputs, accept/reject behaviour.
  2. full wire interop: an envelope sealed by protocol.py opens in pyprotocol and
     vice versa; a sealed box (as keyhunt-gpu produces) opens in pyprotocol and
     vice versa.

Run:  python3 worker/test_khcrypto.py   (needs `cryptography` installed)
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))
sys.path.insert(0, os.path.dirname(HERE))   # repo root for protocol.py

import khcrypto as K
import pyprotocol as W
import protocol as P
from protocol import generate_identity, load_secret as P_load

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

FAILS = []
def check(name, cond):
    print(("  ok  " if cond else "  FAIL ") + name)
    if not cond:
        FAILS.append(name)

def raw_pub(k):
    return k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
def raw_priv(k):
    return k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                           serialization.NoEncryption())


def test_primitives():
    print("[primitives vs cryptography]")
    ok = True
    for _ in range(40):
        seed = os.urandom(32)
        sk = Ed25519PrivateKey.from_private_bytes(seed)
        pub = raw_pub(sk.public_key())
        msg = os.urandom(1 + (_ % 50))
        ok &= K.ed25519_public_from_seed(seed) == pub
        ok &= K.ed25519_sign(seed, msg) == sk.sign(msg)
        ok &= K.ed25519_verify(pub, msg, sk.sign(msg)) is True
        bad = bytearray(sk.sign(msg)); bad[0] ^= 1
        ok &= K.ed25519_verify(pub, msg, bytes(bad)) is False
    check("ed25519 pub/sign byte-exact + verify accept/reject", ok)

    ok = True
    for _ in range(40):
        a = X25519PrivateKey.generate(); b = X25519PrivateKey.generate()
        asec, bpub = raw_priv(a), raw_pub(b.public_key())
        ok &= K.x25519_public_from_secret(asec) == raw_pub(a.public_key())
        ok &= K.x25519_exchange(asec, bpub) == a.exchange(X25519PublicKey.from_public_bytes(bpub))
    check("x25519 pub + ECDH byte-exact", ok)

    ok = True
    for i in range(60):
        key = os.urandom(32); nonce = os.urandom(12)
        pt = os.urandom(i * 5); aad = os.urandom((i * 2) % 33)
        ref = ChaCha20Poly1305(key).encrypt(nonce, pt, aad or None)
        ok &= K.chacha20poly1305_encrypt(key, nonce, pt, aad) == ref
        ok &= K.chacha20poly1305_decrypt(key, nonce, ref, aad) == pt
    check("chacha20-poly1305 byte-exact + decrypt", ok)

    ok = True
    for i in range(20):
        ikm = os.urandom(32); salt = os.urandom(12); info = os.urandom(i)
        ref = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)
        ok &= K.hkdf_sha256(ikm, salt, info, 32) == ref
    check("hkdf-sha256 byte-exact", ok)


def test_wire_interop():
    print("\n[wire interop: pyprotocol <-> protocol.py]")
    node_sec, node_pub = generate_identity()
    srv_sec, srv_pub = generate_identity()
    node_sign_P, node_enc_P = P_load(node_sec)
    srv_sign_P, srv_enc_P = P_load(srv_sec)
    node_seed, node_x = W.load_secret(node_sec)
    srv_seed, srv_x = W.load_secret(srv_sec)

    payload = {"op": "block_request", "rid": "abc", "n": 42}
    env = P.seal(payload, node_sign_P, node_pub["x25519"],
                 srv_pub["ed25519"], srv_pub["x25519"], seq=5)
    snd, got, ts, seq = W.open_envelope(env, srv_pub["ed25519"], srv_x,
                                        lambda h: node_pub["x25519"], last_seq=0)
    check("protocol.py seal -> pyprotocol open", got == payload and snd == node_pub["ed25519"])

    rep = {"ok": True, "status": "active", "rid": "abc"}
    env2 = W.seal(rep, srv_seed, srv_pub["x25519"],
                  node_pub["ed25519"], node_pub["x25519"], seq=9)
    snd2, got2, _, _ = P.open_envelope(env2, node_pub["ed25519"], node_enc_P,
                                       lambda h: srv_pub["x25519"], last_seq=0)
    check("pyprotocol seal -> protocol.py open", got2 == rep and snd2 == srv_pub["ed25519"])

    # tamper / replay / wrong-recipient rejected by pyprotocol
    bad = dict(env); bad["ct"] = "ff" + env["ct"][2:]
    try:
        W.open_envelope(bad, srv_pub["ed25519"], srv_x, lambda h: node_pub["x25519"], last_seq=0)
        check("tamper rejected", False)
    except W.ProtocolError:
        check("tamper rejected", True)
    try:
        W.open_envelope(env, srv_pub["ed25519"], srv_x, lambda h: node_pub["x25519"], last_seq=5)
        check("replay rejected", False)
    except W.ProtocolError:
        check("replay rejected", True)

    # sealed box both directions (keyhunt-gpu style)
    priv = os.urandom(32)
    check("protocol.py seal_secret -> pyprotocol open_sealed",
          W.open_sealed(P.seal_secret(priv, srv_pub["x25519"]), srv_x, srv_pub["x25519"]) == priv)
    check("pyprotocol seal_secret -> protocol.py open_sealed",
          P.open_sealed(W.seal_secret(priv, srv_pub["x25519"]), srv_enc_P, srv_pub["x25519"]) == priv)


def main():
    test_primitives()
    test_wire_interop()
    print("\n" + ("ALL KHCRYPTO TESTS PASSED" if not FAILS else "FAILURES: " + ", ".join(FAILS)))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
