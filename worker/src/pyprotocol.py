"""Sealed-envelope + sealed-box layer for the Worker, built on khcrypto.

This is the Worker's stdlib-only equivalent of the repo's protocol.py (which
uses the `cryptography` package and cannot run on Pyodide). The wire format is
identical, so the Worker interoperates with the deployed keyhunt-node and
keyhunt-gpu clients unchanged -- test_khcrypto.py proves it by round-tripping
envelopes and sealed boxes against protocol.py in both directions.

Keys here are raw bytes: an Ed25519 32-byte seed and an X25519 32-byte scalar,
exactly the hex stored in a .key file by keygen.py.
"""

import json
import os
import time
import zlib

import khcrypto as C

MAGIC = b"KHCOORD1"
VERSION = 1
CLOCK_SKEW_SEC = 120
MAX_PLAINTEXT = 64 * 1024 * 1024
MAGIC_SEAL = b"KHSEAL1"


class ProtocolError(Exception):
    pass


def load_secret(d):
    """Return (ed25519_seed, x25519_scalar) raw bytes from a secret-key dict."""
    return bytes.fromhex(d["ed25519_secret"]), bytes.fromhex(d["x25519_secret"])


def _header_bytes(v, sender, recipient, epk, nonce, ts, seq):
    return b"".join([
        MAGIC, bytes([v]),
        sender, recipient, epk, nonce,
        int(ts).to_bytes(8, "big"), int(seq).to_bytes(8, "big"),
    ])


def _derive(shared, sender, recipient, nonce):
    return C.hkdf_sha256(shared, salt=nonce, info=MAGIC + sender + recipient, length=32)


# ------------------------------------------------------------------- envelope
def seal(payload, sender_ed_seed, sender_enc_pub_hex,
         recipient_ed_hex, recipient_x_hex, seq, ts=None):
    sender = C.ed25519_public_from_seed(sender_ed_seed)
    recipient = bytes.fromhex(recipient_ed_hex)
    rx = bytes.fromhex(recipient_x_hex)

    eph = os.urandom(32)
    epk = C.x25519_public_from_secret(eph)
    nonce = os.urandom(12)
    ts = int(time.time()) if ts is None else int(ts)

    plain = zlib.compress(json.dumps(payload, separators=(",", ":")).encode(), 6)
    hdr = _header_bytes(VERSION, sender, recipient, epk, nonce, ts, seq)
    key = _derive(C.x25519_exchange(eph, rx), sender, recipient, nonce)
    ct = C.chacha20poly1305_encrypt(key, nonce, plain, hdr)
    sig = C.ed25519_sign(sender_ed_seed, hdr + ct)
    return {
        "v": VERSION,
        "from": sender.hex(),
        "to": recipient.hex(),
        "epk": epk.hex(),
        "nonce": nonce.hex(),
        "ts": ts,
        "seq": seq,
        "ct": ct.hex(),
        "sig": sig.hex(),
        "sender_x25519": sender_enc_pub_hex,
    }


def open_envelope(env, my_ed_pub_hex, my_x_priv, lookup_sender_x,
                  last_seq=None, now=None):
    """Verify and decrypt. lookup_sender_x(sender_hex) -> x25519 hex or None.
    my_x_priv is this recipient's raw X25519 scalar. Returns (sender_hex,
    payload, ts, seq)."""
    try:
        if env.get("v") != VERSION:
            raise ProtocolError("unsupported protocol version")
        sender = bytes.fromhex(env["from"])
        recipient = bytes.fromhex(env["to"])
        epk = bytes.fromhex(env["epk"])
        nonce = bytes.fromhex(env["nonce"])
        ct = bytes.fromhex(env["ct"])
        sig = bytes.fromhex(env["sig"])
        ts = int(env["ts"])
        seq = int(env["seq"])
    except (KeyError, ValueError, TypeError) as e:
        raise ProtocolError("malformed envelope: %s" % e)

    if len(sender) != 32 or len(recipient) != 32 or len(epk) != 32 or len(nonce) != 12:
        raise ProtocolError("bad field length")
    if recipient.hex() != my_ed_pub_hex:
        raise ProtocolError("message not addressed to us")

    # Signature first: never run the AEAD on unauthenticated input.
    hdr = _header_bytes(VERSION, sender, recipient, epk, nonce, ts, seq)
    if not C.ed25519_verify(sender, hdr + ct, sig):
        raise ProtocolError("bad signature")

    now = time.time() if now is None else now
    if abs(now - ts) > CLOCK_SKEW_SEC:
        raise ProtocolError("timestamp outside accepted window")
    if last_seq is not None and seq <= last_seq:
        raise ProtocolError("replayed or out-of-order sequence number")

    key = _derive(C.x25519_exchange(my_x_priv, epk), sender, recipient, nonce)
    try:
        plain = C.chacha20poly1305_decrypt(key, nonce, ct, hdr)
    except Exception:
        raise ProtocolError("decryption failed")

    if len(plain) > MAX_PLAINTEXT:
        raise ProtocolError("payload too large")
    try:
        payload = json.loads(zlib.decompress(plain, 0, MAX_PLAINTEXT))
    except Exception as e:
        raise ProtocolError("bad payload: %s" % e)
    if not isinstance(payload, dict):
        raise ProtocolError("payload must be an object")
    return sender.hex(), payload, ts, seq


# ----------------------------------------------------------------- sealed box
def _seal_key(shared, epk, recipient_x, nonce):
    info = MAGIC_SEAL + epk + recipient_x
    return C.hkdf_sha256(shared, salt=nonce, info=info, length=32), info


def seal_secret(plaintext, recipient_x_hex):
    recipient_x = bytes.fromhex(recipient_x_hex)
    if len(recipient_x) != 32:
        raise ProtocolError("recipient x25519 key must be 32 bytes")
    eph = os.urandom(32)
    epk = C.x25519_public_from_secret(eph)
    nonce = os.urandom(12)
    key, info = _seal_key(C.x25519_exchange(eph, recipient_x), epk, recipient_x, nonce)
    ct = C.chacha20poly1305_encrypt(key, nonce, bytes(plaintext), info)
    return (epk + nonce + ct).hex()


def open_sealed(blob_hex, recipient_x_priv, recipient_x_hex=None):
    """recipient_x_priv is the raw X25519 scalar. Returns plaintext bytes."""
    try:
        blob = bytes.fromhex(blob_hex)
    except (ValueError, TypeError) as e:
        raise ProtocolError("malformed sealed blob: %s" % e)
    if len(blob) < 32 + 12 + 16:
        raise ProtocolError("sealed blob too short")
    epk, nonce, ct = blob[:32], blob[32:44], blob[44:]
    if recipient_x_hex is None:
        recipient_x = C.x25519_public_from_secret(recipient_x_priv)
    else:
        recipient_x = bytes.fromhex(recipient_x_hex)
    key, info = _seal_key(C.x25519_exchange(recipient_x_priv, epk), epk, recipient_x, nonce)
    try:
        return C.chacha20poly1305_decrypt(key, nonce, ct, info)
    except Exception:
        raise ProtocolError("sealed-box decryption failed")
