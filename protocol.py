"""Message envelope: every message is encrypted to the recipient and signed by
the sender. Public-key only -- there are no passwords, tokens, or shared
secrets anywhere in this protocol.

Each party holds two keypairs:
  Ed25519  identity / signing.  The public half IS the party's node id.
  X25519   static encryption key, used as the recipient of an ECDH.

Sealing a message:
  1. generate an ephemeral X25519 keypair (forward secrecy for this message)
  2. ECDH(ephemeral_priv, recipient_static_pub) -> HKDF-SHA256 -> 32-byte key
  3. ChaCha20-Poly1305 encrypt the payload, with the envelope header as AAD
  4. Ed25519-sign (header || ciphertext) with the sender's identity key

Opening verifies the signature *before* attempting decryption, so an
unauthenticated peer cannot even make us run the AEAD.

Replay protection is by (timestamp window, strictly increasing sequence
number). The recipient rejects anything outside the window or at or below the
last sequence number seen from that sender.
"""

import json
import os
import time
import zlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"KHCOORD1"
VERSION = 1
CLOCK_SKEW_SEC = 120
MAX_PLAINTEXT = 64 * 1024 * 1024


class ProtocolError(Exception):
    pass


# ------------------------------------------------------------------ key I/O
def raw_pub(k):
    return k.public_bytes(serialization.Encoding.Raw,
                          serialization.PublicFormat.Raw)


def raw_priv(k):
    return k.private_bytes(serialization.Encoding.Raw,
                           serialization.PrivateFormat.Raw,
                           serialization.NoEncryption())


def generate_identity():
    """Returns (secret_dict, public_dict)."""
    sign = Ed25519PrivateKey.generate()
    enc = X25519PrivateKey.generate()
    pub = {"ed25519": raw_pub(sign.public_key()).hex(),
           "x25519": raw_pub(enc.public_key()).hex()}
    sec = dict(pub)
    sec["ed25519_secret"] = raw_priv(sign).hex()
    sec["x25519_secret"] = raw_priv(enc).hex()
    return sec, pub


def load_secret(d):
    return (Ed25519PrivateKey.from_private_bytes(bytes.fromhex(d["ed25519_secret"])),
            X25519PrivateKey.from_private_bytes(bytes.fromhex(d["x25519_secret"])))


def write_key_file(path, obj, secret=False):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
        f.write("\n")
    if secret:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass          # best effort; Windows ACLs differ


# ------------------------------------------------------------ canonical bytes
def _header_bytes(v, sender, recipient, epk, nonce, ts, seq):
    return b"".join([
        MAGIC, bytes([v]),
        sender, recipient, epk, nonce,
        int(ts).to_bytes(8, "big"), int(seq).to_bytes(8, "big"),
    ])


def _derive(shared, sender, recipient, nonce):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=nonce,
                info=MAGIC + sender + recipient).derive(shared)


# ------------------------------------------------------------------- sealing
def seal(payload, sender_sign_key, sender_enc_pub_hex,
         recipient_ed_hex, recipient_x_hex, seq, ts=None):
    """payload: JSON-serialisable dict. Returns an envelope dict."""
    sender = raw_pub(sender_sign_key.public_key())
    recipient = bytes.fromhex(recipient_ed_hex)
    rx = X25519PublicKey.from_public_bytes(bytes.fromhex(recipient_x_hex))

    eph = X25519PrivateKey.generate()
    epk = raw_pub(eph.public_key())
    nonce = os.urandom(12)
    ts = int(time.time()) if ts is None else int(ts)

    plain = zlib.compress(json.dumps(payload, separators=(",", ":")).encode(), 6)
    hdr = _header_bytes(VERSION, sender, recipient, epk, nonce, ts, seq)
    key = _derive(eph.exchange(rx), sender, recipient, nonce)
    ct = ChaCha20Poly1305(key).encrypt(nonce, plain, hdr)

    sig = sender_sign_key.sign(hdr + ct)
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

    Returns (sender_hex, payload, ts, seq).
    """
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
    try:
        Ed25519PublicKey.from_public_bytes(sender).verify(sig, hdr + ct)
    except InvalidSignature:
        raise ProtocolError("bad signature")

    now = time.time() if now is None else now
    if abs(now - ts) > CLOCK_SKEW_SEC:
        raise ProtocolError("timestamp outside accepted window")
    if last_seq is not None and seq <= last_seq:
        raise ProtocolError("replayed or out-of-order sequence number")

    key = _derive(my_x_priv.exchange(X25519PublicKey.from_public_bytes(epk)),
                  sender, recipient, nonce)
    try:
        plain = ChaCha20Poly1305(key).decrypt(nonce, ct, hdr)
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
