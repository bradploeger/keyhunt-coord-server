"""Pure-Python crypto primitives for the Cloudflare Python Worker.

Cloudflare's Python Workers run on Pyodide, where native-extension packages --
`cryptography` and `PyNaCl` among them -- cannot be imported, and the Workers
WebCrypto surface has no ChaCha20-Poly1305. The coordination protocol's wire
format (shared verbatim with keyhunt-node and keyhunt-gpu) is built on Ed25519,
X25519, HKDF-SHA256 and ChaCha20-Poly1305, so to keep the deployed nodes working
unchanged we reimplement exactly those four primitives here using only the
standard library (`hashlib`, `hmac`), which Pyodide provides.

These are byte-for-byte compatible with the `cryptography` implementations used
by the other repos -- `test_khcrypto.py` proves it by cross-checking every
primitive, plus full envelope and sealed-box round trips, against `cryptography`.

The implementations are the well-known reference algorithms (RFC 8032 Ed25519,
RFC 7748 X25519, RFC 8439 ChaCha20-Poly1305). They favour clarity and
correctness over speed; a coordination server runs a few of these per request,
which is well within a Worker's CPU budget on the paid plan.
"""

import hashlib
import hmac as _hmac

# ============================================================ HKDF-SHA256
def hkdf_sha256(ikm, salt, info, length=32):
    if salt is None or len(salt) == 0:
        salt = b"\x00" * hashlib.sha256().digest_size
    prk = _hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    i = 1
    while len(okm) < length:
        t = _hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


# ============================================================ Ed25519 (RFC 8032)
_p = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_d = (-121665 * pow(121666, _p - 2, _p)) % _p
_I = pow(2, (_p - 1) // 4, _p)


def _ed_recover_x(y, sign):
    if y >= _p:
        return None
    xx = (y * y - 1) * pow(_d * y * y + 1, _p - 2, _p) % _p
    x = pow(xx, (_p + 3) // 8, _p)
    if (x * x - xx) % _p != 0:
        x = (x * _I) % _p
    if (x * x - xx) % _p != 0:
        return None
    if (x & 1) != sign:
        x = _p - x
    return x


# extended homogeneous coordinates (X, Y, Z, T)
_ed_By = 4 * pow(5, _p - 2, _p) % _p
_ed_Bx = _ed_recover_x(_ed_By, 0)
_ed_B = (_ed_Bx, _ed_By, 1, _ed_Bx * _ed_By % _p)


def _ed_add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _p
    C = 2 * P[3] * Q[3] * _d % _p
    D = 2 * P[2] * Q[2] % _p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)


def _ed_mul(s, P):
    Q = (0, 1, 1, 0)  # neutral
    while s > 0:
        if s & 1:
            Q = _ed_add(Q, P)
        P = _ed_add(P, P)
        s >>= 1
    return Q


def _ed_eq(P, Q):
    x1 = P[0] * pow(P[2], _p - 2, _p) % _p
    y1 = P[1] * pow(P[2], _p - 2, _p) % _p
    x2 = Q[0] * pow(Q[2], _p - 2, _p) % _p
    y2 = Q[1] * pow(Q[2], _p - 2, _p) % _p
    return x1 == x2 and y1 == y2


def _ed_encode(P):
    zi = pow(P[2], _p - 2, _p)
    x = P[0] * zi % _p
    y = P[1] * zi % _p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _ed_decode(b):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    x = _ed_recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _p)


def _ed_secret_expand(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    return a, h[32:]


def ed25519_public_from_seed(seed):
    a, _ = _ed_secret_expand(seed)
    return _ed_encode(_ed_mul(a, _ed_B))


def ed25519_sign(seed, msg):
    a, prefix = _ed_secret_expand(seed)
    A = _ed_encode(_ed_mul(a, _ed_B))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % _L
    R = _ed_encode(_ed_mul(r, _ed_B))
    k = int.from_bytes(hashlib.sha512(R + A + msg).digest(), "little") % _L
    s = (r + k * a) % _L
    return R + int.to_bytes(s, 32, "little")


def ed25519_verify(public, msg, sig):
    if len(sig) != 64 or len(public) != 32:
        return False
    A = _ed_decode(public)
    if A is None:
        return False
    R = sig[:32]
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    Rp = _ed_decode(R)
    if Rp is None:
        return False
    k = int.from_bytes(hashlib.sha512(R + public + msg).digest(), "little") % _L
    # [s]B == R + [k]A
    return _ed_eq(_ed_mul(s, _ed_B), _ed_add(Rp, _ed_mul(k, A)))


# ============================================================ X25519 (RFC 7748)
_x_p = 2 ** 255 - 19
_A24 = 121665


def _x_clamp(k):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def x25519(scalar, u_bytes):
    k = _x_clamp(scalar)
    u = int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)
    x1 = u
    x2, z2, x3, z3 = 1, 0, u, 1
    swap = 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        A = (x2 + z2) % _x_p
        AA = A * A % _x_p
        B = (x2 - z2) % _x_p
        BB = B * B % _x_p
        E = (AA - BB) % _x_p
        C = (x3 + z3) % _x_p
        D = (x3 - z3) % _x_p
        DA = D * A % _x_p
        CB = C * B % _x_p
        x3 = (DA + CB) % _x_p
        x3 = x3 * x3 % _x_p
        z3 = (DA - CB) % _x_p
        z3 = x1 * (z3 * z3 % _x_p) % _x_p
        x2 = AA * BB % _x_p
        z2 = E * ((AA + _A24 * E) % _x_p) % _x_p
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    res = x2 * pow(z2, _x_p - 2, _x_p) % _x_p
    return int.to_bytes(res, 32, "little")


def x25519_public_from_secret(secret):
    return x25519(secret, (9).to_bytes(32, "little"))


def x25519_exchange(secret, peer_public):
    return x25519(secret, peer_public)


# ============================================================ ChaCha20-Poly1305 (RFC 8439)
def _rotl32(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _chacha_qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl32(s[b] ^ s[c], 7)


_CHACHA_CONST = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)


def _chacha_block(key, counter, nonce):
    st = list(_CHACHA_CONST)
    st += [int.from_bytes(key[i:i + 4], "little") for i in range(0, 32, 4)]
    st.append(counter & 0xFFFFFFFF)
    st += [int.from_bytes(nonce[i:i + 4], "little") for i in range(0, 12, 4)]
    w = list(st)
    for _ in range(10):
        _chacha_qr(w, 0, 4, 8, 12)
        _chacha_qr(w, 1, 5, 9, 13)
        _chacha_qr(w, 2, 6, 10, 14)
        _chacha_qr(w, 3, 7, 11, 15)
        _chacha_qr(w, 0, 5, 10, 15)
        _chacha_qr(w, 1, 6, 11, 12)
        _chacha_qr(w, 2, 7, 8, 13)
        _chacha_qr(w, 3, 4, 9, 14)
    out = bytearray()
    for i in range(16):
        out += int.to_bytes((w[i] + st[i]) & 0xFFFFFFFF, 4, "little")
    return bytes(out)


def _chacha20(key, counter, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = _chacha_block(key, counter + i // 64, nonce)
        block = data[i:i + 64]
        out += bytes(b ^ ks[j] for j, b in enumerate(block))
    return bytes(out)


_P1305 = (1 << 130) - 5


def _poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        n = int.from_bytes(block + b"\x01", "little")  # append 1 bit past the block
        acc = ((acc + n) * r) % _P1305
    acc = (acc + s) & ((1 << 128) - 1)
    return int.to_bytes(acc, 16, "little")


def _pad16(x):
    if len(x) % 16 == 0:
        return b""
    return b"\x00" * (16 - (len(x) % 16))


def _poly_key(key, nonce):
    return _chacha_block(key, 0, nonce)[:32]


def chacha20poly1305_encrypt(key, nonce, plaintext, aad=b""):
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("bad key/nonce length")
    ct = _chacha20(key, 1, nonce, plaintext)
    mac_data = aad + _pad16(aad) + ct + _pad16(ct)
    mac_data += int.to_bytes(len(aad), 8, "little") + int.to_bytes(len(ct), 8, "little")
    tag = _poly1305(_poly_key(key, nonce), mac_data)
    return ct + tag


def chacha20poly1305_decrypt(key, nonce, ciphertext, aad=b""):
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("bad key/nonce length")
    if len(ciphertext) < 16:
        raise ValueError("ciphertext too short")
    ct, tag = ciphertext[:-16], ciphertext[-16:]
    mac_data = aad + _pad16(aad) + ct + _pad16(ct)
    mac_data += int.to_bytes(len(aad), 8, "little") + int.to_bytes(len(ct), 8, "little")
    expected = _poly1305(_poly_key(key, nonce), mac_data)
    if not _hmac.compare_digest(expected, tag):
        raise ValueError("authentication failed")
    return _chacha20(key, 1, nonce, ct)
