# keyhunt-coord-server

Coordination server for a fleet of distributed [keyhunt-gpu](#) search nodes. It
hands out work, tracks progress, and collects verified results. Every message in
both directions is encrypted to the recipient and signed by the sender;
authentication is public-key only — there are no passwords, tokens, or shared
secrets anywhere.

The node client is a **separate repository**: [`keyhunt-node`](#). This repo is
the server side. The two share `protocol.py` and `keygen.py` verbatim; keep them
in sync when the wire format changes.

## What it does

- **register** — a node announces its GPU type and search-software version.
- **targets** — a node downloads the current search list.
- **block/request** — a node leases a 216-bit (27-byte) prefix, one block of
  `2^40` keys. Leases expire; a dead node's block is reclaimed and re-handed.
- **block/complete** — a node reports a block done and how long it took.
- **match** — a node reports the 32-byte private key and 33-byte compressed
  public key, both hex. **The server recomputes the public key from the private
  key itself before believing it**, so a node cannot fake a hit.
- **stats** — per-node blocks completed, total and average processing time,
  derived keys/sec, plus global block and match counts.

`/healthz` is a plain unauthenticated GET for liveness checks.

## Security model

Two keypairs per party: **Ed25519** for signing (this is the node id) and
**X25519** for encryption. Each message uses a fresh ephemeral ECDH →
HKDF-SHA256 → ChaCha20-Poly1305, then an Ed25519 signature over the header and
ciphertext. The signature is verified **before** decryption, so an
unauthenticated peer can't make the server run the cipher. Replay is stopped by
a timestamp window plus a strictly increasing per-sender sequence number.

This gives confidentiality, integrity, sender authenticity, per-message forward
secrecy, and replay resistance. It is **not** a transport-layer TLS replacement —
run it behind HTTPS anyway (see [Running for real](#running-for-real)); the
app-layer crypto protects payloads regardless, but TLS hides metadata and gives
you a normal certificate story.

Because the server independently verifies every reported match, even a fully
malicious registered node cannot inject a false positive — the worst it can do
is waste block leases, which show up in the stats as poor throughput.

## Files

```
server.py              the coordination server
protocol.py            sealed-envelope layer (shared with keyhunt-node)
secp.py                pure-Python secp256k1, used only to verify matches
keygen.py              make an Ed25519+X25519 identity (shared with keyhunt-node)
coord.example.json     sample configuration
make_test_targets.py   build a target list, optionally with a planted key
test_e2e.py            live-server integration + security tests
_testclient.py         minimal client used only by test_e2e.py
```

## Setup

```
pip install -r requirements.txt
python3 keygen.py server.key       # -> server.key (secret), server.pub (share)
```

Copy `coord.example.json` to `coord.json` and edit:

```json
{
  "space_prefix": "abcdef0123456789abcdef0123456789abcdef0123456789",
  "targets_file": "targets.txt",
  "lease_seconds": 3600,
  "max_blocks": 1048576,
  "require_approval": false,
  "match_hook": "curl -s -d 'FOUND %K' https://ntfy.sh/your-topic"
}
```

`space_prefix` is the fixed high part of the key space, in hex, shorter than 54
characters. The server appends the remaining nibbles to enumerate blocks: 48 hex
here leaves 6 nibbles, so up to `16^6` blocks, each a distinct 54-hex (27-byte)
prefix covering `2^40` keys. Set `require_approval: true` to hold new nodes in a
`pending` state until you set them `active` in the database by hand.

Provide a `targets.txt` (one compressed pubkey per line). Then run:

```
python3 server.py --config coord.json --key server.key --db coord.db \
    --host 0.0.0.0 --port 8443
```

Distribute the generated `server.pub` to each node out-of-band. **Never commit
`.key` or `.pub` files** — `.gitignore` excludes them.

## Running for real

Put it behind a reverse proxy for TLS:

```
# nginx
location / { proxy_pass http://127.0.0.1:8443; }
```

The stdlib server with SQLite serialises all writes under one lock — correct,
and fine for a few hundred nodes polling every few seconds. The `Coordinator`
class holds all logic and is transport-agnostic, so wrapping it in gunicorn and
pointing it at Postgres is a small change if you outgrow that. There is no
built-in rate limiting; add it at the proxy if you expose this to an untrusted
network.

## Test

```
python3 make_test_targets.py --count 1000 \
    --plant abcdef0123456789abcdef0123456789abcdef0123456789000005:0x1234ABCD \
    > targets.txt
python3 test_e2e.py
```

`test_e2e.py` starts a real server on a random localhost port and checks
registration, target download, in-order block leasing, completion, rejection of
un-owned and nonexistent blocks, match verification (including a node lying
about the keypair), duplicate detection, stats, and four security properties:
tampered ciphertext, replayed sequence number, wrong recipient, and an
unregistered node trying to lease. All must pass.

## Notes and limits

- A 40-bit block takes minutes to an hour on one GPU. Set `lease_seconds` above
  your slowest node's block time, or you will reclaim blocks still being worked.
- `keys_checked` in a completion is trusted for throughput stats only; it never
  affects correctness. Matches are always re-verified.
- Every match report is stored, including unverified ones, with a note
  explaining why they failed — so a misbehaving node is visible, not silently
  dropped.

## License

MIT — see `LICENSE`.
