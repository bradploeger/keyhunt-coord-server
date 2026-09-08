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
- **block/request** — the server hands the node a **randomly chosen** 216-bit
  (27-byte) prefix, one block of `2^40` keys. Leases expire; if a block is not
  completed within `lease_seconds` its prefix is re-handed to the **next** node
  that asks, with priority over minting a new random block, so no abandoned
  prefix is dropped.
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
test_random_prefix.py  unit tests for random prefixes + expired-block reassignment
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
  "space_prefix": "",
  "targets_file": "targets.txt",
  "lease_seconds": 3600,
  "max_blocks": 1048576,
  "require_approval": false,
  "match_hook": "curl -s -d 'FOUND %K' https://ntfy.sh/your-topic"
}
```

Each block is a random 54-hex (27-byte, 216-bit) prefix covering the `2^40` keys
below it. By default (`space_prefix` empty) prefixes are drawn from the full
`2^216` space using OS entropy — an effectively infinite, non-repeating hunt.
Set `space_prefix` to a hex string shorter than 54 characters to pin the
high-order bits and draw the remaining nibbles at random; this lets you split
the space across several independent servers by giving each a different fixed
prefix. There is no dedup: the space is astronomically large, so a pure random
draw effectively never collides. Set `require_approval: true` to hold new nodes in a
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
python3 test_random_prefix.py      # block model, no server needed
python3 test_e2e.py                # full live-server run (generate fixtures first)
```

`test_random_prefix.py` drives the `Coordinator` directly and checks that new
blocks get distinct random 216-bit prefixes, that a `space_prefix` constraint is
honoured, and — the core of this behaviour — that an expired lease is re-handed
to the next requester with the same prefix and a bumped attempt count, taking
priority over minting a new block. It also confirms only the current holder can
complete a block after a reassignment.

`test_e2e.py` starts a real server on a random localhost port and checks
registration, target download, random-prefix block leasing across two nodes,
completion, rejection of nonexistent-block completion, match verification
(including a node lying about the keypair), duplicate detection, stats, and four
security properties: tampered ciphertext, replayed sequence number, wrong
recipient, and an unregistered node trying to lease. Generate fixtures first:

```
python3 keygen.py server.key
python3 keygen.py node1.key
python3 - <<'PY'
import json, random
from secp import compressed, N
random.seed(3); priv = random.randrange(1, N)
lines = [compressed(priv)] + [compressed(random.randrange(1, N)) for _ in range(999)]
random.shuffle(lines); open("targets.txt","w").write("\n".join(lines)+"\n")
json.dump({"targets_file":"targets.txt","lease_seconds":3600}, open("coord.json","w"))
json.dump({"priv":"%064x"%priv,"pub":compressed(priv)}, open("planted.json","w"))
PY
python3 test_e2e.py
```

## Notes and limits

- A 40-bit block takes minutes to an hour on one GPU. Set `lease_seconds` above
  your slowest node's block time, or a block still being worked will be declared
  expired and its prefix handed to another node — wasting the original node's
  effort, since only the *current* leaseholder can report a block complete. A
  node whose lease has lapsed should just request again rather than report a
  block it no longer holds.
- `keys_checked` in a completion is trusted for throughput stats only; it never
  affects correctness. Matches are always re-verified.
- Every match report is stored, including unverified ones, with a note
  explaining why they failed — so a misbehaving node is visible, not silently
  dropped.

## License

MIT — see `LICENSE`.
