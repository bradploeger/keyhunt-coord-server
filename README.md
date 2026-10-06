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
- **block/request** — the server hands the node a 216-bit (27-byte) prefix, one
  block of `2^40` keys. The choice follows a strict priority: (1) any **expired**
  block — a prefix whose lease ran out without completion — is re-handed to the
  next node that asks, so no abandoned prefix is dropped; (2) otherwise, if the
  operator supplied a **prefix list** (`prefix_list_file`), the next unassigned
  prefix from that file, in file order; (3) otherwise a fresh **random** prefix.
  The response carries `reassigned` and `from_list` flags saying which path it
  took.
- **block/complete** — a node reports a block done and how long it took.
- **match** — a node reports a found key as a **sealed box**: the 32-byte
  private key encrypted to this server's X25519 key (produced by keyhunt-gpu,
  same `protocol.py` sealing), plus the 33-byte compressed public key in hex.
  The node never holds the private key in the clear. The server opens the sealed
  box with its X25519 secret and **recomputes the public key from the private
  key itself before believing it**, so a node cannot fake a hit.
- **stats** — per-node prefixes requested, processed and currently pending,
  total keys and processing time, derived average processing rate, plus
  global block and match counts.

`/healthz` is a plain unauthenticated GET for liveness checks. `/` and
`/stats.html` are a plain unauthenticated GET dashboard: an HTML page listing
the same per-node numbers (node id, GPU type, prefixes requested / processed
/ pending, total keys processed, total processing time, average processing
rate) for viewing in a browser. It's safe to leave open to the public --
a node id is already its Ed25519 public key.

### Live console stats

While running, the server redraws a small table on its console every 5 seconds
with rolling numbers for the last 15 minutes, last hour and last 24 hours:
nodes seen, blocks requested, blocks expired, blocks completed, and effective
rate (combined throughput of all nodes: each node's keys from blocks completed
in the window / the processing time it reported for them, summed). The table
updates in place; if anything else is printed (errors, a MATCH banner), a
fresh table starts below it so nothing is overwritten. `--stats-interval N`
changes the refresh period; `--stats-interval 0` turns it off.

The numbers come from an `events` table in `coord.db` (pruned to ~25 hours).
On the first start after upgrading, it is backfilled from the `blocks` table,
so the first 24h figures are approximate. A window with no completed blocks
shows the rate as `-`.

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
test_prefix_list.py    unit tests for the preassigned prefix-list feature
_testclient.py         minimal client used only by test_e2e.py
test_bootstrap.py      backups production files, generates fixutres, runs test_e2e.py
                       and restores the production files when fininshed..
```

## Setup

```
pip install -r requirements.txt
python3 keygen.py server.key       # -> server.key (secret), server.pub (share)
```

Copy `coord.json` to `coord.json` and edit:

```json
{
  "space_prefix": "",
  "prefix_list_file": "prefixes.txt",
  "targets_file": "targets.txt",
  "lease_seconds": 3600,
  "require_approval": false,
  "match_hook": "curl -s -d 'FOUND %K' https://ntfy.sh/your-topic"
}
```

Each block is a 54-hex (27-byte, 216-bit) prefix covering the `2^40` keys below
it. With no `prefix_list_file` and an empty `space_prefix`, prefixes are drawn
from the full `2^216` space using OS entropy — an effectively infinite,
non-repeating hunt. Set `space_prefix` to a hex string shorter than 54
characters to pin the high-order bits and draw the remaining nibbles at random;
this lets you split the space across several independent servers by giving each
a different fixed prefix. There is no dedup on random draws: the space is
astronomically large, so a pure random draw effectively never collides. Set
`require_approval: true` to hold new nodes in a `pending` state until you set
them `active` in the database by hand.

### Checking a specific list of prefixes first

Point `prefix_list_file` at a text file of prefixes you want searched before the
server falls back to random assignment — for example a shortlist of ranges you
have reason to prioritise. One prefix per line; blank lines and `#` comments are
ignored; each prefix must be exactly 54 hex characters (a single `2^40`-key
block) and, if `space_prefix` is set, must start with it. Malformed or
out-of-space lines are skipped with a count reported at startup.

```
# prefixes.txt — 216-bit prefixes to check first, in this order
0000000000000000000000000000000000000000000000000000a1
0000000000000000000000000000000000000000000000000000a2
0000000000000000000000000000000000000000000000000000a3
```

Listed prefixes are handed out in file order, ahead of any random prefix but
behind expired blocks (an unfinished prefix is always re-covered first).
Loading is **idempotent across restarts**: a prefix already recorded in the
database — leased, done, or still waiting — is not re-added, so you can restart
the server, or append more lines to the file and restart, without duplicating
work. Progress shows up in `stats` as `blocks.pending` (listed prefixes not yet
handed out).

To drop every listed prefix that hasn't been handed out yet, run:

```
python3 server.py --clear-pending --db coord.db --config coord.json
```

This deletes all `pending` blocks and exits; leased, expired and done blocks
are kept. Because seeding only skips prefixes already in the database, the
server will re-add the cleared prefixes on its next start if
`prefix_list_file` still lists them — remove or empty that file (or drop the
setting) first if you want them gone for good.

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

## Running on Cloudflare (Python Worker + D1)

The `worker/` directory runs the same server as a **Cloudflare Python Worker**
backed by a **D1** database instead of the stdlib HTTP server and SQLite. The
wire protocol is identical, so deployed `keyhunt-node` / `keyhunt-gpu` clients
need no changes. Because Cloudflare's Pyodide runtime cannot import
`cryptography`/`PyNaCl` (and WebCrypto lacks ChaCha20-Poly1305), the four
primitives the protocol uses are reimplemented stdlib-only in
`worker/src/khcrypto.py`, byte-for-byte compatible with `protocol.py` (proven by
`worker/test_khcrypto.py`). See `worker/README.md` for the deploy steps
(`wrangler d1 create`, `schema.sql`, `wrangler secret put SERVER_KEY`, seed the
targets, `wrangler deploy`). Deploy on the Workers Paid plan — the pure-Python
crypto runs per request.

## Test

```
python3 test_random_prefix.py      # random block model, no server needed
python3 test_prefix_list.py        # preassigned prefix-list feature, no server needed
python3 test_e2e.py                # full live-server run (generate fixtures first)
python3 bootstrap_test.py          # full live-server run handles file backup, fixture 
                                     generation, and file restoration
```

`test_random_prefix.py` drives the `Coordinator` directly and checks that new
blocks get distinct random 216-bit prefixes, that a `space_prefix` constraint is
honoured, and — the core of this behaviour — that an expired lease is re-handed
to the next requester with the same prefix and a bumped attempt count, taking
priority over minting a new block. It also confirms only the current holder can
complete a block after a reassignment.

`test_prefix_list.py` checks the preassigned prefix list: listed prefixes are
handed out in file order ahead of random assignment, expired blocks still take
priority over the list, malformed and out-of-`space_prefix` lines are skipped,
the list falls back to random once exhausted, seeding is idempotent across a
restart, `stats` reports the pending count, and `--clear-pending`'s
`clear_pending` removes only pending blocks.

`test_e2e.py` starts a real server on a random localhost port and checks
registration, target download, random-prefix block leasing across two nodes,
completion, rejection of nonexistent-block completion, match verification
(including a node lying about the keypair), duplicate detection, stats, and four
security properties: tampered ciphertext, replayed sequence number, wrong
recipient, and an unregistered node trying to lease. It is easier to just use the test
bootstrapping tool: 

```
python3 test_bootstrap.py
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
