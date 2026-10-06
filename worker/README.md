# keyhunt-coord on Cloudflare (Python Worker + D1)

This directory runs the coordination server as a **Cloudflare Python Worker**
backed by a **D1** database, instead of the stdlib HTTP server + SQLite in the
repo root. The wire protocol is unchanged, so existing `keyhunt-node` and
`keyhunt-gpu` clients work against it without modification.

## Why the crypto is reimplemented

Cloudflare Python Workers run on Pyodide, where `cryptography` and `PyNaCl`
cannot be imported, and the Workers WebCrypto surface has no ChaCha20-Poly1305.
The protocol needs Ed25519, X25519, HKDF-SHA256 and ChaCha20-Poly1305, so
`src/khcrypto.py` reimplements exactly those four, stdlib-only (`hashlib`,
`hmac`), and `src/pyprotocol.py` is the stdlib equivalent of the repo's
`protocol.py`. `test_khcrypto.py` proves byte-for-byte compatibility against
`cryptography`, including full envelope and sealed-box round trips in both
directions — so a Worker and a deployed node speak the identical format.

These are the reference algorithms (RFC 8032 / 7748 / 8439); they are not
constant-time. That is acceptable here (keys are public and verification is of
signatures over public data), but note they run per request, so deploy on the
Workers **Paid** plan where the per-request CPU budget is generous.

## Layout

```
src/entry.py        WorkerEntrypoint: routing, D1 adapter, env/secret wiring
src/coordinator.py  async port of the Coordinator (all /v1 ops) over D1
src/pyprotocol.py   sealed-envelope + sealed-box layer (stdlib)
src/khcrypto.py     Ed25519 / X25519 / HKDF-SHA256 / ChaCha20-Poly1305 (stdlib)
src/secp.py         pure-Python secp256k1 for match verification (copied from root)
schema.sql          D1 schema (nodes, blocks, events, matches, targets, meta)
wrangler.jsonc      Worker + D1 binding + tunable vars
tools/make_seed_sql.py   turn a targets.txt (+ optional prefixes.txt) into seed SQL
test_khcrypto.py    crypto + wire-interop tests (need `cryptography`)
test_coordinator.py coordination-logic tests over an in-memory SQLite D1 shim
```

No third-party Python packages are used, so there is nothing to vendor.

## Deploy

```sh
cd worker
npm install -g wrangler          # or: npx wrangler ...

# 1. Create the D1 database and paste the printed id into wrangler.jsonc
npx wrangler d1 create keyhunt-coord

# 2. Apply the schema
npx wrangler d1 execute keyhunt-coord --file schema.sql --remote

# 3. Server identity: generate a keypair (from the repo root) and store the
#    SECRET file as a Worker secret. Distribute the .pub to nodes out of band,
#    exactly as before.
python3 ../keygen.py server.key          # -> server.key (secret), server.pub (share)
npx wrangler secret put SERVER_KEY       # paste the full contents of server.key

# 4. Seed the target list (and any preassigned prefixes) into D1
python3 tools/make_seed_sql.py --targets ../targets.txt \
    [--prefixes ../prefixes.txt] > seed.sql
npx wrangler d1 execute keyhunt-coord --file seed.sql --remote

# 5. (optional) tunables in wrangler.jsonc [vars]:
#    SPACE_PREFIX, LEASE_SECONDS, REQUIRE_APPROVAL

# 6. Deploy
npx wrangler deploy
```

Point nodes at the Worker's URL (`https://keyhunt-coord.<subdomain>.workers.dev`
or your custom domain). `GET /` and `/stats.html` serve the dashboard;
`GET /healthz` is the liveness check.

## Operating notes

- **Approving nodes** (`REQUIRE_APPROVAL=1`): new nodes land `pending`; activate
  with `npx wrangler d1 execute keyhunt-coord --remote --command "UPDATE nodes SET status='active' WHERE id='<node-id>'"`.
- **Clearing pending prefixes** (the old `--clear-pending`):
  `... --command "DELETE FROM blocks WHERE state='pending'"`.
- **Seeing matches**: verified matches are logged (pubkey only — never the
  private key) to `wrangler tail`, and stored in the `matches` table; read them
  with `... --command "SELECT pubkey,privkey,note FROM matches WHERE verified=1"`.
- **Lease expiry** is swept lazily on each block request and each stats read
  (there is no background thread in a Worker); the live console table from the
  stdlib server is replaced by the HTML dashboard.

## Test (locally, no Worker runtime needed)

```sh
python3 worker/test_khcrypto.py      # crypto byte-compat + wire interop
python3 worker/test_coordinator.py   # all /v1 ops over an in-memory SQLite D1 shim
```
