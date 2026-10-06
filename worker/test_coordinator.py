#!/usr/bin/env python3
"""Logic tests for the Worker Coordinator, off-Worker.

The Worker talks to Cloudflare D1 through a tiny async interface (first/all/run/
batch). This test implements that same interface over an in-memory sqlite3
database, then drives the Coordinator exactly as the Worker's entry.py does, so
the SQL and the coordination logic are exercised without a Worker runtime.

It uses the repo's protocol.py (the `cryptography` build) for the *client* side,
proving the Worker's pyprotocol speaks the same wire format as a real node.
"""
import asyncio
import os
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))
sys.path.insert(0, os.path.dirname(HERE))   # repo root for protocol.py / secp.py

import coordinator as COORD
import protocol as P                       # cryptography-based client side

FAILS = []
def check(name, cond):
    print(("  ok  " if cond else "  FAIL ") + name)
    if not cond:
        FAILS.append(name)


# --------------------------------------------- async sqlite D1 shim
class _Stmt:
    def __init__(self, conn, sql, args):
        self.conn, self.sql, self.args = conn, sql, args

    def _exec(self):
        cur = self.conn.execute(self.sql, self.args)
        return cur


class D1Shim:
    """Mimics the subset of the D1 adapter the Coordinator uses."""
    def __init__(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(open(os.path.join(HERE, "schema.sql")).read())
        self.conn.commit()

    async def first(self, sql, *args):
        cur = self.conn.execute(sql, args)
        row = cur.fetchone()
        return dict(row) if row is not None else None

    async def all(self, sql, *args):
        cur = self.conn.execute(sql, args)
        return [dict(r) for r in cur.fetchall()]

    async def run(self, sql, *args):
        cur = self.conn.execute(sql, args)
        results = []
        if sql.strip().upper().find("RETURNING") != -1 or sql.strip().upper().startswith("SELECT"):
            try:
                results = [dict(r) for r in cur.fetchall()]
            except sqlite3.ProgrammingError:
                results = []
        self.conn.commit()
        return {"results": results, "changes": cur.rowcount,
                "last_row_id": cur.lastrowid}

    async def batch(self, ops):
        for sql, args in ops:
            self.conn.execute(sql, args)
        self.conn.commit()


def seed_targets(db, pubs):
    for i, pub in enumerate(pubs):
        db.conn.execute("INSERT INTO targets(ord, pub) VALUES (?,?)", (i, pub.lower()))
    db.conn.commit()


# --------------------------------------------- a minimal client (protocol.py)
class Client:
    def __init__(self, sec, pub, server_ed, server_x, coord):
        self.sign, self.enc = P.load_secret(sec)
        self.ed, self.x = pub["ed25519"], pub["x25519"]
        self.server_ed, self.server_x = server_ed, server_x
        self.coord = coord
        self.out = 1000
        self.server_seq = None

    async def call(self, path, op, payload=None):
        self.out += 1
        body = dict(payload or {}); body["op"] = op; body["rid"] = os.urandom(4).hex()
        env = P.seal(body, self.sign, self.x, self.server_ed, self.server_x, self.out)
        import json
        code, reply = await self.coord.handle(path, json.dumps(env))
        if code != 200:
            return code, reply
        snd, got, ts, seq = P.open_envelope(
            reply, self.ed, self.enc, lambda h: self.server_x, last_seq=self.server_seq)
        self.server_seq = seq
        return code, got


async def main():
    srv_sec, srv_pub = P.generate_identity()
    db = D1Shim()
    coord = COORD.Coordinator(db, srv_sec, {"lease_seconds": 2})

    # targets: a planted key + decoys
    import random
    random.seed(7)
    planted_priv = random.randrange(1, COORD.secp.N)
    planted_pub = COORD.secp.compressed(planted_priv)
    decoys = [COORD.secp.compressed(random.randrange(1, COORD.secp.N)) for _ in range(20)]
    seed_targets(db, [planted_pub] + decoys)

    n_sec, n_pub = P.generate_identity()
    node = Client(n_sec, n_pub, srv_pub["ed25519"], srv_pub["x25519"], coord)
    n2_sec, n2_pub = P.generate_identity()
    node2 = Client(n2_sec, n2_pub, srv_pub["ed25519"], srv_pub["x25519"], coord)

    print("[register]")
    code, r = await node.call("/v1/register", "register", {"x25519": n_pub["x25519"], "gpu": "RTX 3070", "sw": "t"})
    check("register ok", code == 200 and r.get("ok") and r["status"] == "active")
    check("targets_count 21", r["targets_count"] == 21)
    await node2.call("/v1/register", "register", {"x25519": n2_pub["x25519"], "gpu": "A100", "sw": "t"})

    print("\n[unregistered node refused]")
    strange_sec, strange_pub = P.generate_identity()
    stranger = Client(strange_sec, strange_pub, srv_pub["ed25519"], srv_pub["x25519"], coord)
    code, r = await stranger.call("/v1/block/request", "block_request")
    check("unknown node 403", code == 403)

    print("\n[targets download]")
    code, r = await node.call("/v1/targets", "targets")
    check("targets listed", code == 200 and r["count"] == 21 and planted_pub in r["targets"])
    check("digest matches register", r["digest"] == (await coord._targets_meta())[0])

    print("\n[block request: random mint, two nodes distinct]")
    code, b1 = await node.call("/v1/block/request", "block_request")
    code, b2 = await node2.call("/v1/block/request", "block_request")
    check("b1 minted", b1["ok"] and not b1["reassigned"] and not b1["from_list"])
    check("distinct prefixes", b1["prefix"] != b2["prefix"])
    check("prefix is 54 hex", len(b1["prefix"]) == 54 and int(b1["prefix"], 16) >= 0)

    print("\n[complete: only leaseholder]")
    code, r = await node2.call("/v1/block/complete", "block_complete",
                               {"block_idx": b1["block_idx"], "seconds": 1.0, "keys_checked": 1 << 40})
    check("non-owner refused", r.get("ok") is False)
    code, r = await node.call("/v1/block/complete", "block_complete",
                              {"block_idx": b1["block_idx"], "seconds": 1.0, "keys_checked": 1 << 40})
    check("owner completes", r.get("ok") and r["blocks_done"] == 1)
    code, r = await node.call("/v1/block/complete", "block_complete",
                              {"block_idx": b1["block_idx"], "seconds": 1.0})
    check("double-complete idempotent", r.get("ok") and r.get("note") == "already recorded")

    print("\n[expired lease reassigned, attempts bumped]")
    # b2 is still leased to node2 with a 2s lease; wait it out, then node asks.
    import time as _t
    _t.sleep(2.1)
    code, b3 = await node.call("/v1/block/request", "block_request")
    check("expired reassigned to next asker", b3["reassigned"] and b3["prefix"] == b2["prefix"])
    check("attempts bumped to 2", b3["attempts"] == 2)
    # node2's late completion is now stale (node holds it)
    code, r = await node2.call("/v1/block/complete", "block_complete",
                               {"block_idx": b2["block_idx"], "seconds": 1.0})
    check("stale completion refused", r.get("ok") is False)

    print("\n[match: sealed verify + in targets]")
    sealed = P.seal_secret(planted_priv.to_bytes(32, "big"), srv_pub["x25519"])
    code, r = await node.call("/v1/match", "match",
                              {"privkey_sealed": sealed, "pubkey": planted_pub, "block_idx": b3["block_idx"]})
    check("match verified", r.get("verified") is True and r.get("in_targets") is True)
    code, r = await node.call("/v1/match", "match",
                              {"privkey_sealed": P.seal_secret(planted_priv.to_bytes(32, "big"), srv_pub["x25519"]),
                               "pubkey": planted_pub})
    check("duplicate detected", r.get("duplicate") is True)

    print("\n[match: node lies about the keypair]")
    wrong_pub = COORD.secp.compressed(0x9999)
    code, r = await node.call("/v1/match", "match",
                              {"privkey_sealed": P.seal_secret(planted_priv.to_bytes(32, "big"), srv_pub["x25519"]),
                               "pubkey": wrong_pub})
    check("mismatched keypair not verified", r.get("verified") is False)

    print("\n[match: garbage sealed blob rejected]")
    code, r = await node.call("/v1/match", "match", {"privkey_sealed": "deadbeef", "pubkey": planted_pub})
    check("bad sealed blob rejected", r.get("ok") is False)

    print("\n[dashboard renders]")
    html = await coord.render_dashboard()
    check("dashboard has node + match", "keyhunt-coord-server" in html
          and "RTX 3070" in html and "verified matches: 1" in html)

    print("\n[stats]")
    code, r = await node.call("/v1/stats", "stats")
    check("stats ok", r.get("ok"))
    check("verified match counted", r["verified_matches"] == 1)
    check("blocks total consistent", r["blocks"]["total"] ==
          r["blocks"]["leased"] + r["blocks"]["expired"] + r["blocks"]["done"] + r["blocks"]["pending"])

    print("\n" + ("ALL COORDINATOR TESTS PASSED" if not FAILS else "FAILURES: " + ", ".join(FAILS)))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
