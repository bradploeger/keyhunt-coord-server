#!/usr/bin/env python3
"""Coordination server for distributed keyhunt-gpu nodes.

Every request and response is a sealed envelope (see protocol.py): encrypted to
the recipient and signed by the sender. Authentication is by Ed25519 public key
alone -- a node's id *is* its public key, so there is nothing to steal from the
server that would let an attacker impersonate a node.

Endpoints, all POST, all taking an envelope:

  /v1/register        announce gpu type and software version
  /v1/targets         download the search list
  /v1/block/request   lease a 216-bit prefix to search
  /v1/block/complete  report a finished block and how long it took
  /v1/match           report a found key (32-byte private, 33-byte public, hex)
  /v1/stats           per-node and global counters

  /healthz            plain GET, no auth, liveness only
"""

import argparse
import hashlib
import json
import os
import random
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import protocol as P
import secp

PREFIX_HEX_LEN = 54          # 27 bytes = 216 bits
LEASE_SECONDS = 3600
MAX_BODY = 8 * 1024 * 1024

SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
  id            TEXT PRIMARY KEY,
  x25519        TEXT NOT NULL,
  gpu           TEXT,
  sw            TEXT,
  status        TEXT NOT NULL DEFAULT 'active',
  first_seen    REAL,
  last_seen     REAL,
  last_seq      INTEGER NOT NULL DEFAULT 0,
  out_seq       INTEGER NOT NULL DEFAULT 0,
  blocks_done   INTEGER NOT NULL DEFAULT 0,
  total_seconds REAL    NOT NULL DEFAULT 0,
  keys_checked  INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS blocks (
  idx           INTEGER PRIMARY KEY AUTOINCREMENT,
  prefix        TEXT NOT NULL,        -- the randomly chosen 54-hex (216-bit) prefix
  state         TEXT NOT NULL DEFAULT 'leased',  -- leased | expired | done
  node_id       TEXT,
  leased_at     REAL,
  lease_expires REAL,
  completed_at  REAL,
  seconds       REAL,
  attempts      INTEGER NOT NULL DEFAULT 0
);
-- Expired blocks are re-handed oldest-first, so index by (state, lease_expires).
CREATE INDEX IF NOT EXISTS blocks_state ON blocks(state, lease_expires);
CREATE TABLE IF NOT EXISTS matches (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  node_id      TEXT,
  block_idx    INTEGER,
  privkey      TEXT UNIQUE,
  pubkey       TEXT,
  reported_at  REAL,
  verified     INTEGER,
  in_targets   INTEGER,
  note         TEXT
);
"""


class Coordinator:
    def __init__(self, cfg, db_path, secret, targets_path):
        self.cfg = cfg
        self.lock = threading.Lock()
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.executescript(SCHEMA)
        self.db.commit()

        self.sign_key, self.enc_key = P.load_secret(secret)
        self.ed_hex = secret["ed25519"]
        self.x_hex = secret["x25519"]

        # Optional high-order constraint. Empty (the default) means prefixes are
        # drawn from the full 2^216 space; a non-empty value pins the top bits,
        # e.g. to carve the space between several independent servers.
        self.space_prefix = str(cfg.get("space_prefix", "")).lower()
        if len(self.space_prefix) >= PREFIX_HEX_LEN:
            raise SystemExit("space_prefix must be shorter than %d hex chars" % PREFIX_HEX_LEN)
        if self.space_prefix:
            int(self.space_prefix, 16)          # validate hex
        self.random_nibbles = PREFIX_HEX_LEN - len(self.space_prefix)
        self.lease_seconds = float(cfg.get("lease_seconds", LEASE_SECONDS))
        self.require_approval = bool(cfg.get("require_approval", False))
        self.rng = random.SystemRandom()

        with open(targets_path) as f:
            self.targets = [l.strip().lower() for l in f
                            if l.strip() and not l.startswith("#")]
        self.target_set = set(self.targets)
        self.targets_digest = hashlib.sha256(
            "\n".join(self.targets).encode()).hexdigest()

    def random_prefix(self):
        """A fresh random 54-hex (216-bit) prefix, respecting any space_prefix
        constraint. Pure random, drawn from os-backed entropy; no dedup."""
        rnd = self.rng.getrandbits(4 * self.random_nibbles)
        return self.space_prefix + ("%0*x" % (self.random_nibbles, rnd))

    # ------------------------------------------------------------- node state
    def get_node(self, nid):
        r = self.db.execute(
            "SELECT id,x25519,gpu,sw,status,last_seq,out_seq FROM nodes WHERE id=?",
            (nid,)).fetchone()
        if not r:
            return None
        return dict(zip(["id", "x25519", "gpu", "sw", "status", "last_seq", "out_seq"], r))

    def next_out_seq(self, nid):
        cur = self.db.execute("UPDATE nodes SET out_seq=out_seq+1 WHERE id=? "
                              "RETURNING out_seq", (nid,)).fetchone()
        self.db.commit()
        return cur[0]

    # ------------------------------------------------------------- operations
    def op_register(self, nid, p):
        x = str(p.get("x25519", ""))
        gpu = str(p.get("gpu", "unknown"))[:200]
        sw = str(p.get("sw", "unknown"))[:100]
        try:
            if len(bytes.fromhex(x)) != 32:
                raise ValueError
        except ValueError:
            return {"ok": False, "error": "bad x25519 key"}

        now = time.time()
        existing = self.get_node(nid)
        if existing:
            # A node's encryption key is pinned on first registration. Letting
            # it rotate freely here would let anyone who steals the signing key
            # redirect ciphertext to themselves.
            if existing["x25519"] != x:
                return {"ok": False, "error": "x25519 key does not match registration"}
            self.db.execute("UPDATE nodes SET gpu=?,sw=?,last_seen=? WHERE id=?",
                            (gpu, sw, now, nid))
        else:
            status = "pending" if self.require_approval else "active"
            self.db.execute(
                "INSERT INTO nodes(id,x25519,gpu,sw,status,first_seen,last_seen) "
                "VALUES (?,?,?,?,?,?,?)", (nid, x, gpu, sw, status, now, now))
        self.db.commit()
        n = self.get_node(nid)
        return {"ok": True, "status": n["status"],
                "targets_digest": self.targets_digest,
                "targets_count": len(self.targets),
                "prefix_hex_len": PREFIX_HEX_LEN,
                "unknown_bits": 256 - 4 * PREFIX_HEX_LEN}

    def op_targets(self, nid, p):
        return {"ok": True, "digest": self.targets_digest,
                "count": len(self.targets), "targets": self.targets}

    def op_block_request(self, nid, p):
        now = time.time()
        exp = now + self.lease_seconds

        # Any block whose lease ran out without a completion is now 'expired'.
        # These take priority: an unfinished prefix must be searched by someone.
        self.db.execute(
            "UPDATE blocks SET state='expired' "
            "WHERE state='leased' AND lease_expires < ?", (now,))

        # 1. Re-hand the oldest expired block, if there is one. Oldest-first so a
        #    prefix that has been waiting longest gets covered soonest.
        row = self.db.execute(
            "SELECT idx, prefix FROM blocks WHERE state='expired' "
            "ORDER BY lease_expires LIMIT 1").fetchone()
        if row:
            idx, prefix = row
            self.db.execute(
                "UPDATE blocks SET state='leased', node_id=?, leased_at=?, "
                "lease_expires=?, attempts=attempts+1 WHERE idx=?",
                (nid, now, exp, idx))
            self.db.commit()
            return {"ok": True, "block_idx": idx, "prefix": prefix,
                    "reassigned": True, "attempts": self._attempts(idx),
                    "unknown_bits": 256 - 4 * PREFIX_HEX_LEN,
                    "lease_expires": exp, "lease_seconds": self.lease_seconds}

        # 2. Otherwise mint a brand-new block with a fresh random prefix.
        prefix = self.random_prefix()
        cur = self.db.execute(
            "INSERT INTO blocks(prefix, state, node_id, leased_at, lease_expires, "
            "attempts) VALUES (?,'leased',?,?,?,1) RETURNING idx",
            (prefix, nid, now, exp))
        idx = cur.fetchone()[0]
        self.db.commit()
        return {"ok": True, "block_idx": idx, "prefix": prefix,
                "reassigned": False, "attempts": 1,
                "unknown_bits": 256 - 4 * PREFIX_HEX_LEN,
                "lease_expires": exp, "lease_seconds": self.lease_seconds}

    def _attempts(self, idx):
        r = self.db.execute("SELECT attempts FROM blocks WHERE idx=?", (idx,)).fetchone()
        return r[0] if r else 0

    def op_block_complete(self, nid, p):
        try:
            idx = int(p["block_idx"])
            secs = float(p["seconds"])
            keys = int(p.get("keys_checked", 0))
        except (KeyError, ValueError, TypeError):
            return {"ok": False, "error": "bad fields"}
        if not (0 <= secs < 30 * 86400) or keys < 0:
            return {"ok": False, "error": "implausible timing"}

        row = self.db.execute("SELECT state,node_id FROM blocks WHERE idx=?",
                              (idx,)).fetchone()
        if not row:
            return {"ok": False, "error": "no such block"}
        state, owner = row
        if state == "done":
            return {"ok": True, "note": "already recorded"}

        # Only the node currently holding the lease may complete it. If A's lease
        # expired and the prefix was re-handed to B, A's late report is stale: B is
        # now searching that prefix, and marking it done here would waste B's work.
        # A 'reassigned' flag on the request tells the node when it has picked up
        # someone else's abandoned block; a node that finds its lease gone should
        # simply request again rather than report a block it no longer owns.
        if owner != nid:
            return {"ok": False, "error": "block is not leased to you "
                    "(lease may have expired and been reassigned)"}

        self.db.execute(
            "UPDATE blocks SET state='done', completed_at=?, seconds=? WHERE idx=?",
            (time.time(), secs, idx))
        self.db.execute(
            "UPDATE nodes SET blocks_done=blocks_done+1, total_seconds=total_seconds+?, "
            "keys_checked=keys_checked+?, last_seen=? WHERE id=?",
            (secs, keys, time.time(), nid))
        self.db.commit()
        done, total = self.db.execute(
            "SELECT (SELECT COUNT(*) FROM blocks WHERE state='done'), COUNT(*) FROM blocks"
        ).fetchone()
        return {"ok": True, "block_idx": idx, "blocks_done": done, "blocks_total": total}

    def op_match(self, nid, p):
        priv = str(p.get("privkey", "")).lower().strip()
        pub = str(p.get("pubkey", "")).lower().strip()
        try:
            idx = int(p.get("block_idx", -1))
        except (ValueError, TypeError):
            idx = -1

        if len(priv) != 64 or len(pub) != 66 or pub[:2] not in ("02", "03"):
            return {"ok": False, "error": "expect 64-hex private key and 66-hex compressed public key"}
        try:
            k = int(priv, 16)
            int(pub, 16)
        except ValueError:
            return {"ok": False, "error": "not hex"}
        if not (0 < k < secp.N):
            return {"ok": False, "error": "private key out of range"}

        # Recompute independently. A node claiming a match proves nothing.
        derived = secp.compressed(k)
        verified = (derived == pub)
        in_targets = pub in self.target_set
        note = ""
        if not verified:
            note = "private key does not derive the reported public key"
        elif not in_targets:
            note = "verified keypair but the public key is not in the target list"

        try:
            self.db.execute(
                "INSERT INTO matches(node_id,block_idx,privkey,pubkey,reported_at,"
                "verified,in_targets,note) VALUES (?,?,?,?,?,?,?,?)",
                (nid, idx, priv, pub, time.time(), int(verified), int(in_targets), note))
            self.db.commit()
            dup = False
        except sqlite3.IntegrityError:
            dup = True

        if verified and in_targets and not dup:
            sys.stderr.write(
                "\n*** MATCH from node %s ***\n    pubkey  %s\n    privkey %s\n\n"
                % (nid[:16], pub, priv))
            sys.stderr.flush()
            hook = self.cfg.get("match_hook")
            if hook:
                os.system(hook.replace("%P", pub).replace("%K", priv))
        return {"ok": True, "verified": verified, "in_targets": in_targets,
                "duplicate": dup, "note": note}

    def op_stats(self, nid, p):
        nodes = []
        for r in self.db.execute(
                "SELECT id,gpu,sw,status,first_seen,last_seen,blocks_done,"
                "total_seconds,keys_checked FROM nodes ORDER BY blocks_done DESC"):
            d = dict(zip(["id", "gpu", "sw", "status", "first_seen", "last_seen",
                          "blocks_done", "total_seconds", "keys_checked"], r))
            d["avg_seconds_per_block"] = (d["total_seconds"] / d["blocks_done"]
                                          if d["blocks_done"] else None)
            d["keys_per_sec"] = (d["keys_checked"] / d["total_seconds"]
                                 if d["total_seconds"] > 0 else None)
            nodes.append(d)
        leased, expired, done = (self.db.execute(
            "SELECT SUM(state='leased'), SUM(state='expired'), SUM(state='done') "
            "FROM blocks").fetchone())
        nmatch = self.db.execute(
            "SELECT COUNT(*) FROM matches WHERE verified=1 AND in_targets=1").fetchone()[0]
        return {"ok": True, "nodes": nodes,
                "blocks": {"leased": leased or 0, "expired": expired or 0,
                           "done": done or 0,
                           "total": (leased or 0) + (expired or 0) + (done or 0)},
                "verified_matches": nmatch,
                "targets_digest": self.targets_digest}

    OPS = {
        "/v1/register": ("register", op_register, False),
        "/v1/targets": ("targets", op_targets, True),
        "/v1/block/request": ("block_request", op_block_request, True),
        "/v1/block/complete": ("block_complete", op_block_complete, True),
        "/v1/match": ("match", op_match, True),
        "/v1/stats": ("stats", op_stats, True),
    }

    def handle(self, path, body):
        entry = self.OPS.get(path)
        if not entry:
            return 404, {"error": "no such endpoint"}
        op_name, fn, need_active = entry

        try:
            env = json.loads(body)
        except Exception:
            return 400, {"error": "bad json"}

        with self.lock:
            sender = env.get("from")
            known = self.get_node(sender) if isinstance(sender, str) else None
            last_seq = known["last_seq"] if known else None
            try:
                nid, payload, ts, seq = P.open_envelope(
                    env, self.ed_hex, self.enc_key,
                    lambda h: known["x25519"] if known else None,
                    last_seq=last_seq)
            except P.ProtocolError as e:
                return 401, {"error": str(e)}

            if payload.get("op") != op_name:
                return 400, {"error": "op does not match endpoint"}

            if known:
                self.db.execute("UPDATE nodes SET last_seq=?, last_seen=? WHERE id=?",
                                (seq, time.time(), nid))
                self.db.commit()
            elif need_active:
                return 403, {"error": "unknown node; register first"}

            if need_active:
                st = self.get_node(nid)["status"]
                if st != "active":
                    return 403, {"error": "node status is %s" % st}

            try:
                result = fn(self, nid, payload)
            except Exception as e:
                sys.stderr.write("handler error: %r\n" % (e,))
                return 500, {"error": "internal error"}

            node = self.get_node(nid)
            if not node:
                return 500, {"error": "node vanished"}
            out_seq = self.next_out_seq(nid)
            reply = P.seal(dict(result, op=op_name, rid=payload.get("rid")),
                           self.sign_key, self.x_hex, nid, node["x25519"], out_seq)
            return 200, reply


def make_handler(coord):
    class H(BaseHTTPRequestHandler):
        server_version = "keyhunt-coord/1"

        def log_message(self, fmt, *a):
            sys.stderr.write("%s %s\n" % (self.address_string(), fmt % a))

        def _send(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            if self.path == "/healthz":
                self._send(200, {"ok": True, "service": "keyhunt-coord"})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            try:
                n = int(self.headers.get("Content-Length", 0))
            except ValueError:
                return self._send(400, {"error": "bad length"})
            if n <= 0 or n > MAX_BODY:
                return self._send(413, {"error": "body too large"})
            body = self.rfile.read(n)
            code, obj = coord.handle(self.path, body)
            self._send(code, obj)
    return H


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="coord.json")
    ap.add_argument("--key", default="server.key")
    ap.add_argument("--db", default="coord.db")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    a = ap.parse_args()

    with open(a.config) as f:
        cfg = json.load(f)
    with open(a.key) as f:
        secret = json.load(f)

    coord = Coordinator(cfg, a.db, secret, cfg["targets_file"])
    print("server ed25519 : %s" % coord.ed_hex)
    print("server x25519  : %s" % coord.x_hex)
    print("targets        : %d  digest %s" % (len(coord.targets), coord.targets_digest[:16]))
    space_desc = ("full 2^216 space" if not coord.space_prefix
                  else "%s + %d random nibbles" % (coord.space_prefix, coord.random_nibbles))
    print("block space    : %s, random prefixes, each block 2^%d keys"
          % (space_desc, 256 - 4 * PREFIX_HEX_LEN))
    print("lease          : %g s; expired blocks re-handed to the next node"
          % coord.lease_seconds)
    print("listening on   : %s:%d" % (a.host, a.port))
    ThreadingHTTPServer((a.host, a.port), make_handler(coord)).serve_forever()


if __name__ == "__main__":
    main()
