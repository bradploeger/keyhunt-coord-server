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

While running, the server also redraws a live stats table on the console every
--stats-interval seconds (default 5; 0 turns it off): nodes seen, blocks
requested / expired / completed, and effective keys/second over the last
10 minutes, hour and 24 hours.
"""

import argparse
import hashlib
import html
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
LEASE_SECONDS = 3600         # 1 hour
MAX_BODY = 8 * 1024 * 1024
BLOCK_KEYS = 1 << (256 - 4 * PREFIX_HEX_LEN)   # keys in one block (2^40)

# Rolling windows shown on the live console display: (label, seconds).
STATS_WINDOWS = (("last 10m", 600), ("last 1h", 3600), ("last 24h", 86400))
EVENT_RETENTION = 86400 + 3600   # keep a little more than the widest window

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
  blocks_requested INTEGER NOT NULL DEFAULT 0,
  blocks_done   INTEGER NOT NULL DEFAULT 0,
  total_seconds REAL    NOT NULL DEFAULT 0,
  keys_checked  INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS blocks (
  idx           INTEGER PRIMARY KEY AUTOINCREMENT,
  prefix        TEXT NOT NULL,        -- the 54-hex (216-bit) prefix for this block
  state         TEXT NOT NULL DEFAULT 'leased',  -- pending | leased | expired | done
  node_id       TEXT,
  leased_at     REAL,
  lease_expires REAL,
  completed_at  REAL,
  seconds       REAL,
  attempts      INTEGER NOT NULL DEFAULT 0
);
-- Expired blocks are re-handed oldest-first, so index by (state, lease_expires).
CREATE INDEX IF NOT EXISTS blocks_state ON blocks(state, lease_expires);
-- Append-only log of block lifecycle events for the rolling console stats.
-- kind is 'request' | 'expire' | 'complete'; keys is set on 'complete'.
-- Pruned to the last ~25 hours.
CREATE TABLE IF NOT EXISTS events (
  ts            REAL NOT NULL,
  kind          TEXT NOT NULL,
  node_id       TEXT,
  block_idx     INTEGER,
  keys          INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS events_kind_ts ON events(kind, ts);
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
class QuietHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Overriding this method prevents logs from printing to the console
        pass

class Coordinator:
    def __init__(self, cfg, db_path, secret, targets_path):
        self.cfg = cfg
        self.lock = threading.Lock()
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        had_events = self.db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='events'"
        ).fetchone() is not None
        self.db.executescript(SCHEMA)
        self.db.commit()
        self.started_at = time.time()
        if not had_events:
            self._backfill_events()
        # Migration for databases created before blocks_requested existed.
        try:
            self.db.execute(
                "ALTER TABLE nodes ADD COLUMN blocks_requested INTEGER NOT NULL DEFAULT 0")
            self.db.commit()
        except sqlite3.OperationalError:
            pass  # column already present

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

        # Optional explicit prefix list: prefixes to hand out (in file order)
        # before falling back to random assignment.
        self.pending_seed = self._seed_pending(cfg.get("prefix_list_file"))

    def random_prefix(self):
        """A fresh random 54-hex (216-bit) prefix, respecting any space_prefix
        constraint. Pure random, drawn from os-backed entropy; no dedup."""
        rnd = self.rng.getrandbits(4 * self.random_nibbles)
        return self.space_prefix + ("%0*x" % (self.random_nibbles, rnd))

    def _seed_pending(self, path):
        """Load an optional text file of 216-bit prefixes and seed each as a
        'pending' block, in file order, to be handed out before any random
        prefix. One prefix per line; blank lines and '#' comments ignored; each
        must be exactly 54 hex chars (a single 2^40-key block) and, if a
        space_prefix is configured, must start with it.

        Idempotent across restarts: a prefix already present in the blocks table
        (in any state) is skipped, sor re-running the server -- or adding more
        lines to the file and restarting -- never double-counts work.
        Returns {added, skipped_bad, skipped_dup}."""
        stats = {"added": 0, "skipped_bad": 0, "skipped_dup": 0}
        if not path:
            return stats
        try:
            with open(path) as f:
                lines = f.readlines()
        except OSError as e:
            raise SystemExit("cannot open prefix_list_file %s: %s" % (path, e))

        with self.lock:
            existing = {r[0] for r in self.db.execute("SELECT prefix FROM blocks")}
            seen = set()
            for ln in lines:
                s = ln.strip().lower()
                if not s or s.startswith("#"):
                    continue
                if len(s) != PREFIX_HEX_LEN:
                    stats["skipped_bad"] += 1
                    continue
                try:
                    int(s, 16)
                except ValueError:
                    stats["skipped_bad"] += 1
                    continue
                if self.space_prefix and not s.startswith(self.space_prefix):
                    stats["skipped_bad"] += 1
                    continue
                if s in existing or s in seen:
                    stats["skipped_dup"] += 1
                    continue
                seen.add(s)
                self.db.execute(
                    "INSERT INTO blocks(prefix, state, node_id, leased_at, "
                    "lease_expires, attempts) VALUES (?, 'pending', NULL, NULL, "
                    "NULL, 0)", (s,))
                stats["added"] += 1
            if stats["added"]:
                self.db.commit()
        return stats

    # ------------------------------------------------------------ event log
    def _log_event(self, kind, nid, idx, keys=0, ts=None):
        self.db.execute(
            "INSERT INTO events(ts, kind, node_id, block_idx, keys) VALUES (?,?,?,?,?)",
            (time.time() if ts is None else ts, kind, nid, idx, int(keys)))

    def _backfill_events(self):
        """First start on a database that predates the events table: seed the
        last 24h of history from the blocks table so the rolling stats aren't
        empty. Approximate -- the blocks table only keeps each block's latest
        lease, and per-block key counts weren't stored, so completions are
        counted at the nominal 2^40 keys per block."""
        since = time.time() - EVENT_RETENTION
        self.db.execute(
            "INSERT INTO events(ts, kind, node_id, block_idx, keys) "
            "SELECT leased_at, 'request', node_id, idx, 0 FROM blocks "
            "WHERE leased_at IS NOT NULL AND leased_at >= ?", (since,))
        self.db.execute(
            "INSERT INTO events(ts, kind, node_id, block_idx, keys) "
            "SELECT lease_expires, 'expire', node_id, idx, 0 FROM blocks "
            "WHERE state='expired' AND lease_expires >= ?", (since,))
        self.db.execute(
            "INSERT INTO events(ts, kind, node_id, block_idx, keys) "
            "SELECT completed_at, 'complete', node_id, idx, ? FROM blocks "
            "WHERE state='done' AND completed_at >= ?", (BLOCK_KEYS, since))
        self.db.commit()

    def _expire_leases(self, now):
        """Mark every lease that ran out without a completion as 'expired',
        logging each expiry at the moment the lease actually lapsed. Caller
        holds self.lock and commits."""
        rows = self.db.execute(
            "SELECT idx, node_id, lease_expires FROM blocks "
            "WHERE state='leased' AND lease_expires < ?", (now,)).fetchall()
        for idx, owner, exp in rows:
            self._log_event("expire", owner, idx, ts=exp)
        if rows:
            self.db.execute(
                "UPDATE blocks SET state='expired' "
                "WHERE state='leased' AND lease_expires < ?", (now,))
        return len(rows)

    def window_stats(self, now=None):
        """Rolling stats for each of STATS_WINDOWS. Also sweeps expired leases
        (so expiries show up when they happen, not when the next node asks for
        work) and prunes old events. Takes self.lock.

        Effective rate is keys from blocks completed in the window divided by
        the window length -- or by the available history, if the server has
        less than a full window of it (flagged by 'partial')."""
        now = time.time() if now is None else now
        with self.lock:
            self._expire_leases(now)
            self.db.execute("DELETE FROM events WHERE ts < ?",
                            (now - EVENT_RETENTION,))
            self.db.commit()
            first = self.db.execute("SELECT MIN(ts) FROM events").fetchone()[0]
            origin = min(self.started_at, first if first is not None else now)
            out = []
            for label, secs in STATS_WINDOWS:
                cut = now - secs
                nodes = self.db.execute(
                    "SELECT COUNT(*) FROM nodes WHERE last_seen >= ?",
                    (cut,)).fetchone()[0]
                req, exp, done, keys = self.db.execute(
                    "SELECT COALESCE(SUM(kind='request'),0), "
                    "COALESCE(SUM(kind='expire'),0), "
                    "COALESCE(SUM(kind='complete'),0), "
                    "COALESCE(SUM(CASE WHEN kind='complete' THEN keys END),0) "
                    "FROM events WHERE ts >= ? AND ts <= ?", (cut, now)).fetchone()
                span = max(1.0, min(float(secs), now - origin))
                out.append({"label": label, "seconds": secs, "nodes": nodes,
                            "requested": req, "expired": exp, "completed": done,
                            "keys": keys, "span": span,
                            "partial": span < secs - 1,
                            "keys_per_sec": keys / span})
        return out

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
        self._expire_leases(now)

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
            self.db.execute(
                "UPDATE nodes SET blocks_requested=blocks_requested+1 WHERE id=?", (nid,))
            self._log_event("request", nid, idx, ts=now)
            self.db.commit()
            return {"ok": True, "block_idx": idx, "prefix": prefix,
                    "reassigned": True, "from_list": False,
                    "attempts": self._attempts(idx),
                    "unknown_bits": 256 - 4 * PREFIX_HEX_LEN,
                    "lease_expires": exp, "lease_seconds": self.lease_seconds}

        # 2. Otherwise hand out the next preassigned prefix, in file order, if
        #    the operator supplied a prefix list and any remain unassigned.
        row = self.db.execute(
            "SELECT idx, prefix FROM blocks WHERE state='pending' "
            "ORDER BY idx LIMIT 1").fetchone()
        if row:
            idx, prefix = row
            self.db.execute(
                "UPDATE blocks SET state='leased', node_id=?, leased_at=?, "
                "lease_expires=?, attempts=1 WHERE idx=?", (nid, now, exp, idx))
            self.db.execute(
                "UPDATE nodes SET blocks_requested=blocks_requested+1 WHERE id=?", (nid,))
            self._log_event("request", nid, idx, ts=now)
            self.db.commit()
            return {"ok": True, "block_idx": idx, "prefix": prefix,
                    "reassigned": False, "from_list": True, "attempts": 1,
                    "unknown_bits": 256 - 4 * PREFIX_HEX_LEN,
                    "lease_expires": exp, "lease_seconds": self.lease_seconds}

        # 3. Otherwise mint a brand-new block with a fresh random prefix.
        prefix = self.random_prefix()
        cur = self.db.execute(
            "INSERT INTO blocks(prefix, state, node_id, leased_at, lease_expires, "
            "attempts) VALUES (?,'leased',?,?,?,1) RETURNING idx",
            (prefix, nid, now, exp))
        idx = cur.fetchone()[0]
        self.db.execute(
            "UPDATE nodes SET blocks_requested=blocks_requested+1 WHERE id=?", (nid,))
        self._log_event("request", nid, idx, ts=now)
        self.db.commit()
        return {"ok": True, "block_idx": idx, "prefix": prefix,
                "reassigned": False, "from_list": False, "attempts": 1,
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
        self._log_event("complete", nid, idx, keys=keys)
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

    def _node_stats_rows(self):
        """Per-node stats, shared by the authenticated /v1/stats op and the
        plain HTML dashboard. blocks_pending is the count of blocks currently
        leased to that node and not yet completed (i.e. in flight)."""
        nodes = []
        for r in self.db.execute(
                "SELECT id,gpu,sw,status,first_seen,last_seen,blocks_requested,"
                "blocks_done,total_seconds,keys_checked FROM nodes "
                "ORDER BY blocks_done DESC"):
            d = dict(zip(["id", "gpu", "sw", "status", "first_seen", "last_seen",
                          "blocks_requested", "blocks_done", "total_seconds",
                          "keys_checked"], r))
            d["blocks_pending"] = self.db.execute(
                "SELECT COUNT(*) FROM blocks WHERE node_id=? AND state='leased'",
                (d["id"],)).fetchone()[0]
            d["blocks_expired"] = self.db.execute(
                "SELECT COUNT(*) FROM blocks WHERE node_id=? AND state='expired'",
                (d["id"],)).fetchone()[0]
            d["avg_seconds_per_block"] = (d["total_seconds"] / d["blocks_done"]
                                          if d["blocks_done"] else None)
            d["keys_per_sec"] = (d["keys_checked"] / d["total_seconds"]
                                 if d["total_seconds"] > 0 else None)
            nodes.append(d)
        return nodes

    def op_stats(self, nid, p):
        nodes = self._node_stats_rows()
        leased, expired, done, pending = (self.db.execute(
            "SELECT SUM(state='leased'), SUM(state='expired'), SUM(state='done'), "
            "SUM(state='pending') FROM blocks").fetchone())
        nmatch = self.db.execute(
            "SELECT COUNT(*) FROM matches WHERE verified=1 AND in_targets=1").fetchone()[0]
        return {"ok": True, "nodes": nodes,
                "blocks": {"leased": leased or 0, "expired": expired or 0,
                           "done": done or 0, "pending": pending or 0,
                           "total": (leased or 0) + (expired or 0) + (done or 0)
                                    + (pending or 0)},
                "verified_matches": nmatch,
                "targets_digest": self.targets_digest}

    def render_stats_html(self):
        """A plain, unauthenticated GET dashboard. Node ids are already public
        (a node id *is* its Ed25519 public key), so serving this without the
        sealed-envelope protocol leaks nothing a node itself couldn't publish;
        it exists so a human can check progress from a browser."""
        nodes = self._node_stats_rows()
        leased, expired, done, pending = (self.db.execute(
            "SELECT SUM(state='leased'), SUM(state='expired'), SUM(state='done'), "
            "SUM(state='pending') FROM blocks").fetchone())
        nmatch = self.db.execute(
            "SELECT COUNT(*) FROM matches WHERE verified=1 AND in_targets=1").fetchone()[0]

        def esc(s):
            return html.escape(str(s), quote=True)

        def sec_parse(s):
            s = float(s)
            dys, rem = divmod(s, 86400)
            hrs, rem = divmod(rem, 3600)
            min, sec = divmod(rem, 60)
            return dys, hrs, min, sec

        def fmt_secs(s):
            if s is None:
                return "-"
            dys, hrs, min, sec = sec_parse(s)

            if dys > 0:
                return f"{dys:.0f}d {hrs:.0f}h {min:.0f}m {sec:.0f}s"
            elif hrs > 0:
                return f"{hrs:.0f}h {min:.0f}m {sec:.0f}s"
            elif min > 0:
                return f"{min:.0f}m {sec:.0f}s"
            else:
                return f"{sec:.0f}s"

        rows = []
        for d in nodes:
            rateUnits = {0: 'key/s', 1: 'Kkey/s', 2: 'Mkey/s', 3: 'Gkey/s', 4: 'Tkey/s', 5: 'Pkey/s'}
            rateScale = 0
            while d['keys_per_sec'] >= 1000.0:
               rateScale += 1
               d['keys_per_sec'] /= 1000.0
            rate = ("%.3f %s" % (d["keys_per_sec"], rateUnits[rateScale]) if d["keys_per_sec"] is not None else "-")
            keyScale = 0
            while d['keys_checked'] >= 1000.0:
                keyScale += 1
                d['keys_checked'] /= 1000.0
            keyUnits = { 0: "",
                         1: "Thousand",
                         2: "Million",
                         3: "Billion",
                         4: "Trillion",
                         5: "Quadrillion",
                         6: "Quintillion",
                         7: "Sextillion",
                         8: "Septillion",
                         9: "Octillion",
                         10: "Non-octillion",
                         11: "Decillion",
                         12: "Undecillion",
                         13: "Duodecillion",
                         14: "Tredecillion",
                         15: "Quattuordecillion",
                         16: "Quindecillion",
                         17: "Sexdecillion",
                         18: "Septendecillion",
                         19: "Octodecillion",
                         20: "Novemdecillion"}
            ttlKeys = ("%.3f %s (%d zeros)" % (d["keys_checked"], keyUnits[keyScale], keyScale * 3) if d["keys_checked"] is not None else "-")
            if d["blocks_requested"] < d["blocks_done"] + d["blocks_pending"] + d["blocks_expired"]:
                d["blocks_requested"] = d["blocks_done"] + d["blocks_pending"] + d["blocks_expired"]
            nodePct = d["blocks_done"] / (done or 1) * 100
            ExpireRate = d["blocks_expired"]/(d["blocks_requested"] or 1) * 100
            PendingRate = d["blocks_pending"]/(d["blocks_requested"] or 1) * 100
            CompleteRate = d["blocks_done"] / (d["blocks_requested"] or 1) * 100
            rows.append(
                "<tr>"
                f"<td class='mono'>{esc(d["id"][:8])}...{esc(d["id"][-4:])}</td>"
                f"<td>{esc(d["gpu"] or "unknown")}</td>"
                f"<td>{d["blocks_pending"]:.0f} ({PendingRate:0.1f}%)</td>"
                f"<td>{d["blocks_expired"]:.0f} ({ExpireRate:0.1f}%)</td>"
                f"<td>{d["blocks_done"]:.0f} ({CompleteRate:0.1f}%</td>"
                f"<td>{esc(fmt_secs(d["avg_seconds_per_block"]))}</td>"
                f"<td>{esc(rate)}</td>"
                f"<td>{esc(fmt_secs(d["total_seconds"]))}</td>"
                f"<td><div class='progress-container'><div class='progress-bar' style='width: {nodePct}%;'>"
                f"<span class='progress-text'>{nodePct:0.3f}%</span></div></div></td>"
                "</tr>")
        blocks_total = (leased or 0) + (expired or 0) + (done or 0) + (pending or 0)
        table_rows = "\n".join(rows) if rows else "<tr><td colspan='10' style='text-align:center;color:#888'>no nodes yet</td></tr>"
        page = """<!doctype html>
                <html>
                <head>
                <meta charset="utf-8">
                <meta http-equiv="refresh" content="30">
                <title>keyhunt-coord stats</title>
                <style>
                  body { font: 12px/1.4 -apple-system, Segoe UI, Roboto, sans-serif;
                         margin: 2rem; color: #1a1a1a; background: #fafafa; }
                  h1 { font-size: 1.3rem; margin-bottom: 0.25rem; }
                  .summary { color: #555; margin-bottom: 1.5rem; }
                  table { border-collapse: collapse; width: 100%; background: #fff; }
                  th, td { padding: 0.4rem 0.7rem; border-bottom: 1px solid #e0e0e0;
                           text-align: right; vertical-align:middle; }
                  th:nth-child(1), td:nth-child(1), th:nth-child(2), td:nth-child(2) {
                           text-align: left; }
                  th { background: #f0f0f0; font-weight: 600; }
                  .mono { font-family: ui-monospace, Menlo, Consolas, monospace; }
                  tr:hover { background: #f6f8ff; }
                  /* The outer track of the progress bar */
                  .progress-container {
                      width: 100%; background-color: #e0e0e0; border-radius: 4px; overflow: hidden; height: 16px; * Thickness of the bar */
                      position: relative;
                    }
                    
                    /* The filling inner percentage bar */
                    .progress-bar {
                      height: 100%;
                      background-color: #f7931a; /* Primary bar color (Bitcoin Orange) */
                      background-image: linear-gradient(to right, #f7931a, #ffffff); /* Optional gradient */
                      display: flex;
                      align-items: center;
                      justify-content: center;   /* Centers text inside the filled portion */
                      transition: width 0.4s ease;/* Smooth transition if data updates dynamically */
                    }    
                    /* Text style inside the bar */
                    .progress-text { color: #000000; font-size: 8px; font-weight: bold;
                    }
                </style>
                </head>
                <body>
                <h1>keyhunt-coord-server</h1>
                <div class="summary">"""
        page += f"blocks: {done or 0:.0f} done, {leased or 0:.0f} leased, {expired or 0:.0f} expired, {pending or 0:.0f} pending, {blocks_total:.0f} total &middot;"
        page += f"verified matches: {nmatch} &middot; targets: {len(self.targets):0d} (digest {esc(self.targets_digest[:16])})</div>"
        page += f"<table><thead><tr><th>Node</th><th>GPU</th><th>Pending</th><th>Expired</th>"
        page += f"<th>Completed</th><th>Avg Block Time</th><th>Avg Rate</th><th>Total Time</th><th>Share of Work</th>"
        page += f"</tr></thead><tbody>{table_rows}</tbody></table></body></html>"

        return page.encode()

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


# ---------------------------------------------------------------- live console
def _enable_ansi(stream):
    """True if the stream is a terminal that understands ANSI cursor codes.
    On Windows this switches on virtual-terminal processing for the console."""
    try:
        if not stream.isatty():
            return False
    except Exception:
        return False
    if os.name != "nt":
        return True
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        h = k32.GetStdHandle(-11)                     # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not k32.GetConsoleMode(h, ctypes.byref(mode)):
            return False
        return bool(k32.SetConsoleMode(h, mode.value | 0x0004))  # VT processing
    except Exception:
        return False


class LiveConsole:
    """Redraws the stats table in place. stdout/stderr are wrapped so that any
    other output (errors, MATCH banners, request logs) marks the screen dirty:
    the next redraw then starts a fresh table below it instead of overwriting,
    so nothing that was logged is ever erased."""

    class _Tracked:
        def __init__(self, console, stream):
            self._c, self._s = console, stream

        def write(self, s):
            with self._c.lock:
                if s:
                    self._c.dirty = True
                return self._s.write(s)

        def flush(self):
            return self._s.flush()

        def __getattr__(self, name):
            return getattr(self._s, name)

    def __init__(self):
        self.lock = threading.RLock()
        self.out, self.err = sys.stdout, sys.stderr
        self.ansi = _enable_ansi(self.out)
        self.dirty = True
        self.lines = 0
        sys.stdout = self._Tracked(self, self.out)
        sys.stderr = self._Tracked(self, self.err)

    def draw(self, lines):
        with self.lock:
            self.err.flush()
            if self.ansi and not self.dirty and self.lines:
                # cursor to start of the previous table, clear to end of screen
                self.out.write("\x1b[%dF\x1b[J" % self.lines)
            else:
                self.out.write("\n")          # fresh table below other output
            self.out.write("\n".join(lines) + "\n")
            self.out.flush()
            self.lines = len(lines)
            self.dirty = False


def fmt_rate(kps):
    units = ("key/s", "Kkey/s", "Mkey/s", "Gkey/s", "Tkey/s", "Pkey/s", "Ekey/s")
    i = 0
    while kps >= 1000.0 and i < len(units) - 1:
        kps /= 1000.0
        i += 1
    return "%.2f %s" % (kps, units[i])


def fmt_span(s):
    s = int(s)
    if s >= 3600:
        return "%dh %02dm" % (s // 3600, s % 3600 // 60)
    if s >= 60:
        return "%dm %02ds" % (s // 60, s % 60)
    return "%ds" % s


def render_console_stats(stats, interval, now=None):
    now = time.time() if now is None else now
    lw, cw = 18, 15
    head = "keyhunt-coord live stats  %s  (every %gs)" % (
        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)), interval)
    lines = [head, "-" * (lw + cw * len(stats))]
    lines.append("".ljust(lw) + "".join((w["label"] + " ").rjust(cw) for w in stats))
    for label, key in (("nodes seen", "nodes"), ("blocks requested", "requested"),
                       ("blocks expired", "expired"), ("blocks completed", "completed")):
        lines.append(label.ljust(lw) + "".join(
            ("{:,}".format(w[key]) + " ").rjust(cw) for w in stats))
    lines.append("effective rate".ljust(lw) + "".join(
        (fmt_rate(w["keys_per_sec"]) + ("*" if w["partial"] else " ")).rjust(cw)
        for w in stats))
    partial = [w for w in stats if w["partial"]]
    if partial:
        lines.append("* averaged over the %s of history available so far"
                     % fmt_span(partial[0]["span"]))
    return lines


def run_live_stats(coord, interval):
    console = LiveConsole()

    def loop():
        while True:
            try:
                console.draw(render_console_stats(coord.window_stats(), interval))
            except Exception as e:
                sys.stderr.write("stats display error: %r\n" % (e,))
            time.sleep(interval)
    threading.Thread(target=loop, name="live-stats", daemon=True).start()


def make_handler(coord):
    class H(BaseHTTPRequestHandler):
        server_version = "keyhunt-coord/1"

        def log_message(self, fmt, *a):
            if a[1] != '200' and "/favicon.ico" not in a[0]:
                sys.stderr.write("\"%s\" %s\n" % (self.address_string(), fmt % a))
            else:
                pass

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
            elif self.path in ("/", "/stats.html"):
                body = coord.render_stats_html()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
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
    ap.add_argument("--stats-interval", type=float, default=5.0,
                    help="seconds between live console stats redraws (0 = off)")
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
    if cfg.get("prefix_list_file"):
        s = coord.pending_seed
        waiting = coord.db.execute(
            "SELECT COUNT(*) FROM blocks WHERE state='pending'").fetchone()[0]
        print("prefix list    : %s  (+%d new, %d bad, %d dup this start; %d awaiting a node)"
              % (cfg["prefix_list_file"], s["added"], s["skipped_bad"],
                 s["skipped_dup"], waiting))
        print("                 these are handed out in file order before any random prefix")
    print("listening on   : %s:%d" % (a.host, a.port))
    if a.stats_interval > 0:
        run_live_stats(coord, a.stats_interval)
    ThreadingHTTPServer((a.host, a.port), make_handler(coord)).serve_forever()


if __name__ == "__main__":
    main()
