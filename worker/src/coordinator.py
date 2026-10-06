"""Coordination logic for the Cloudflare Python Worker, over Cloudflare D1.

This is the async port of the stdlib server's Coordinator class. It is written
against a tiny async DB interface (first/all/run/batch, see entry.py's D1Adapter
and test_coordinator.py's sqlite shim) so the same logic runs on D1 in a Worker
and is unit-testable off-Worker.

Differences forced by the Worker/D1 model, none of which change the wire
protocol:
  - No files: the server identity comes from a Worker secret, tunables from env
    vars, and the target list lives in a D1 table (seeded out of band).
  - No background threads: lease expiry is swept lazily on each block request
    and on each stats read, exactly where the stdlib server already swept it.
  - No process-wide lock: blocks are claimed with single atomic UPDATE ...
    WHERE ... RETURNING statements (D1 serialises writes), which is race-free
    across concurrent Worker invocations without any lock.
  - Matches are recorded in D1 and logged (pubkey only -- never the private key)
    rather than shelling out to a match hook.
"""

import hashlib
import json
import secrets
import time

import pyprotocol as P
import secp

PREFIX_HEX_LEN = 54          # 27 bytes = 216 bits
LEASE_SECONDS = 3600         # 1 hour
BLOCK_KEYS = 1 << (256 - 4 * PREFIX_HEX_LEN)   # keys in one block (2^40)
UNKNOWN_BITS = 256 - 4 * PREFIX_HEX_LEN

STATS_WINDOWS = (("last 15m", 900), ("last 1h", 3600), ("last 24h", 86400))
EVENT_RETENTION = 86400 + 3600


class ProtocolError(P.ProtocolError):
    pass


class Coordinator:
    def __init__(self, db, secret, cfg=None):
        """db: async D1-like adapter. secret: dict with ed25519/x25519 (+_secret).
        cfg: dict of tunables (space_prefix, lease_seconds, require_approval)."""
        self.db = db
        cfg = cfg or {}
        self.ed_seed, self.x_priv = P.load_secret(secret)
        self.ed_hex = secret["ed25519"]
        self.x_hex = secret["x25519"]

        self.space_prefix = str(cfg.get("space_prefix", "")).lower()
        if len(self.space_prefix) >= PREFIX_HEX_LEN:
            raise ValueError("space_prefix must be shorter than %d hex chars" % PREFIX_HEX_LEN)
        if self.space_prefix:
            int(self.space_prefix, 16)
        self.random_nibbles = PREFIX_HEX_LEN - len(self.space_prefix)
        self.lease_seconds = float(cfg.get("lease_seconds", LEASE_SECONDS))
        self.require_approval = bool(cfg.get("require_approval", False))

    # ------------------------------------------------------------- targets
    async def _targets_meta(self):
        """(digest, count), cached in the meta table so register/stats don't
        rescan the whole target list each request."""
        row = await self.db.first("SELECT v FROM meta WHERE k='targets_digest'")
        crow = await self.db.first("SELECT v FROM meta WHERE k='targets_count'")
        if row and crow:
            return row["v"], int(crow["v"])
        targets = await self._targets_list()
        digest = hashlib.sha256("\n".join(targets).encode()).hexdigest()
        await self.db.batch([
            ("INSERT OR REPLACE INTO meta(k,v) VALUES('targets_digest',?)", [digest]),
            ("INSERT OR REPLACE INTO meta(k,v) VALUES('targets_count',?)", [str(len(targets))]),
        ])
        return digest, len(targets)

    async def _targets_list(self):
        rows = await self.db.all("SELECT pub FROM targets ORDER BY ord")
        return [r["pub"] for r in rows]

    def random_prefix(self):
        rnd = secrets.randbits(4 * self.random_nibbles)
        return self.space_prefix + ("%0*x" % (self.random_nibbles, rnd))

    # ------------------------------------------------------------ event log
    async def _log_event(self, kind, nid, idx, keys=0, ts=None, seconds=None):
        await self.db.run(
            "INSERT INTO events(ts, kind, node_id, block_idx, keys, seconds) "
            "VALUES (?,?,?,?,?,?)",
            time.time() if ts is None else ts, kind, nid, idx, int(keys), seconds)

    async def _expire_leases(self, now):
        """Mark lapsed leases 'expired', logging each at the moment it lapsed."""
        rows = await self.db.all(
            "SELECT idx, node_id, lease_expires FROM blocks "
            "WHERE state='leased' AND lease_expires < ?", now)
        for r in rows:
            await self._log_event("expire", r["node_id"], r["idx"], ts=r["lease_expires"])
        if rows:
            await self.db.run(
                "UPDATE blocks SET state='expired' "
                "WHERE state='leased' AND lease_expires < ?", now)
        return len(rows)

    # ------------------------------------------------------------- node state
    async def get_node(self, nid):
        r = await self.db.first(
            "SELECT id,x25519,gpu,sw,status,last_seq,out_seq FROM nodes WHERE id=?", nid)
        return r

    async def next_out_seq(self, nid):
        r = await self.db.run(
            "UPDATE nodes SET out_seq=out_seq+1 WHERE id=? RETURNING out_seq", nid)
        return r["results"][0]["out_seq"]

    # ------------------------------------------------------------- operations
    async def op_register(self, nid, p):
        x = str(p.get("x25519", ""))
        gpu = str(p.get("gpu", "unknown"))[:200]
        sw = str(p.get("sw", "unknown"))[:100]
        try:
            if len(bytes.fromhex(x)) != 32:
                raise ValueError
        except ValueError:
            return {"ok": False, "error": "bad x25519 key"}

        now = time.time()
        existing = await self.get_node(nid)
        if existing:
            # The encryption key is pinned on first registration; letting it
            # rotate would let a stolen signing key redirect ciphertext.
            if existing["x25519"] != x:
                return {"ok": False, "error": "x25519 key does not match registration"}
            await self.db.run("UPDATE nodes SET gpu=?,sw=?,last_seen=? WHERE id=?",
                              gpu, sw, now, nid)
        else:
            status = "pending" if self.require_approval else "active"
            await self.db.run(
                "INSERT INTO nodes(id,x25519,gpu,sw,status,first_seen,last_seen) "
                "VALUES (?,?,?,?,?,?,?)", nid, x, gpu, sw, status, now, now)
        n = await self.get_node(nid)
        digest, count = await self._targets_meta()
        return {"ok": True, "status": n["status"],
                "targets_digest": digest, "targets_count": count,
                "prefix_hex_len": PREFIX_HEX_LEN, "unknown_bits": UNKNOWN_BITS}

    async def op_targets(self, nid, p):
        targets = await self._targets_list()
        digest, _ = await self._targets_meta()
        return {"ok": True, "digest": digest, "count": len(targets), "targets": targets}

    async def op_block_request(self, nid, p):
        now = time.time()
        exp = now + self.lease_seconds
        await self._expire_leases(now)

        # 1. Claim the oldest expired block atomically (single statement, so two
        #    concurrent requesters can never take the same one). Expired blocks
        #    take priority: an unfinished prefix must be covered by someone.
        r = await self.db.run(
            "UPDATE blocks SET state='leased', node_id=?, leased_at=?, lease_expires=?, "
            "attempts=attempts+1 "
            "WHERE idx=(SELECT idx FROM blocks WHERE state='expired' "
            "           ORDER BY lease_expires LIMIT 1) "
            "RETURNING idx, prefix, attempts", nid, now, exp)
        row = r["results"][0] if r["results"] else None
        if row:
            await self.db.run("UPDATE nodes SET blocks_requested=blocks_requested+1 WHERE id=?", nid)
            await self._log_event("request", nid, row["idx"], ts=now)
            return {"ok": True, "block_idx": row["idx"], "prefix": row["prefix"],
                    "reassigned": True, "from_list": False, "attempts": row["attempts"],
                    "unknown_bits": UNKNOWN_BITS, "lease_expires": exp,
                    "lease_seconds": self.lease_seconds}

        # 2. Otherwise the next preassigned prefix, in file order, if any remain.
        r = await self.db.run(
            "UPDATE blocks SET state='leased', node_id=?, leased_at=?, lease_expires=?, "
            "attempts=1 "
            "WHERE idx=(SELECT idx FROM blocks WHERE state='pending' ORDER BY idx LIMIT 1) "
            "RETURNING idx, prefix", nid, now, exp)
        row = r["results"][0] if r["results"] else None
        if row:
            await self.db.run("UPDATE nodes SET blocks_requested=blocks_requested+1 WHERE id=?", nid)
            await self._log_event("request", nid, row["idx"], ts=now)
            return {"ok": True, "block_idx": row["idx"], "prefix": row["prefix"],
                    "reassigned": False, "from_list": True, "attempts": 1,
                    "unknown_bits": UNKNOWN_BITS, "lease_expires": exp,
                    "lease_seconds": self.lease_seconds}

        # 3. Otherwise mint a brand-new block with a fresh random prefix.
        prefix = self.random_prefix()
        r = await self.db.run(
            "INSERT INTO blocks(prefix, state, node_id, leased_at, lease_expires, attempts) "
            "VALUES (?,'leased',?,?,?,1) RETURNING idx", prefix, nid, now, exp)
        idx = r["results"][0]["idx"]
        await self.db.run("UPDATE nodes SET blocks_requested=blocks_requested+1 WHERE id=?", nid)
        await self._log_event("request", nid, idx, ts=now)
        return {"ok": True, "block_idx": idx, "prefix": prefix,
                "reassigned": False, "from_list": False, "attempts": 1,
                "unknown_bits": UNKNOWN_BITS, "lease_expires": exp,
                "lease_seconds": self.lease_seconds}

    async def op_block_complete(self, nid, p):
        try:
            idx = int(p["block_idx"])
            secs = float(p["seconds"])
            keys = int(p.get("keys_checked", 0))
        except (KeyError, ValueError, TypeError):
            return {"ok": False, "error": "bad fields"}
        if not (0 <= secs < 30 * 86400) or keys < 0:
            return {"ok": False, "error": "implausible timing"}

        row = await self.db.first("SELECT state,node_id FROM blocks WHERE idx=?", idx)
        if not row:
            return {"ok": False, "error": "no such block"}
        if row["state"] == "done":
            return {"ok": True, "note": "already recorded"}
        # Only the current leaseholder may complete it: if A's lease expired and
        # the prefix was re-handed to B, A's late report is stale.
        if row["node_id"] != nid:
            return {"ok": False, "error": "block is not leased to you "
                    "(lease may have expired and been reassigned)"}

        now = time.time()
        await self.db.run(
            "UPDATE blocks SET state='done', completed_at=?, seconds=? WHERE idx=?",
            now, secs, idx)
        await self.db.run(
            "UPDATE nodes SET blocks_done=blocks_done+1, total_seconds=total_seconds+?, "
            "keys_checked=keys_checked+?, last_seen=? WHERE id=?", secs, keys, now, nid)
        await self._log_event("complete", nid, idx, keys=keys, seconds=secs)
        done = (await self.db.first(
            "SELECT COUNT(*) AS c FROM blocks WHERE state='done'"))["c"]
        total = (await self.db.first("SELECT COUNT(*) AS c FROM blocks"))["c"]
        return {"ok": True, "block_idx": idx, "blocks_done": done, "blocks_total": total}

    async def op_match(self, nid, p):
        # The private key arrives only as a sealed box, encrypted to this
        # server's X25519 key; we open it here then re-verify independently.
        sealed = str(p.get("privkey_sealed", "")).strip()
        pub = str(p.get("pubkey", "")).lower().strip()
        try:
            idx = int(p.get("block_idx", -1))
        except (ValueError, TypeError):
            idx = -1

        if not sealed:
            return {"ok": False, "error": "missing privkey_sealed (sealed private key)"}
        if len(pub) != 66 or pub[:2] not in ("02", "03"):
            return {"ok": False, "error": "expect a 66-hex compressed public key"}
        try:
            priv_bytes = P.open_sealed(sealed, self.x_priv, self.x_hex)
        except P.ProtocolError as e:
            return {"ok": False, "error": "cannot open sealed private key: %s" % e}
        if len(priv_bytes) != 32:
            return {"ok": False, "error": "sealed payload is not a 32-byte private key"}
        priv = priv_bytes.hex()
        try:
            k = int(priv, 16)
            int(pub, 16)
        except ValueError:
            return {"ok": False, "error": "not hex"}
        if not (0 < k < secp.N):
            return {"ok": False, "error": "private key out of range"}

        derived = secp.compressed(k)
        verified = (derived == pub)
        in_targets = bool(await self.db.first("SELECT 1 AS x FROM targets WHERE pub=?", pub))
        note = ""
        if not verified:
            note = "private key does not derive the reported public key"
        elif not in_targets:
            note = "verified keypair but the public key is not in the target list"

        r = await self.db.run(
            "INSERT OR IGNORE INTO matches(node_id,block_idx,privkey,pubkey,reported_at,"
            "verified,in_targets,note) VALUES (?,?,?,?,?,?,?,?)",
            nid, idx, priv, pub, time.time(), int(verified), int(in_targets), note)
        dup = (r["changes"] == 0)

        if verified and in_targets and not dup:
            # Log the pubkey only -- never the recovered private key -- so it
            # does not land in plaintext in the Worker's logs.
            print("*** VERIFIED MATCH from node %s for pubkey %s ***" % (nid[:16], pub))
        return {"ok": True, "verified": verified, "in_targets": in_targets,
                "duplicate": dup, "note": note}

    # --------------------------------------------------------------- stats
    async def _node_stats_rows(self):
        nodes = []
        rows = await self.db.all(
            "SELECT id,gpu,sw,status,first_seen,last_seen,blocks_requested,"
            "blocks_done,total_seconds,keys_checked FROM nodes ORDER BY blocks_done DESC")
        for d in rows:
            d = dict(d)
            d["blocks_pending"] = (await self.db.first(
                "SELECT COUNT(*) AS c FROM blocks WHERE node_id=? AND state='leased'",
                d["id"]))["c"]
            d["blocks_expired"] = (await self.db.first(
                "SELECT COUNT(*) AS c FROM blocks WHERE node_id=? AND state='expired'",
                d["id"]))["c"]
            d["avg_seconds_per_block"] = (d["total_seconds"] / d["blocks_done"]
                                          if d["blocks_done"] else None)
            d["keys_per_sec"] = (d["keys_checked"] / d["total_seconds"]
                                 if d["total_seconds"] > 0 else None)
            nodes.append(d)
        return nodes

    async def _block_counts(self):
        r = await self.db.first(
            "SELECT COALESCE(SUM(state='leased'),0) AS leased, "
            "COALESCE(SUM(state='expired'),0) AS expired, "
            "COALESCE(SUM(state='done'),0) AS done, "
            "COALESCE(SUM(state='pending'),0) AS pending FROM blocks")
        return int(r["leased"]), int(r["expired"]), int(r["done"]), int(r["pending"])

    async def op_stats(self, nid, p):
        await self._expire_leases(time.time())
        nodes = await self._node_stats_rows()
        leased, expired, done, pending = await self._block_counts()
        nmatch = (await self.db.first(
            "SELECT COUNT(*) AS c FROM matches WHERE verified=1 AND in_targets=1"))["c"]
        digest, _ = await self._targets_meta()
        return {"ok": True, "nodes": nodes,
                "blocks": {"leased": leased, "expired": expired, "done": done,
                           "pending": pending,
                           "total": leased + expired + done + pending},
                "verified_matches": nmatch, "targets_digest": digest}

    # --------------------------------------------------------------- dashboard
    async def render_dashboard(self):
        """Plain, unauthenticated HTML dashboard (node ids are already public,
        being Ed25519 public keys). Returns an HTML string."""
        import html as _html

        await self._expire_leases(time.time())
        nodes = await self._node_stats_rows()
        leased, expired, done, pending = await self._block_counts()
        nmatch = (await self.db.first(
            "SELECT COUNT(*) AS c FROM matches WHERE verified=1 AND in_targets=1"))["c"]
        digest, count = await self._targets_meta()

        def esc(s):
            return _html.escape(str(s), quote=True)

        def fmt_secs(s):
            if s is None:
                return "-"
            s = float(s)
            d, r = divmod(s, 86400)
            h, r = divmod(r, 3600)
            m, sec = divmod(r, 60)
            if d:
                return "%.0fd %.0fh %.0fm" % (d, h, m)
            if h:
                return "%.0fh %.0fm %.0fs" % (h, m, sec)
            if m:
                return "%.0fm %.0fs" % (m, sec)
            return "%.0fs" % sec

        def fmt_rate(kps):
            if kps is None:
                return "-"
            units = ("key/s", "Kkey/s", "Mkey/s", "Gkey/s", "Tkey/s", "Pkey/s")
            i = 0
            while kps >= 1000.0 and i < len(units) - 1:
                kps /= 1000.0
                i += 1
            return "%.2f %s" % (kps, units[i])

        rows = []
        for d in nodes:
            share = (d["blocks_done"] / done * 100) if done else 0.0
            rows.append(
                "<tr>"
                "<td class='mono'>%s...%s</td><td>%s</td><td>%s</td>"
                "<td>%d</td><td>%d</td><td>%d</td><td>%s</td><td>%s</td><td>%.2f%%</td>"
                "</tr>" % (
                    esc(d["id"][:8]), esc(d["id"][-4:]), esc(d["gpu"] or "unknown"),
                    esc(d["status"]), d["blocks_pending"], d["blocks_expired"],
                    d["blocks_done"], esc(fmt_secs(d["avg_seconds_per_block"])),
                    esc(fmt_rate(d["keys_per_sec"])), share))
        table_rows = "\n".join(rows) or (
            "<tr><td colspan='9' style='text-align:center;color:#888'>no nodes yet</td></tr>")
        total = leased + expired + done + pending

        # The head (with its literal % in the CSS) is static; only the small
        # summary and the table body carry formatted values.
        head = (
            "<!doctype html><html><head><meta charset='utf-8'>"
            "<meta http-equiv='refresh' content='30'>"
            "<title>keyhunt-coord stats</title><style>"
            "body{font:13px/1.4 -apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;"
            "color:#1a1a1a;background:#fafafa}h1{font-size:1.3rem;margin-bottom:.25rem}"
            ".summary{color:#555;margin-bottom:1.25rem}table{border-collapse:collapse;"
            "width:100%;background:#fff}th,td{padding:.4rem .7rem;border-bottom:1px solid "
            "#e0e0e0;text-align:right}th:first-child,td:first-child,th:nth-child(2),"
            "td:nth-child(2),th:nth-child(3),td:nth-child(3){text-align:left}"
            "th{background:#f0f0f0;font-weight:600}.mono{font-family:ui-monospace,Menlo,"
            "Consolas,monospace}tr:hover{background:#f6f8ff}</style></head><body>"
            "<h1>keyhunt-coord-server</h1>")
        summary = (
            "<div class='summary'>"
            "blocks: {done} done, {leased} leased, {expired} expired, {pending} pending, "
            "{total} total &middot; verified matches: {nmatch} &middot; "
            "targets: {count} (digest {digest})</div>").format(
                done=done, leased=leased, expired=expired, pending=pending,
                total=total, nmatch=nmatch, count=count, digest=esc(digest[:16]))
        table = (
            "<table><thead><tr><th>Node</th><th>GPU</th><th>Status</th><th>Leased</th>"
            "<th>Expired</th><th>Completed</th><th>Avg Block</th><th>Rate</th>"
            "<th>Share</th></tr></thead><tbody>" + table_rows +
            "</tbody></table></body></html>")
        return head + summary + table

    # --------------------------------------------------------------- routing
    OPS = {
        "/v1/register": ("register", "op_register", False),
        "/v1/targets": ("targets", "op_targets", True),
        "/v1/block/request": ("block_request", "op_block_request", True),
        "/v1/block/complete": ("block_complete", "op_block_complete", True),
        "/v1/match": ("match", "op_match", True),
        "/v1/stats": ("stats", "op_stats", True),
    }

    async def handle(self, path, body):
        entry = self.OPS.get(path)
        if not entry:
            return 404, {"error": "no such endpoint"}
        op_name, fn_name, need_active = entry

        try:
            env = json.loads(body)
        except Exception:
            return 400, {"error": "bad json"}

        sender = env.get("from")
        known = await self.get_node(sender) if isinstance(sender, str) else None
        last_seq = known["last_seq"] if known else None
        try:
            nid, payload, ts, seq = P.open_envelope(
                env, self.ed_hex, self.x_priv,
                (lambda h: known["x25519"] if known else None), last_seq=last_seq)
        except P.ProtocolError as e:
            return 401, {"error": str(e)}

        if payload.get("op") != op_name:
            return 400, {"error": "op does not match endpoint"}

        if known:
            await self.db.run("UPDATE nodes SET last_seq=?, last_seen=? WHERE id=?",
                              seq, time.time(), nid)
        elif need_active:
            return 403, {"error": "unknown node; register first"}

        if need_active:
            st = (await self.get_node(nid))["status"]
            if st != "active":
                return 403, {"error": "node status is %s" % st}

        try:
            result = await getattr(self, fn_name)(nid, payload)
        except Exception as e:
            print("handler error: %r" % (e,))
            return 500, {"error": "internal error"}

        node = await self.get_node(nid)
        if not node:
            return 500, {"error": "node vanished"}
        out_seq = await self.next_out_seq(nid)
        reply = P.seal(dict(result, op=op_name, rid=payload.get("rid")),
                       self.ed_seed, self.x_hex, nid, node["x25519"], out_seq)
        return 200, reply
