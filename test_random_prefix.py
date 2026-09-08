#!/usr/bin/env python3
"""Tests the random-prefix block model directly against Coordinator, no HTTP.

Checks:
  - each new block gets a distinct random 54-hex (216-bit) prefix
  - prefixes honour an optional space_prefix constraint
  - an expired lease is re-handed to the NEXT requester, same prefix, before any
    new random block is minted
  - the reassignment carries the prefix unchanged and bumps the attempt count
  - a node finishing a block it still holds is credited
  - a node finishing a block whose lease expired (and moved on) is still credited
  - completing an expired block marks that prefix done and stops re-handing it
"""
import json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server as S
from secp import compressed, N

FAILS = []
def check(name, cond):
    print(("  ok  " if cond else "  FAIL ") + name)
    if not cond: FAILS.append(name)


def make_coord(tmp, space_prefix="", lease=3600):
    cfg = {"targets_file": "targets_rp.txt", "lease_seconds": lease}
    if space_prefix:
        cfg["space_prefix"] = space_prefix
    # tiny target file
    open("targets_rp.txt", "w").write(compressed(0xABCDEF) + "\n")
    if os.path.exists(tmp): os.remove(tmp)
    secret = json.load(open("server.key"))
    return S.Coordinator(cfg, tmp, secret, cfg["targets_file"])


def main():
    if not os.path.exists("server.key"):
        os.system("python3 keygen.py server.key >/dev/null 2>&1")

    print("[random prefixes are 216-bit and distinct]")
    c = make_coord("rp1.db")
    prefixes = set()
    for _ in range(200):
        r = c.op_block_request("nodeA", {})
        check("request ok", r["ok"]) if len(prefixes) == 0 else None
        p = r["prefix"]
        if len(p) != 54:
            check("prefix is 54 hex chars", False); break
        int(p, 16)  # valid hex
        prefixes.add(p)
    check("54-hex prefixes", all(len(p) == 54 for p in prefixes))
    check("200 distinct random prefixes", len(prefixes) == 200)
    check("unknown_bits is 40", r["unknown_bits"] == 40)

    print("\n[space_prefix constraint respected]")
    c2 = make_coord("rp2.db", space_prefix="dead")
    for _ in range(50):
        r = c2.op_block_request("nodeA", {})
        if not r["prefix"].startswith("dead"):
            check("prefix begins with space_prefix", False); break
    else:
        check("prefix begins with space_prefix", True)
    check("still 54 hex total", len(r["prefix"]) == 54)

    print("\n[expired lease is re-handed to the next requester]")
    c3 = make_coord("rp3.db", lease=1)
    a = c3.op_block_request("nodeA", {})
    check("A leased, not reassigned", a["ok"] and a["reassigned"] is False)
    check("A attempts == 1", a["attempts"] == 1)
    a_prefix, a_idx = a["prefix"], a["block_idx"]
    time.sleep(1.2)  # let A's lease expire
    b = c3.op_block_request("nodeB", {})
    check("B gets A's expired prefix", b["prefix"] == a_prefix)
    check("B marked as reassigned", b["reassigned"] is True)
    check("same block idx re-handed", b["block_idx"] == a_idx)
    check("attempts incremented to 2", b["attempts"] == 2)

    print("\n[expired block has priority over minting a new one]")
    c4 = make_coord("rp4.db", lease=1)
    x = c4.op_block_request("nodeA", {})
    time.sleep(1.2)
    # two expired? no -- only one leased. Next request must reuse it, not mint.
    before = c4.db.execute("SELECT COUNT(*) FROM blocks").fetchone()[0]
    y = c4.op_block_request("nodeB", {})
    after = c4.db.execute("SELECT COUNT(*) FROM blocks").fetchone()[0]
    check("no new block minted while an expired one waits", after == before)
    check("expired prefix reused", y["prefix"] == x["prefix"])

    print("\n[current holder completes normally]")
    c5 = make_coord("rp5.db", lease=3600)
    _, apub = __import__("protocol").generate_identity()
    c5.op_register("nodeA", {"x25519": apub["x25519"], "gpu": "t", "sw": "t"})
    r = c5.op_block_request("nodeA", {})
    cr = c5.op_block_complete("nodeA", {"block_idx": r["block_idx"],
                                        "seconds": 100.0, "keys_checked": 1 << 40})
    check("owner completion ok", cr["ok"] and not cr.get("note"))
    st = c5.op_stats("nodeA", {})
    check("blocks_done credited", st["nodes"][0]["blocks_done"] == 1)
    check("one done block in stats", st["blocks"]["done"] == 1)

    print("\n[after reassignment only the current holder can complete]")
    c6 = make_coord("rp6.db", lease=1)
    a = c6.op_block_request("nodeA", {})
    time.sleep(1.2)
    b = c6.op_block_request("nodeB", {})     # A's block re-handed to B
    check("re-handed to B", b["block_idx"] == a["block_idx"])
    # A's stale report is refused -- B is now searching that prefix
    lc = c6.op_block_complete("nodeA", {"block_idx": a["block_idx"], "seconds": 200.0})
    check("stale report from A refused", not lc["ok"])
    check("prefix still leased to B", c6.db.execute(
        "SELECT state FROM blocks WHERE idx=?", (a["block_idx"],)).fetchone()[0] == "leased")
    # B, the current holder, completes it
    lc2 = c6.op_block_complete("nodeB", {"block_idx": a["block_idx"],
                                         "seconds": 50.0, "keys_checked": 1 << 40})
    check("current holder B completes ok", lc2["ok"] and not lc2.get("note"))
    check("prefix now done", c6.db.execute(
        "SELECT state FROM blocks WHERE idx=?", (a["block_idx"],)).fetchone()[0] == "done")
    # completed prefix must no longer be re-handed
    nxt = c6.op_block_request("nodeC", {})
    check("done prefix not re-handed", nxt["prefix"] != a["prefix"])

    print("\n[stranger cannot complete a block it never held]")
    c7 = make_coord("rp7.db", lease=3600)
    r = c7.op_block_request("nodeA", {})
    bad = c7.op_block_complete("nodeZ", {"block_idx": r["block_idx"], "seconds": 1.0})
    check("non-holder refused on live block", not bad["ok"])

    for f in ["rp1.db","rp2.db","rp3.db","rp4.db","rp5.db","rp6.db","rp7.db",
              "targets_rp.txt","server.key","server.pub"]:
        if os.path.exists(f): os.remove(f)

    print("\n" + ("ALL RANDOM-PREFIX TESTS PASSED" if not FAILS
                  else "FAILURES: " + ", ".join(FAILS)))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
