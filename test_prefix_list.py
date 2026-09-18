#!/usr/bin/env python3
"""Tests the preassigned prefix-list feature directly against Coordinator.

Checks:
  - listed prefixes are handed out in file order, before any random prefix
  - expired blocks still take priority over the pending list
  - once the list is exhausted, assignment falls back to random
  - bad lines (wrong length / non-hex / wrong space_prefix) are skipped
  - a space_prefix constraint is enforced against listed prefixes
  - seeding is idempotent across a restart (same DB, file re-read)
  - stats report the pending count
"""
import json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server as S
from secp import compressed

FAILS = []
def check(name, cond):
    print(("  ok  " if cond else "  FAIL ") + name)
    if not cond:
        FAILS.append(name)


def write(path, text):
    with open(path, "w") as f:
        f.write(text)


def make_coord(dbpath, cfg_extra=None):
    if not os.path.exists("server.key"):
        os.system("python3 keygen.py server.key >/dev/null 2>&1")
    write("targets_pl.txt", compressed(0xABCDEF) + "\n")
    cfg = {"targets_file": "targets_pl.txt", "lease_seconds": 3600}
    if cfg_extra:
        cfg.update(cfg_extra)
    if os.path.exists(dbpath):
        os.remove(dbpath)
    secret = json.load(open("server.key"))
    return S.Coordinator(cfg, dbpath, secret, cfg["targets_file"]), cfg


P = "%054x"   # 54-hex formatter


def main():
    # A list of three valid 54-hex prefixes plus junk lines to skip.
    listed = [P % 0x11, P % 0x22, P % 0x33]
    write("plist.txt",
          "# a comment\n\n"
          + listed[0] + "\n"
          + listed[1] + "\n"
          + "not-hex-here" + "\n"          # non-hex -> skipped
          + ("ab" * 20) + "\n"             # 40 hex, wrong length -> skipped
          + listed[2] + "\n"
          + listed[1] + "\n")              # duplicate -> skipped

    print("[listed prefixes handed out in file order before random]")
    c, _ = make_coord("pl1.db", {"prefix_list_file": "plist.txt"})
    check("seed added 3", c.pending_seed["added"] == 3)
    check("seed skipped 2 bad", c.pending_seed["skipped_bad"] == 2)
    check("seed skipped 1 dup", c.pending_seed["skipped_dup"] == 1)

    got = []
    for _ in range(3):
        r = c.op_block_request("nodeA", {})
        check("from_list true", r.get("from_list") is True)
        got.append(r["prefix"])
    check("handed out in file order", got == listed)

    # 4th request: list exhausted -> random
    r4 = c.op_block_request("nodeA", {})
    check("4th is random (from_list false)", r4.get("from_list") is False)
    check("4th prefix not in list", r4["prefix"] not in listed)
    check("random prefix is 54 hex", len(r4["prefix"]) == 54)

    print("\n[expired blocks take priority over the pending list]")
    c2, _ = make_coord("pl2.db", {"prefix_list_file": "plist.txt", "lease_seconds": 1})
    a = c2.op_block_request("nodeA", {})          # gets listed[0]
    check("first from list", a["prefix"] == listed[0] and a["from_list"])
    time.sleep(1.2)                               # let it expire
    b = c2.op_block_request("nodeB", {})
    check("expired re-handed before next list entry",
          b["prefix"] == listed[0] and b["reassigned"] is True)
    cnext = c2.op_block_request("nodeC", {})
    check("then the next list entry", cnext["prefix"] == listed[1] and cnext["from_list"])

    print("\n[space_prefix constraint enforced against the list]")
    # prefixes must start with 'dead'; one does, two don't
    good = "dead" + ("%050x" % 0x5)
    write("plist2.txt", good + "\n" + (P % 0xAA) + "\n" + ("beef" + "%050x" % 1) + "\n")
    c3, _ = make_coord("pl3.db", {"prefix_list_file": "plist2.txt", "space_prefix": "dead"})
    check("only the matching prefix seeded", c3.pending_seed["added"] == 1)
    check("two rejected as bad", c3.pending_seed["skipped_bad"] == 2)
    r = c3.op_block_request("nodeA", {})
    check("served the space_prefix-matching entry", r["prefix"] == good)

    print("\n[seeding is idempotent across a restart]")
    # reuse pl1.db: it already has the 3 listed prefixes (some leased/random now).
    secret = json.load(open("server.key"))
    cfg = {"targets_file": "targets_pl.txt", "lease_seconds": 3600,
           "prefix_list_file": "plist.txt"}
    c1b = S.Coordinator(cfg, "pl1.db", secret, "targets_pl.txt")
    check("restart adds no duplicates", c1b.pending_seed["added"] == 0)
    # 3 listed prefixes already in the table + the one repeated line = 4 dup skips
    check("restart counts 4 as dup", c1b.pending_seed["skipped_dup"] == 4)

    print("\n[stats report pending count]")
    c4, _ = make_coord("pl4.db", {"prefix_list_file": "plist.txt"})
    st = c4.op_stats("nodeA", {})
    check("pending == 3 before any request", st["blocks"]["pending"] == 3)
    c4.op_block_request("nodeA", {})
    st2 = c4.op_stats("nodeA", {})
    check("pending drops to 2 after one lease", st2["blocks"]["pending"] == 2)
    check("total counts all states", st2["blocks"]["total"] ==
          st2["blocks"]["leased"] + st2["blocks"]["expired"]
          + st2["blocks"]["done"] + st2["blocks"]["pending"])

    for f in ["pl1.db", "pl2.db", "pl3.db", "pl4.db", "plist.txt", "plist2.txt",
              "targets_pl.txt", "server.key", "server.pub"]:
        if os.path.exists(f):
            os.remove(f)

    print("\n" + ("ALL PREFIX-LIST TESTS PASSED" if not FAILS
                  else "FAILURES: " + ", ".join(FAILS)))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
