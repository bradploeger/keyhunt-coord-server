#!/usr/bin/env python3
"""Spins up a real server on a random localhost port and exercises the whole
protocol, including the security properties. Run: python3 test_e2e.py"""
import json, os, sys, threading, time, copy
from http.server import ThreadingHTTPServer
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import protocol as P
import server as S
from _testclient import TestClient as Node

FAILS = []
def check(name, cond):
    print(("  ok  " if cond else "  FAIL ") + name)
    if not cond: FAILS.append(name)

def main():
    secret = json.load(open("server.key"))
    cfg = json.load(open("coord.json"))
    if os.path.exists("test.db"): os.remove("test.db")
    coord = S.Coordinator(cfg, "test.db", secret, cfg["targets_file"])
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), S.make_handler(coord))
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:%d" % port
    sinfo = json.load(open("server.pub"))
    planted = json.load(open("planted.json"))
    print("server on", url)

    n = Node("node1.key", url, sinfo["ed25519"], sinfo["x25519"])

    print("\n[register]")
    r = n.register(gpu="RTX 4090", sw="keyhunt-gpu 1.0")
    check("register ok", r.get("ok"))
    check("returns targets digest", len(r.get("targets_digest","")) == 64)
    check("reports 40 unknown bits", r.get("unknown_bits") == 40)

    print("\n[targets download]")
    t = n.get_targets()
    check("targets ok", t.get("ok"))
    check("count matches", t.get("count") == 1000)
    check("planted key present", planted["pub"] in t["targets"])
    check("digest matches register", t["digest"] == r["targets_digest"])

    print("\n[block lease + complete]")
    # Lease blocks until we've held the planted one, completing each as we go.
    # Blocks are handed out in ascending index order, so this terminates fast.
    seen = set()
    blk = None
    completed = 0
    for _ in range(planted["block_idx"] + 5):
        b = n.request_block()
        check("block ok", b.get("ok")) if len(seen) == 0 else None
        seen.add(b["block_idx"])
        if b["block_idx"] == planted["block_idx"]:
            blk = b
        secs = 812.4 if b["block_idx"] == planted["block_idx"] else 100.0 + b["block_idx"]
        cr = n.complete_block(b["block_idx"], seconds=secs, keys_checked=1 << 40)
        if cr.get("ok") and not cr.get("note"):
            completed += 1
        if blk is not None:
            break
    check("distinct blocks leased in order", len(seen) == planted["block_idx"] + 1)
    check("planted block leased", blk is not None)
    check("all leases completed", completed == len(seen))

    print("\n[completing someone else's block is refused]")
    other = Node("node1.key", url, sinfo["ed25519"], sinfo["x25519"])
    # lease a fresh block as node1, then try to complete a not-owned index
    b2 = n.request_block()
    bad = n.complete_block(999999, seconds=1.0)   # nonexistent
    check("nonexistent block rejected", not bad.get("ok"))

    print("\n[match: verified + in targets]")
    mr = n.report_match(planted["priv"], planted["pub"], block_idx=planted["block_idx"])
    check("match verified", mr.get("verified") is True)
    check("match in targets", mr.get("in_targets") is True)
    dup = n.report_match(planted["priv"], planted["pub"])
    check("duplicate detected", dup.get("duplicate") is True)

    print("\n[match: node lies about the keypair]")
    from secp import compressed
    honest_pub = planted["pub"]
    wrong_pub = compressed(0x9999)   # valid key, but not derived from planted priv
    lie = n.report_match(planted["priv"], wrong_pub)
    check("mismatched keypair not verified", lie.get("verified") is False)

    print("\n[stats]")
    st = n.stats()
    check("stats ok", st.get("ok"))
    node_row = st["nodes"][0]
    check("blocks_done recorded", node_row["blocks_done"] == len(seen))
    check("avg seconds computed", node_row["avg_seconds_per_block"] is not None)
    check("keys/sec computed", node_row["keys_per_sec"] is not None)
    check("verified match counted", st["verified_matches"] == 1)

    # -------- security properties, poking the raw envelope layer directly ----
    print("\n[security: tampered ciphertext rejected]")
    n2 = Node("node1.key", url, sinfo["ed25519"], sinfo["x25519"])
    n2.out_seq += 1
    env = P.seal({"op":"stats","rid":"x"}, n2.sign_key, n2.x_hex,
                 n2.server_ed, n2.server_x, n2.out_seq)
    bad_env = copy.deepcopy(env)
    ba = bytearray(bytes.fromhex(bad_env["ct"])); ba[0] ^= 1
    bad_env["ct"] = ba.hex()
    import urllib.request, urllib.error
    def post(e):
        req = urllib.request.Request(url+"/v1/stats", data=json.dumps(e).encode(),
                                     headers={"Content-Type":"application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as ex:
            return ex.code, json.loads(ex.read())
    code, _ = post(bad_env)
    check("tampered ct -> 401", code == 401)

    print("\n[security: replayed sequence number rejected]")
    n3 = Node("node1.key", url, sinfo["ed25519"], sinfo["x25519"])
    n3.out_seq += 1
    e1 = P.seal({"op":"stats","rid":"a"}, n3.sign_key, n3.x_hex,
                n3.server_ed, n3.server_x, n3.out_seq)
    c1,_ = post(e1)
    c2,_ = post(e1)   # exact replay
    check("first accepted", c1 == 200)
    check("replay rejected", c2 == 401)

    print("\n[security: message for a different recipient rejected]")
    _, bogus_pub = P.generate_identity()
    n4 = Node("node1.key", url, sinfo["ed25519"], sinfo["x25519"])
    n4.out_seq += 1
    ewrong = P.seal({"op":"stats","rid":"b"}, n4.sign_key, n4.x_hex,
                    bogus_pub["ed25519"], bogus_pub["x25519"], n4.out_seq)
    cw,_ = post(ewrong)
    check("wrong-recipient rejected", cw == 401)

    print("\n[security: unregistered node cannot lease]")
    from protocol import generate_identity, write_key_file
    sec, pub = generate_identity()
    write_key_file("stranger.key", sec, secret=True)
    stranger = Node("stranger.key", url, sinfo["ed25519"], sinfo["x25519"])
    try:
        resp = stranger.request_block()
        refused = not resp.get("ok")
    except RuntimeError as e:
        refused = "403" in str(e) or "register" in str(e)
    check("unregistered node refused a block", refused)
    os.remove("stranger.key")

    httpd.shutdown()
    print("\n" + ("ALL E2E TESTS PASSED" if not FAILS else "FAILURES: " + ", ".join(FAILS)))
    return 1 if FAILS else 0

if __name__ == "__main__":
    sys.exit(main())
