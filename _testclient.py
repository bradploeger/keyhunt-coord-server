"""Minimal sealed-envelope HTTP client, used only by test_e2e.py so the server
repo can test itself without depending on the node repo. The real node client
lives in the keyhunt-node repository; this is a deliberately small stand-in that
speaks the same protocol.
"""
import json
import os
import time
import urllib.error
import urllib.request

import protocol as P


class TestClient:
    def __init__(self, key_path, url, server_ed_hex, server_x_hex, timeout=30):
        with open(key_path) as f:
            secret = json.load(f)
        self.sign_key, self.enc_key = P.load_secret(secret)
        self.ed_hex = secret["ed25519"]
        self.x_hex = secret["x25519"]
        self.url = url.rstrip("/")
        self.server_ed = server_ed_hex
        self.server_x = server_x_hex
        self.timeout = timeout
        self.out_seq = int(time.time() * 1000)
        self.server_seq = None

    def _call(self, path, op, payload=None):
        body = dict(payload or {})
        body["op"] = op
        body["rid"] = os.urandom(8).hex()
        self.out_seq += 1
        env = P.seal(body, self.sign_key, self.x_hex,
                     self.server_ed, self.server_x, self.out_seq)
        req = urllib.request.Request(
            self.url + path, data=json.dumps(env).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                resp = json.loads(r.read())
        except urllib.error.HTTPError as e:
            raise RuntimeError("server %d: %s" % (e.code, e.read().decode()[:200]))
        sender, reply, ts, seq = P.open_envelope(
            resp, self.ed_hex, self.enc_key,
            lambda h: self.server_x, last_seq=self.server_seq)
        if sender != self.server_ed:
            raise RuntimeError("reply signed by unexpected key")
        self.server_seq = seq
        return reply

    def register(self, gpu, sw):
        return self._call("/v1/register", "register",
                          {"x25519": self.x_hex, "gpu": gpu, "sw": sw})

    def get_targets(self):
        return self._call("/v1/targets", "targets")

    def request_block(self):
        return self._call("/v1/block/request", "block_request")

    def complete_block(self, block_idx, seconds, keys_checked=0):
        return self._call("/v1/block/complete", "block_complete",
                          {"block_idx": block_idx, "seconds": seconds,
                           "keys_checked": keys_checked})

    def report_match(self, privkey_hex, pubkey_hex, block_idx=-1):
        return self._call("/v1/match", "match",
                          {"privkey": privkey_hex, "pubkey": pubkey_hex,
                           "block_idx": block_idx})

    def stats(self):
        return self._call("/v1/stats", "stats")
