#!/usr/bin/env python3
"""Generate an Ed25519 + X25519 identity. Writes the secret file (chmod 600)
and a companion .pub file safe to distribute."""
import argparse, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import protocol as P

ap = argparse.ArgumentParser()
ap.add_argument("out", help="secret key file path, e.g. node.key")
a = ap.parse_args()
if os.path.exists(a.out):
    raise SystemExit("refusing to overwrite existing %s" % a.out)

sec, pub = P.generate_identity()
P.write_key_file(a.out, sec, secret=True)
P.write_key_file(a.out + ".pub" if not a.out.endswith(".key")
                 else a.out[:-4] + ".pub", pub)
pubpath = a.out[:-4] + ".pub" if a.out.endswith(".key") else a.out + ".pub"
print("secret : %s  (keep private, chmod 600)" % a.out)
print("public : %s  (distribute this)" % pubpath)
print("node id: %s" % pub["ed25519"])
