import json, random, shutil, subprocess, sys, os
from secp import compressed, N


def copy_and_rename(src_path, dest_path, new_name):
    # Copy the file
    shutil.copy(src_path, dest_path)

    # Rename the copied file
    new_path = f"{dest_path}/{new_name}"
    shutil.move(f"{dest_path}/{src_path}", new_path)


# Backup the vital production files
files = ["coord.db", "coord.json", "server.key", "server.pub", "targets.txt"]

for file in files:
    copy_and_rename(f"{file}", "./backup", f"{file}.bak")

# Generate New Keys
subprocess.run([sys.executable, "keygen.py", "server.key"])
subprocess.run([sys.executable, "keygen.py", "node1.key"])

# Hide A Valid Key in the Mix
random.seed(3)
priv = random.randrange(1, N)
lines = [compressed(priv)] + [compressed(random.randrange(1, N)) for _ in range(999)]
random.shuffle(lines)

open("targets.txt","w").write("\n".join(lines)+"\n")
json.dump({"targets_file":"targets.txt","lease_seconds":3600}, open("coord.json","w"))
json.dump({"priv":"%064x"%priv,"pub":compressed(priv)}, open("planted.json","w"))

# Run the E2E Tests
subprocess.run([sys.executable, "test_e2e.py"])

# Restore The Backed Up Files
for file in files:
    copy_and_rename(f"backup/{file}.bak", ".", f"{file}")
