#!/usr/bin/env python3
"""generate an rsa device keypair outside the repository.

blockaudit does not load or use these keys today. the script exists so keys are provisioned
safely if signing is added: private key mode 0600, never inside the source tree, never overwritten.
"""
import argparse
import os
import sys

from Crypto.PublicKey import RSA

REPO = os.path.dirname(os.path.abspath(__file__))


def default_dir():
    return os.environ.get("BLOCKAUDIT_KEY_DIR") or os.path.join(os.path.expanduser("~"), ".config", "blockaudit", "keys")


def generate_rsa_keypair(out_dir, name="device", key_size=3072):
    out_dir = os.path.realpath(out_dir)
    if out_dir == REPO or out_dir.startswith(REPO + os.sep):
        raise SystemExit("refusing to write keys inside the repository; choose another --out-dir")
    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    priv, pub = os.path.join(out_dir, f"{name}_priv.pem"), os.path.join(out_dir, f"{name}_pub.pem")
    for path in (priv, pub):
        if os.path.exists(path):
            raise SystemExit(f"{path} already exists; move it aside to rotate, it will not be overwritten")
    key = RSA.generate(key_size)
    fd = os.open(priv, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.export_key())
    with open(pub, "wb") as f:
        f.write(key.publickey().export_key())
    return priv, pub


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out-dir", default=default_dir())
    ap.add_argument("--name", default="device")
    args = ap.parse_args()
    priv, pub = generate_rsa_keypair(args.out_dir, args.name)
    print(f"wrote {priv} (0600) and {pub}", file=sys.stderr)
