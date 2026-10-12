"""Generates cases.json and negative.json for sign-detached-pq-v1 with the Python implementation. ML-DSA signing is
randomized, so implementations reproduce the public key from the seed and verify the stored signature; their own
signatures are checked by verification."""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "impl", "python"))
import sign_detached_pq_v1 as r  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "vectors", r.RECIPE)
inputs = [
    ("seed-07", "07" * 32, "The quick brown fox jumps over the lazy dog"),
    ("empty-message", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", ""),
    ("unicode", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "message with ünïcödé and emoji 🔐 and a newline\n"),
    ("zero-seed", "00" * 32, "a zero seed is a valid ML-DSA key; it is here only so that an implementation that rejects it fails loudly"),
    ("long", "deadbeef" * 8, "x" * 10_000),
]
cases = []
for cid, seed, message in inputs:
    cases.append({"id": cid, "seed_hex": seed, "public_hex": r.public_key(bytes.fromhex(seed)).hex(), "message": message,
                  "signature_base64": r.sign(bytes.fromhex(seed), message)})
# The five platforms probed on 2026-10-12 (pyca, Go, Node, the JDK, CryptoKit) all derive this public key from seed 07*32.
assert cases[0]["public_hex"].startswith("37584a6e4279aece")

base = cases[0]
sig = bytearray(base64.b64decode(base["signature_base64"]))
def b64(b): return base64.b64encode(bytes(b)).decode()
def flipped(i):
    x = bytearray(sig); x[i] ^= 0x01; return b64(x)
other_public = cases[2]["public_hex"]
raw_sig = MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(base["seed_hex"])).sign(base["message"].encode())
ctx_sig = MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(base["seed_hex"])).sign(base["message"].encode(), context=r.DOMAIN[:-1])
negative = [
    {"id": "wrong-message", "public_hex": base["public_hex"], "message": base["message"] + ".", "input_base64": base["signature_base64"], "note": "one character appended to the message"},
    {"id": "wrong-public-key", "public_hex": other_public, "message": base["message"], "input_base64": base["signature_base64"], "note": "a different key's public half"},
    {"id": "signature-first-byte-flipped", "public_hex": base["public_hex"], "message": base["message"], "input_base64": flipped(0), "note": "first byte of the signature flipped"},
    {"id": "signature-last-byte-flipped", "public_hex": base["public_hex"], "message": base["message"], "input_base64": flipped(len(sig) - 1), "note": "last byte of the signature flipped"},
    {"id": "truncated", "public_hex": base["public_hex"], "message": base["message"], "input_base64": b64(sig[:-1]), "note": "3308-byte signature"},
    {"id": "extended", "public_hex": base["public_hex"], "message": base["message"], "input_base64": b64(sig + b"\x00"), "note": "3310-byte signature"},
    {"id": "empty", "public_hex": base["public_hex"], "message": base["message"], "input_base64": "", "note": "empty signature"},
    {"id": "not-base64", "public_hex": base["public_hex"], "message": base["message"], "input_base64": "@@@@", "note": "not Base64"},
    {"id": "no-domain-separation", "public_hex": base["public_hex"], "message": base["message"], "input_base64": b64(raw_sig), "note": "a plain ML-DSA-65 signature over the raw message with an empty context; an implementation that accepts it skipped the prefix"},
    {"id": "prefix-as-context", "public_hex": base["public_hex"], "message": base["message"], "input_base64": b64(ctx_sig), "note": "the raw message signed with the recipe name as the FIPS 204 context string instead of as a prefix; the recipe uses the prefix"},
    {"id": "short-public-key", "public_hex": base["public_hex"][:-2], "message": base["message"], "input_base64": base["signature_base64"], "note": "1951-byte public key"},
]
os.makedirs(OUT, exist_ok=True)
with open(os.path.join(OUT, "cases.json"), "w") as f:
    json.dump({"recipe": r.RECIPE, "note": "An implementation must reproduce public_hex from seed_hex and must verify signature_base64 with the public key. ML-DSA signing is randomized, so an implementation's own signatures are checked by verification, not by comparison.", "cases": cases}, f, indent=1, ensure_ascii=False)
    f.write("\n")
with open(os.path.join(OUT, "negative.json"), "w") as f:
    json.dump({"recipe": r.RECIPE, "note": "Every case must fail to verify. input_base64 is the signature under test.", "cases": negative}, f, indent=1, ensure_ascii=False)
    f.write("\n")
print(f"wrote {len(cases)} cases and {len(negative)} negative cases to {OUT}")
