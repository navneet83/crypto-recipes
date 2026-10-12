"""Generates cases.json and negative.json for sign-detached-v1 with the Python implementation. Ed25519 is
deterministic, so every implementation must reproduce the public key and the signature byte for byte."""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "impl", "python"))
import sign_detached_v1 as r  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "vectors", r.RECIPE)
inputs = [
    ("rfc8032-key-1", "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", ""),
    ("short", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "The quick brown fox jumps over the lazy dog"),
    ("unicode", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "message with ünïcödé and emoji 🔐 and a newline\n"),
    ("zero-seed", "00" * 32, "a zero seed is a valid Ed25519 key; it is here only so that an implementation that rejects it fails loudly"),
    ("long", "deadbeef" * 8, "x" * 10_000),
]
cases = []
for cid, seed, message in inputs:
    cases.append({"id": cid, "seed_hex": seed, "public_hex": r.public_key(bytes.fromhex(seed)).hex(), "message": message,
                  "signature_base64": r.sign(bytes.fromhex(seed), message)})
# RFC 8032 section 7.1 test 1: the seed above has this public key.
assert cases[0]["public_hex"] == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

base = cases[1]
sig = bytearray(base64.b64decode(base["signature_base64"]))
def b64(b): return base64.b64encode(bytes(b)).decode()
def flipped(i):
    x = bytearray(sig); x[i] ^= 0x01; return b64(x)
other_public = r.public_key(bytes.fromhex(cases[2]["seed_hex"])).hex()
raw_sig = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(base["seed_hex"])).sign(base["message"].encode())
negative = [
    {"id": "wrong-message", "public_hex": base["public_hex"], "message": base["message"] + ".", "input_base64": base["signature_base64"], "note": "one character appended to the message"},
    {"id": "wrong-public-key", "public_hex": other_public, "message": base["message"], "input_base64": base["signature_base64"], "note": "a different key's public half"},
    {"id": "signature-r-flipped", "public_hex": base["public_hex"], "message": base["message"], "input_base64": flipped(0), "note": "first byte of R flipped"},
    {"id": "signature-s-flipped", "public_hex": base["public_hex"], "message": base["message"], "input_base64": flipped(63), "note": "last byte of S flipped"},
    {"id": "truncated", "public_hex": base["public_hex"], "message": base["message"], "input_base64": b64(sig[:-1]), "note": "63-byte signature"},
    {"id": "extended", "public_hex": base["public_hex"], "message": base["message"], "input_base64": b64(sig + b"\x00"), "note": "65-byte signature"},
    {"id": "empty", "public_hex": base["public_hex"], "message": base["message"], "input_base64": "", "note": "empty signature"},
    {"id": "not-base64", "public_hex": base["public_hex"], "message": base["message"], "input_base64": "@@@@", "note": "not Base64"},
    {"id": "no-domain-separation", "public_hex": base["public_hex"], "message": base["message"], "input_base64": b64(raw_sig), "note": "a plain Ed25519 signature over the raw message, without the recipe prefix; an implementation that accepts it skipped the prefix"},
    {"id": "swapped-halves", "public_hex": base["public_hex"], "message": base["message"], "input_base64": b64(sig[32:] + sig[:32]), "note": "S placed before R"},
]
os.makedirs(OUT, exist_ok=True)
with open(os.path.join(OUT, "cases.json"), "w") as f:
    json.dump({"recipe": r.RECIPE, "note": "An implementation must reproduce public_hex from seed_hex and must verify signature_base64 with the public key. RFC 8032 signing is deterministic, so most implementations also reproduce signature_base64 byte for byte; CryptoKit randomizes its signatures, and such implementations are checked by verifying their own output instead. Case rfc8032-key-1 uses the first key of RFC 8032 section 7.1.", "cases": cases}, f, indent=1, ensure_ascii=False)
    f.write("\n")
with open(os.path.join(OUT, "negative.json"), "w") as f:
    json.dump({"recipe": r.RECIPE, "note": "Every case must fail to verify. input_base64 is the signature under test.", "cases": negative}, f, indent=1, ensure_ascii=False)
    f.write("\n")
print(f"wrote {len(cases)} cases and {len(negative)} negative cases to {OUT}")
