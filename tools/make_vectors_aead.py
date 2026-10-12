"""Generates cases.json and negative.json for aead-record-v1 with the Python implementation,
which tools/xaes_c2sp_check.py has checked against the C2SP vectors. The other languages must reproduce them."""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "impl", "python"))
import aead_record_v1 as r  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "vectors", r.RECIPE)
C2SP_NONCE = b"ABCDEFGHIJKLMNOPQRSTUVWX".hex()
inputs = [
    ("c2sp-1", "01" * 32, C2SP_NONCE, "", "XAES-256-GCM"),
    ("c2sp-2", "03" * 32, C2SP_NONCE, "c2sp.org/XAES-256-GCM", "XAES-256-GCM"),
    ("empty-plaintext", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00" * 24, "", ""),
    ("aad-only", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "ff" * 24, "header v2", ""),
    ("unicode", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "0123456789abcdef" * 3, "tenant=42 ✓", "plaintext with ünïcödé and emoji 🔐 and a newline\n"),
    ("one-block-plus-one", "deadbeef" * 8, "cafebabe" * 6, "", "a" * 17),
    ("long", "a0" * 32, "b1" * 24, "x" * 300, "x" * 10_000),
]
cases = []
for cid, key, nonce, aad, pt in inputs:
    cases.append({"id": cid, "key_hex": key, "nonce_hex": nonce, "aad": aad, "plaintext": pt,
                  "output_base64": r.encrypt(bytes.fromhex(key), pt, aad, bytes.fromhex(nonce))})
assert base64.b64decode(cases[0]["output_base64"])[25:].hex() == "ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271"
assert base64.b64decode(cases[1]["output_base64"])[25:].hex() == "986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d"

base = cases[1]
raw = bytearray(base64.b64decode(base["output_base64"]))
def b64(b): return base64.b64encode(bytes(b)).decode()
def flipped(i):
    x = bytearray(raw); x[i] ^= 0x01; return b64(x)
wrong_key = bytearray(bytes.fromhex(base["key_hex"])); wrong_key[0] ^= 0x01
negative = [
    {"id": "wrong-key", "key_hex": wrong_key.hex(), "aad": base["aad"], "input_base64": base["output_base64"], "note": "one key bit flipped"},
    {"id": "wrong-aad", "key_hex": base["key_hex"], "aad": "c2sp.org/XAES-256-GCM ", "input_base64": base["output_base64"], "note": "trailing space added to the additional data"},
    {"id": "missing-aad", "key_hex": base["key_hex"], "aad": "", "input_base64": base["output_base64"], "note": "record was sealed with additional data, opened with none"},
    {"id": "tag-flipped", "key_hex": base["key_hex"], "aad": base["aad"], "input_base64": flipped(len(raw) - 1), "note": "last byte of the tag flipped"},
    {"id": "ciphertext-flipped", "key_hex": base["key_hex"], "aad": base["aad"], "input_base64": flipped(1 + 24), "note": "first ciphertext byte flipped"},
    {"id": "nonce-prefix-flipped", "key_hex": base["key_hex"], "aad": base["aad"], "input_base64": flipped(1), "note": "first nonce byte flipped, so the derived key differs"},
    {"id": "nonce-suffix-flipped", "key_hex": base["key_hex"], "aad": base["aad"], "input_base64": flipped(1 + 12), "note": "byte 13 of the nonce flipped, so the GCM nonce differs"},
    {"id": "truncated-tag", "key_hex": base["key_hex"], "aad": base["aad"], "input_base64": b64(raw[:-1]), "note": "one byte of the tag missing"},
    {"id": "truncated-to-header", "key_hex": base["key_hex"], "aad": base["aad"], "input_base64": b64(raw[:1 + 24]), "note": "no ciphertext and no tag"},
    {"id": "wrong-version", "key_hex": base["key_hex"], "aad": base["aad"], "input_base64": b64(bytes([0x02]) + raw[1:]), "note": "version byte 0x02"},
    {"id": "no-version", "key_hex": base["key_hex"], "aad": base["aad"], "input_base64": b64(raw[1:]), "note": "layout without the leading byte"},
    {"id": "empty-input", "key_hex": base["key_hex"], "aad": base["aad"], "input_base64": "", "note": "empty string"},
    {"id": "not-base64", "key_hex": base["key_hex"], "aad": base["aad"], "input_base64": "@@@@", "note": "not Base64"},
    {"id": "tag-moved", "key_hex": base["key_hex"], "aad": base["aad"], "input_base64": b64(raw[:1 + 24] + raw[-16:] + raw[1 + 24:-16]), "note": "tag placed before the ciphertext"},
    {"id": "short-key", "key_hex": base["key_hex"][:32], "aad": base["aad"], "input_base64": base["output_base64"], "note": "16-byte key; the recipe takes 32 bytes only"},
]
os.makedirs(OUT, exist_ok=True)
with open(os.path.join(OUT, "cases.json"), "w") as f:
    json.dump({"recipe": r.RECIPE, "note": "The nonce is fixed here only to make the output reproducible; real encryptions use a random one. Cases c2sp-1 and c2sp-2 wrap the two vectors published at https://c2sp.org/XAES-256-GCM: bytes 25 onward of the decoded output are the C2SP ciphertext.", "cases": cases}, f, indent=1, ensure_ascii=False)
    f.write("\n")
with open(os.path.join(OUT, "negative.json"), "w") as f:
    json.dump({"recipe": r.RECIPE, "note": "Every case must fail to decrypt. An implementation that returns any plaintext for any of them does not conform.", "cases": negative}, f, indent=1, ensure_ascii=False)
    f.write("\n")
print(f"wrote {len(cases)} cases and {len(negative)} negative cases to {OUT}")
