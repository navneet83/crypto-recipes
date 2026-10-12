"""Generates cases.json and negative.json for pbe-record-pbkdf2-gcm-v1 with the Python implementation.
The TypeScript and Swift harnesses must reproduce the same outputs; the CI runs all three."""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "impl", "python"))
import pbe_record_pbkdf2_gcm_v1 as r  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "vectors", r.RECIPE)

inputs = [
    ("short", "correct horse battery staple", "000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b", "The quick brown fox jumps over the lazy dog"),
    ("empty-plaintext", "correct horse battery staple", "000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b", ""),
    ("empty-password", "", "ffffffffffffffffffffffffffffffff", "000000000000000000000000", "empty password is allowed, but do not do this"),
    ("unicode", "pässwörd ✓ 密码", "0f0e0d0c0b0a09080706050403020100", "1b1a19181716151413121110", "plaintext with ünïcödé and emoji 🔐 and a newline\n"),
    ("one-block-plus-one", "p", "00" * 16, "00" * 12, "a" * 17),
    ("long", "a much longer password than usual, which is fine", "deadbeef" * 4, "cafebabe" * 3, "x" * 10_000),
]
cases = []
for cid, pw, salt, nonce, pt in inputs:
    cases.append({"id": cid, "password": pw, "salt_hex": salt, "nonce_hex": nonce, "plaintext": pt,
                  "output_base64": r.encrypt(pw, pt, bytes.fromhex(salt), bytes.fromhex(nonce))})

base = cases[0]
raw = bytearray(base64.b64decode(base["output_base64"]))
def b64(b): return base64.b64encode(bytes(b)).decode()
def flipped(i):
    x = bytearray(raw); x[i] ^= 0x01; return b64(x)
negative = [
    {"id": "wrong-password", "password": "correct horse battery stapl", "input_base64": base["output_base64"], "note": "password off by one character"},
    {"id": "tag-flipped", "password": base["password"], "input_base64": flipped(len(raw) - 1), "note": "last byte of the tag flipped"},
    {"id": "ciphertext-flipped", "password": base["password"], "input_base64": flipped(1 + 16 + 12), "note": "first ciphertext byte flipped"},
    {"id": "salt-flipped", "password": base["password"], "input_base64": flipped(1), "note": "first salt byte flipped, so the key differs"},
    {"id": "nonce-flipped", "password": base["password"], "input_base64": flipped(1 + 16), "note": "first nonce byte flipped"},
    {"id": "truncated-tag", "password": base["password"], "input_base64": b64(raw[:-1]), "note": "one byte of the tag missing"},
    {"id": "truncated-to-header", "password": base["password"], "input_base64": b64(raw[:1 + 16 + 12]), "note": "no ciphertext and no tag"},
    {"id": "wrong-version", "password": base["password"], "input_base64": b64(bytes([0x02]) + raw[1:]), "note": "version byte 0x02"},
    {"id": "no-version", "password": base["password"], "input_base64": b64(raw[1:]), "note": "the pre-versioning layout without the leading byte"},
    {"id": "empty-input", "password": base["password"], "input_base64": "", "note": "empty string"},
    {"id": "not-base64", "password": base["password"], "input_base64": "@@@@", "note": "not Base64"},
    {"id": "tag-moved", "password": base["password"], "input_base64": b64(raw[:1 + 16 + 12] + raw[-16:] + raw[1 + 16 + 12:-16]), "note": "tag placed before the ciphertext"},
]
os.makedirs(OUT, exist_ok=True)
with open(os.path.join(OUT, "cases.json"), "w") as f:
    json.dump({"recipe": r.RECIPE, "note": "Salt and nonce are fixed here only to make the output reproducible; real encryptions use random ones.", "cases": cases}, f, indent=1, ensure_ascii=False)
    f.write("\n")
with open(os.path.join(OUT, "negative.json"), "w") as f:
    json.dump({"recipe": r.RECIPE, "note": "Every case must fail to decrypt. An implementation that returns any plaintext for any of them does not conform.", "cases": negative}, f, indent=1, ensure_ascii=False)
    f.write("\n")
print(f"wrote {len(cases)} cases and {len(negative)} negative cases to {OUT}")
