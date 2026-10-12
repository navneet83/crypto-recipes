"""Generates the vectors for hpke-envelope-v1 with the Python implementation.

HPKE encryption draws a fresh ephemeral key that none of the native APIs let a caller fix, so cases.json holds
records to open, not outputs to reproduce: an implementation must derive public_hex from private_hex, open
record_base64, and have its own records opened by the others. rfc9180.json is the one CFRG test vector for this
suite (base mode, X25519, HKDF-SHA256, AES-256-GCM); implementations that assemble HPKE from parts check against it."""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "impl", "python"))
import hpke_envelope_v1 as r  # noqa: E402

HERE = os.path.dirname(__file__)
OUT = os.path.join(HERE, "..", "vectors", r.RECIPE)
inputs = [
    ("rfc9180-recipient", "497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d", "The quick brown fox jumps over the lazy dog"),
    ("empty-plaintext", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", ""),
    ("unicode", "a0" * 32, "plaintext with ünïcödé and emoji 🔐 and a newline\n"),
    ("long", "deadbeef" * 8, "x" * 10_000),
]
cases = []
for cid, priv, pt in inputs:
    pub = r.public_key(bytes.fromhex(priv))
    cases.append({"id": cid, "private_hex": priv, "public_hex": pub.hex(), "plaintext": pt, "record_base64": r.encrypt(pub, pt)})
assert cases[0]["public_hex"] == "430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c"  # pkRm of the CFRG vector

base = cases[0]
raw = bytearray(base64.b64decode(base["record_base64"]))
def b64(b): return base64.b64encode(bytes(b)).decode()
def flipped(i):
    x = bytearray(raw); x[i] ^= 0x01; return b64(x)
other_record = r.encrypt(bytes.fromhex(cases[2]["public_hex"]), base["plaintext"])
from cryptography.hazmat.primitives import hpke  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey  # noqa: E402
wrong_info = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_256_GCM).encrypt(
    base["plaintext"].encode(), X25519PublicKey.from_public_bytes(bytes.fromhex(base["public_hex"])), b"crypto-recipes/hpke-envelope-v2")
negative = [
    {"id": "wrong-recipient", "private_hex": cases[2]["private_hex"], "input_base64": base["record_base64"], "note": "opened with a different recipient's private key"},
    {"id": "sealed-to-other", "private_hex": base["private_hex"], "input_base64": other_record, "note": "a record sealed to a different public key"},
    {"id": "enc-flipped", "private_hex": base["private_hex"], "input_base64": flipped(1), "note": "first byte of the encapsulated key flipped"},
    {"id": "ciphertext-flipped", "private_hex": base["private_hex"], "input_base64": flipped(1 + 32), "note": "first ciphertext byte flipped"},
    {"id": "tag-flipped", "private_hex": base["private_hex"], "input_base64": flipped(len(raw) - 1), "note": "last byte of the tag flipped"},
    {"id": "truncated-tag", "private_hex": base["private_hex"], "input_base64": b64(raw[:-1]), "note": "one byte of the tag missing"},
    {"id": "truncated-to-header", "private_hex": base["private_hex"], "input_base64": b64(raw[:1 + 32]), "note": "no ciphertext and no tag"},
    {"id": "wrong-version", "private_hex": base["private_hex"], "input_base64": b64(bytes([0x02]) + raw[1:]), "note": "version byte 0x02"},
    {"id": "no-version", "private_hex": base["private_hex"], "input_base64": b64(raw[1:]), "note": "layout without the leading byte"},
    {"id": "wrong-info", "private_hex": base["private_hex"], "input_base64": b64(b"\x01" + wrong_info), "note": "sealed with a different HPKE info string"},
    {"id": "empty-input", "private_hex": base["private_hex"], "input_base64": "", "note": "empty string"},
    {"id": "not-base64", "private_hex": base["private_hex"], "input_base64": "@@@@", "note": "not Base64"},
]
cfrg = json.load(open(sys.argv[1])) if len(sys.argv) > 1 else None
os.makedirs(OUT, exist_ok=True)
with open(os.path.join(OUT, "cases.json"), "w") as f:
    json.dump({"recipe": r.RECIPE, "note": "Records to open, not outputs to reproduce: HPKE draws a fresh ephemeral key per record. An implementation must derive public_hex from private_hex and open record_base64. Case rfc9180-recipient uses the recipient key of the CFRG test vector in rfc9180.json.", "cases": cases}, f, indent=1, ensure_ascii=False)
    f.write("\n")
with open(os.path.join(OUT, "negative.json"), "w") as f:
    json.dump({"recipe": r.RECIPE, "note": "Every case must fail to open.", "cases": negative}, f, indent=1, ensure_ascii=False)
    f.write("\n")
if cfrg:
    v = [x for x in cfrg if x["mode"] == 0 and x["kem_id"] == 0x20 and x["kdf_id"] == 1 and x["aead_id"] == 2][0]
    keep = {k: v[k] for k in ("mode", "kem_id", "kdf_id", "aead_id", "info", "ikmE", "ikmR", "skEm", "skRm", "pkEm", "pkRm", "enc", "shared_secret", "key", "base_nonce")}
    keep["encryptions"] = v["encryptions"][:2]
    keep["source"] = "https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/master/test-vectors.json"
    with open(os.path.join(OUT, "rfc9180.json"), "w") as f:
        json.dump(keep, f, indent=1)
        f.write("\n")
print(f"wrote {len(cases)} cases and {len(negative)} negative cases to {OUT}")
