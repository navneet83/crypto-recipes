"""Generates the vectors for hpke-envelope-pq-v1 with the Python implementation.

HPKE encryption draws a fresh ephemeral key that none of the native APIs let a caller fix, so cases.json holds
records to open, not outputs to reproduce: an implementation must derive public_hex from private_hex, open
record_base64, and have its own records opened by the others. rfc9180.json is the one CFRG test vector for this
suite (base mode, X25519, HKDF-SHA256, AES-256-GCM); implementations that assemble HPKE from parts check against it."""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "impl", "python"))
import hpke_envelope_pq_v1 as r  # noqa: E402

HERE = os.path.dirname(__file__)
OUT = os.path.join(HERE, "..", "vectors", r.RECIPE)
inputs = [
    ("draft-recipient", "b6bfa0299b955e85224df2e468f29eeab377ff3b96d4462b39447a22d32b91be", "The quick brown fox jumps over the lazy dog"),
    ("empty-plaintext", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", ""),
    ("unicode", "a0" * 32, "plaintext with ünïcödé and emoji 🔐 and a newline\n"),
    ("long", "deadbeef" * 8, "x" * 10_000),
]
cases = []
for cid, priv, pt in inputs:
    pub = r.public_key(bytes.fromhex(priv))
    cases.append({"id": cid, "private_hex": priv, "public_hex": pub.hex(), "plaintext": pt, "record_base64": r.encrypt(pub, pt)})
assert cases[0]["public_hex"].startswith("d3d102410970b8bab2984008669914490c95dea2c2ae331ca229aaf3609a")  # pkRm of the draft vector

base = cases[0]
raw = bytearray(base64.b64decode(base["record_base64"]))
def b64(b): return base64.b64encode(bytes(b)).decode()
def flipped(i):
    x = bytearray(raw); x[i] ^= 0x01; return b64(x)
other_record = r.encrypt(bytes.fromhex(cases[2]["public_hex"]), base["plaintext"])
from cryptography.hazmat.primitives import hpke  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519  # noqa: E402
_pub = bytes.fromhex(base["public_hex"])
wrong_info = hpke.Suite(hpke.KEM.MLKEM768_X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_256_GCM).encrypt(
    base["plaintext"].encode(), hpke.MLKEM768X25519PublicKey(mlkem.MLKEM768PublicKey.from_public_bytes(_pub[:1184]), x25519.X25519PublicKey.from_public_bytes(_pub[1184:])), b"crypto-recipes/hpke-envelope-pq-v2")
# A classical-only record: the same plaintext sealed with hpke-envelope-v1 to an X25519 key; must not open here.
import hpke_envelope_v1  # noqa: E402
classical = hpke_envelope_v1.encrypt(hpke_envelope_v1.public_key(bytes.fromhex(base["private_hex"])), base["plaintext"])
negative = [
    {"id": "wrong-recipient", "private_hex": cases[2]["private_hex"], "input_base64": base["record_base64"], "note": "opened with a different recipient's private key"},
    {"id": "sealed-to-other", "private_hex": base["private_hex"], "input_base64": other_record, "note": "a record sealed to a different public key"},
    {"id": "enc-flipped", "private_hex": base["private_hex"], "input_base64": flipped(1), "note": "first byte of the encapsulated key flipped"},
    {"id": "mlkem-ct-flipped", "private_hex": base["private_hex"], "input_base64": flipped(500), "note": "a byte inside the ML-KEM ciphertext flipped"},
    {"id": "x25519-ct-flipped", "private_hex": base["private_hex"], "input_base64": flipped(1 + 1088), "note": "first byte of the X25519 half of enc flipped"},
    {"id": "classical-record", "private_hex": base["private_hex"], "input_base64": classical, "note": "an hpke-envelope-v1 record for the same seed used as an X25519 key"},
    {"id": "ciphertext-flipped", "private_hex": base["private_hex"], "input_base64": flipped(1 + 1120), "note": "first ciphertext byte flipped"},
    {"id": "tag-flipped", "private_hex": base["private_hex"], "input_base64": flipped(len(raw) - 1), "note": "last byte of the tag flipped"},
    {"id": "truncated-tag", "private_hex": base["private_hex"], "input_base64": b64(raw[:-1]), "note": "one byte of the tag missing"},
    {"id": "truncated-to-header", "private_hex": base["private_hex"], "input_base64": b64(raw[:1 + 1120]), "note": "no ciphertext and no tag"},
    {"id": "wrong-version", "private_hex": base["private_hex"], "input_base64": b64(bytes([0x02]) + raw[1:]), "note": "version byte 0x02"},
    {"id": "no-version", "private_hex": base["private_hex"], "input_base64": b64(raw[1:]), "note": "layout without the leading byte"},
    {"id": "wrong-info", "private_hex": base["private_hex"], "input_base64": b64(b"\x01" + wrong_info), "note": "sealed with a different HPKE info string"},
    {"id": "empty-input", "private_hex": base["private_hex"], "input_base64": "", "note": "empty string"},
    {"id": "not-base64", "private_hex": base["private_hex"], "input_base64": "@@@@", "note": "not Base64"},
]
cfrg = json.load(open(sys.argv[1])) if len(sys.argv) > 1 else None
os.makedirs(OUT, exist_ok=True)
with open(os.path.join(OUT, "cases.json"), "w") as f:
    json.dump({"recipe": r.RECIPE, "note": "Records to open, not outputs to reproduce: HPKE draws fresh encapsulation randomness per record. An implementation must derive public_hex from the 32-byte X-Wing seed in private_hex and open record_base64. Case draft-recipient uses the recipient key of the draft-ietf-hpke-pq test vector in draft-hpke-pq.json.", "cases": cases}, f, indent=1, ensure_ascii=False)
    f.write("\n")
with open(os.path.join(OUT, "negative.json"), "w") as f:
    json.dump({"recipe": r.RECIPE, "note": "Every case must fail to open.", "cases": negative}, f, indent=1, ensure_ascii=False)
    f.write("\n")
if cfrg:
    # The draft has no MLKEM768-X25519 vector with AES-256-GCM. The HKDF-SHA256 + ChaCha20-Poly1305 one checks the
    # KEM (key expansion, decapsulation, shared secret) and the key schedule, which do not depend on the AEAD beyond its id.
    v = [x for x in cfrg if x["mode"] == 0 and x["kem_id"] == 0x647a and x["kdf_id"] == 1 and x["aead_id"] == 3][0]
    keep = {k: v[k] for k in ("mode", "kem_id", "kdf_id", "aead_id", "suite_id", "info", "ikmR", "skRm", "pkRm", "enc", "shared_secret", "key", "base_nonce")}
    keep["encryptions"] = v["encryptions"][:2]
    keep["source"] = "https://github.com/hpkewg/hpke-pq/blob/main/test-vectors.json"
    with open(os.path.join(OUT, "draft-hpke-pq.json"), "w") as f:
        json.dump(keep, f, indent=1)
        f.write("\n")
print(f"wrote {len(cases)} cases and {len(negative)} negative cases to {OUT}")
