"""Recipe hpke-envelope-pq-v1: encrypt a short record to a recipient's public key, post-quantum hybrid.

Uses the `cryptography` package (47+ with OpenSSL 3.5+), and hashlib for SHAKE256.

Suite:  HPKE base mode with the KEM MLKEM768-X25519 (X-Wing, KEM id 0x647a, draft-ietf-hpke-pq), HKDF-SHA256,
        AES-256-GCM, single-shot, no additional data. A record stays confidential unless both ML-KEM-768 and X25519 fall.
Info:   "crypto-recipes/hpke-envelope-pq-v1".
Keys:   recipient private key is the 32-byte X-Wing seed; public key is ML-KEM-768 public key (1184) || X25519 point (32).
        pyca takes the two halves separately, so the seed is expanded as the draft says: SHAKE256(seed, 96) gives the
        64-byte ML-KEM seed and the 32-byte X25519 scalar.
Output: Base64 of  version (1 byte, 0x01) || enc (1120) || ciphertext || tag (16).
"""
import base64
import hashlib

from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519

RECIPE = "hpke-envelope-pq-v1"
VERSION = b"\x01"
INFO = b"crypto-recipes/hpke-envelope-pq-v1"
SEED_BYTES = 32
PUBLIC_BYTES = 1216
ENC_BYTES = 1120
TAG_BYTES = 16
_SUITE = hpke.Suite(hpke.KEM.MLKEM768_X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_256_GCM)


def _private(seed: bytes) -> hpke.MLKEM768X25519PrivateKey:
    if len(seed) != SEED_BYTES:
        raise ValueError("private key must be the 32-byte X-Wing seed")
    expanded = hashlib.shake_256(seed).digest(96)
    return hpke.MLKEM768X25519PrivateKey(mlkem.MLKEM768PrivateKey.from_seed_bytes(expanded[:64]),
                                         x25519.X25519PrivateKey.from_private_bytes(expanded[64:]))


def public_key(seed: bytes) -> bytes:
    if len(seed) != SEED_BYTES:
        raise ValueError("private key must be the 32-byte X-Wing seed")
    expanded = hashlib.shake_256(seed).digest(96)
    return (mlkem.MLKEM768PrivateKey.from_seed_bytes(expanded[:64]).public_key().public_bytes_raw()
            + x25519.X25519PrivateKey.from_private_bytes(expanded[64:]).public_key().public_bytes_raw())


def encrypt(public: bytes, plaintext: str) -> str:
    if len(public) != PUBLIC_BYTES:
        raise ValueError("public key must be 1216 bytes")
    pk = hpke.MLKEM768X25519PublicKey(mlkem.MLKEM768PublicKey.from_public_bytes(public[:1184]),
                                      x25519.X25519PublicKey.from_public_bytes(public[1184:]))
    return base64.b64encode(VERSION + _SUITE.encrypt(plaintext.encode("utf-8"), pk, INFO)).decode("ascii")


def decrypt(seed: bytes, text: str) -> str:
    data = base64.b64decode(text, validate=True)
    if len(data) < 1 + ENC_BYTES + TAG_BYTES or data[:1] != VERSION:
        raise ValueError("not an hpke-envelope-pq-v1 record")
    # A wrong key or any modification raises; there is never partial output.
    return _SUITE.decrypt(data[1:], _private(seed), INFO).decode("utf-8")
