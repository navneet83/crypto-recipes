"""Recipe hpke-envelope-v1: encrypt a short record to a recipient's public key.

Uses the `cryptography` package (47+), nothing else.

Suite:  HPKE (RFC 9180) base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, single-shot, no additional data.
Info:   "crypto-recipes/hpke-envelope-v1", which binds every record to this recipe.
Keys:   recipient private key is the 32-byte X25519 scalar, public key the 32-byte point, both Base64 when transported.
Output: Base64 of  version (1 byte, 0x01) || enc (32) || ciphertext || tag (16).
Every record uses a fresh ephemeral key, so two encryptions of one plaintext differ and both open.
"""
import base64

from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

RECIPE = "hpke-envelope-v1"
VERSION = b"\x01"
INFO = b"crypto-recipes/hpke-envelope-v1"
KEY_BYTES = 32
ENC_BYTES = 32
TAG_BYTES = 16
_SUITE = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_256_GCM)


def public_key(private: bytes) -> bytes:
    if len(private) != KEY_BYTES:
        raise ValueError("private key must be 32 bytes")
    return X25519PrivateKey.from_private_bytes(private).public_key().public_bytes_raw()


def encrypt(public: bytes, plaintext: str) -> str:
    if len(public) != KEY_BYTES:
        raise ValueError("public key must be 32 bytes")
    sealed = _SUITE.encrypt(plaintext.encode("utf-8"), X25519PublicKey.from_public_bytes(public), INFO)  # enc || ct || tag
    return base64.b64encode(VERSION + sealed).decode("ascii")


def decrypt(private: bytes, text: str) -> str:
    if len(private) != KEY_BYTES:
        raise ValueError("private key must be 32 bytes")
    data = base64.b64decode(text, validate=True)
    if len(data) < 1 + ENC_BYTES + TAG_BYTES or data[:1] != VERSION:
        raise ValueError("not an hpke-envelope-v1 record")
    # A wrong key or any modification raises; there is never partial output.
    return _SUITE.decrypt(data[1:], X25519PrivateKey.from_private_bytes(private), INFO).decode("utf-8")
