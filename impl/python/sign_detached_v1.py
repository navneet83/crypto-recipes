"""Recipe sign-detached-v1: sign a message and verify the signature.

Uses the `cryptography` package, nothing else.

Keys:      Ed25519 (RFC 8032). Private key is the 32-byte seed, public key is the 32-byte point, both Base64 when
           transported. Keep the seed; the expanded or PKCS#8 forms some libraries produce are derived from it.
Input:     "crypto-recipes/sign-detached-v1" || 0x00 || message. The prefix stops a signature made for this recipe
           from meaning anything in another protocol that signs raw bytes with the same key, and the other way round.
Signature: the 64 raw Ed25519 bytes, Base64 (standard alphabet, with padding). Nothing else is encoded: the public key
           and the message travel separately, which is what "detached" means.
"""
import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

RECIPE = "sign-detached-v1"
DOMAIN = b"crypto-recipes/sign-detached-v1\x00"
SEED_BYTES = 32
PUBLIC_BYTES = 32
SIGNATURE_BYTES = 64


def public_key(seed: bytes) -> bytes:
    if len(seed) != SEED_BYTES:
        raise ValueError("seed must be 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()


def sign(seed: bytes, message: str) -> str:
    if len(seed) != SEED_BYTES:
        raise ValueError("seed must be 32 bytes")
    return base64.b64encode(Ed25519PrivateKey.from_private_bytes(seed).sign(DOMAIN + message.encode("utf-8"))).decode("ascii")


def verify(public: bytes, message: str, signature: str) -> None:
    """Returns normally for a valid signature and raises for anything else; callers never get a boolean to ignore."""
    if len(public) != PUBLIC_BYTES:
        raise ValueError("public key must be 32 bytes")
    sig = base64.b64decode(signature, validate=True)
    if len(sig) != SIGNATURE_BYTES:
        raise InvalidSignature("signature must be 64 bytes")
    Ed25519PublicKey.from_public_bytes(public).verify(sig, DOMAIN + message.encode("utf-8"))
