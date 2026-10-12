"""Recipe sign-detached-pq-v1: sign a message and verify the signature, post-quantum.

Uses the `cryptography` package (46+ with OpenSSL 3.5+), nothing else.

Keys:      ML-DSA-65 (FIPS 204). Private key is the 32-byte seed; public key is the 1952-byte encoding. Both Base64 when
           transported. Every platform rebuilds the same key pair from the seed, so the seed is the only thing to store;
           the PKCS#8 form of the seed is the fixed 22-byte prefix 3034020100300b060960864801650304031204228020 followed
           by the seed, and the X.509 form of the public key is 308207b2300b0609608648016503040312038207a100 followed by
           the 1952 bytes.
Input:     "crypto-recipes/sign-detached-pq-v1" || 0x00 || message, with an empty FIPS 204 context string. The prefix
           does what the context string would, and it also works on the platforms (the JDK, as of Java 27) that do not
           expose the context parameter.
Signature: the 3309 raw ML-DSA-65 bytes, Base64 (standard alphabet, with padding). ML-DSA signing is randomized by
           default, so two signatures of the same message differ and both verify.
"""
import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey, MLDSA65PublicKey

RECIPE = "sign-detached-pq-v1"
DOMAIN = b"crypto-recipes/sign-detached-pq-v1\x00"
SEED_BYTES = 32
PUBLIC_BYTES = 1952
SIGNATURE_BYTES = 3309


def public_key(seed: bytes) -> bytes:
    if len(seed) != SEED_BYTES:
        raise ValueError("seed must be 32 bytes")
    return MLDSA65PrivateKey.from_seed_bytes(seed).public_key().public_bytes_raw()


def sign(seed: bytes, message: str) -> str:
    if len(seed) != SEED_BYTES:
        raise ValueError("seed must be 32 bytes")
    return base64.b64encode(MLDSA65PrivateKey.from_seed_bytes(seed).sign(DOMAIN + message.encode("utf-8"))).decode("ascii")


def verify(public: bytes, message: str, signature: str) -> None:
    """Returns normally for a valid signature and raises for anything else; callers never get a boolean to ignore."""
    if len(public) != PUBLIC_BYTES:
        raise ValueError("public key must be 1952 bytes")
    sig = base64.b64decode(signature, validate=True)
    if len(sig) != SIGNATURE_BYTES:
        raise InvalidSignature("signature must be 3309 bytes")
    MLDSA65PublicKey.from_public_bytes(public).verify(sig, DOMAIN + message.encode("utf-8"))
