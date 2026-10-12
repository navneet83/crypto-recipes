"""Recipe pbe-record-pbkdf2-gcm-v1: encrypt a short record with a password.

Uses the `cryptography` package (pip install cryptography), nothing else.

Key:    PBKDF2-HMAC-SHA256, 600000 iterations, random 16-byte salt, over the UTF-8 bytes of the password.
Cipher: AES-256-GCM, random 12-byte nonce, 16-byte tag, no additional data.
Output: Base64 of  version (1 byte, 0x01) || salt (16) || nonce (12) || ciphertext || tag (16).
This is the fallback profile of recipe R1; see RECIPES.md for the Argon2id and XAES-256-GCM profiles.
"""
import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

RECIPE = "pbe-record-pbkdf2-gcm-v1"
VERSION = b"\x01"
ITERATIONS = 600000
SALT_BYTES = 16
NONCE_BYTES = 12
TAG_BYTES = 16


def _derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS).derive(password.encode("utf-8"))


def encrypt(password: str, plaintext: str, salt: bytes | None = None, nonce: bytes | None = None) -> str:
    salt = os.urandom(SALT_BYTES) if salt is None else salt
    nonce = os.urandom(NONCE_BYTES) if nonce is None else nonce
    if len(salt) != SALT_BYTES or len(nonce) != NONCE_BYTES:
        raise ValueError("bad salt or nonce length")
    sealed = AESGCM(_derive_key(password, salt)).encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(VERSION + salt + nonce + sealed).decode("ascii")


def decrypt(password: str, text: str) -> str:
    data = base64.b64decode(text, validate=True)
    if len(data) < 1 + SALT_BYTES + NONCE_BYTES + TAG_BYTES or data[:1] != VERSION:
        raise ValueError("not a pbe-record-pbkdf2-gcm-v1 record")
    salt = data[1:1 + SALT_BYTES]
    nonce = data[1 + SALT_BYTES:1 + SALT_BYTES + NONCE_BYTES]
    sealed = data[1 + SALT_BYTES + NONCE_BYTES:]
    # A wrong password or any modification raises InvalidTag; there is never partial output.
    return AESGCM(_derive_key(password, salt)).decrypt(nonce, sealed, None).decode("utf-8")
