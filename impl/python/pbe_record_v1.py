"""Recipe pbe-record-v1: encrypt a short record with a password.

Uses the `cryptography` package (44+ with OpenSSL 3.2+ for Argon2id), nothing else.

Key:    Argon2id, 64 MiB memory, 3 passes, 1 lane, random 16-byte salt, 32-byte output, over the UTF-8 bytes of the password.
Cipher: AES-256-GCM, random 12-byte nonce, 16-byte tag, no additional data. The salt is fresh per record, so the
        derived key is used once and a 12-byte random nonce is safe; the extended-nonce cipher of aead-record-v1 is not needed.
Output: Base64 of  version (1 byte, 0x01) || salt (16) || nonce (12) || ciphertext || tag (16).
Platforms without Argon2id in their standard library use pbe-record-pbkdf2-gcm-v1 instead; the two do not interoperate.
"""
import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

RECIPE = "pbe-record-v1"
VERSION = b"\x01"
MEMORY_KIB = 64 * 1024
PASSES = 3
LANES = 1
SALT_BYTES = 16
NONCE_BYTES = 12
TAG_BYTES = 16


def _derive_key(password: str, salt: bytes) -> bytes:
    return Argon2id(salt=salt, length=32, iterations=PASSES, lanes=LANES, memory_cost=MEMORY_KIB).derive(password.encode("utf-8"))


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
        raise ValueError("not a pbe-record-v1 record")
    salt = data[1:1 + SALT_BYTES]
    nonce = data[1 + SALT_BYTES:1 + SALT_BYTES + NONCE_BYTES]
    # A wrong password or any modification raises InvalidTag; there is never partial output.
    return AESGCM(_derive_key(password, salt)).decrypt(nonce, data[1 + SALT_BYTES + NONCE_BYTES:], None).decode("utf-8")
