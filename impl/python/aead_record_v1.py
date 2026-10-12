"""Recipe aead-record-v1: encrypt a short record with a 32-byte key you already have.

Uses the `cryptography` package, nothing else. Cipher is XAES-256-GCM (https://c2sp.org/XAES-256-GCM):
a 24-byte random nonce, from which a per-message AES-256-GCM key is derived with one block of
AES-CMAC, so random nonces are safe for any number of messages under one key.

Key:    32 bytes, from a KMS, a key store or a KDF; never a password (see pbe-record-v1).
Cipher: XAES-256-GCM, random 24-byte nonce, 16-byte tag, optional additional data (not stored).
Output: Base64 of  version (1 byte, 0x01) || nonce (24) || ciphertext || tag (16).
"""
import base64
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RECIPE = "aead-record-v1"
VERSION = b"\x01"
KEY_BYTES = 32
NONCE_BYTES = 24
TAG_BYTES = 16


def _aes_block(key: bytes, block: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def _xaes_subkey(key: bytes, nonce: bytes) -> tuple[bytes, bytes]:
    """Steps 1-6 of the XAES-256-GCM key derivation: returns (AES-256-GCM key, 12-byte nonce)."""
    l = int.from_bytes(_aes_block(key, bytes(16)), "big")
    k1 = (l << 1) & ((1 << 128) - 1)
    if l >> 127:
        k1 ^= 0x87
    k1 = k1.to_bytes(16, "big")
    m1 = b"\x00\x01X\x00" + nonce[:12]
    m2 = b"\x00\x02X\x00" + nonce[:12]
    kx = _aes_block(key, bytes(a ^ b for a, b in zip(m1, k1))) + _aes_block(key, bytes(a ^ b for a, b in zip(m2, k1)))
    return kx, nonce[12:]


def xaes_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    kx, nx = _xaes_subkey(key, nonce)
    return AESGCM(kx).encrypt(nx, plaintext, aad)


def xaes_open(key: bytes, nonce: bytes, sealed: bytes, aad: bytes) -> bytes:
    kx, nx = _xaes_subkey(key, nonce)
    return AESGCM(kx).decrypt(nx, sealed, aad)


def encrypt(key: bytes, plaintext: str, aad: str = "", nonce: bytes | None = None) -> str:
    if len(key) != KEY_BYTES:
        raise ValueError("key must be 32 bytes")
    nonce = os.urandom(NONCE_BYTES) if nonce is None else nonce
    if len(nonce) != NONCE_BYTES:
        raise ValueError("bad nonce length")
    sealed = xaes_seal(key, nonce, plaintext.encode("utf-8"), aad.encode("utf-8"))
    return base64.b64encode(VERSION + nonce + sealed).decode("ascii")


def decrypt(key: bytes, text: str, aad: str = "") -> str:
    if len(key) != KEY_BYTES:
        raise ValueError("key must be 32 bytes")
    data = base64.b64decode(text, validate=True)
    if len(data) < 1 + NONCE_BYTES + TAG_BYTES or data[:1] != VERSION:
        raise ValueError("not an aead-record-v1 record")
    # A wrong key, wrong additional data or any modification raises InvalidTag; there is never partial output.
    return xaes_open(key, data[1:1 + NONCE_BYTES], data[1 + NONCE_BYTES:], aad.encode("utf-8")).decode("utf-8")
