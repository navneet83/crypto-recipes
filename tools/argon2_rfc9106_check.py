"""Checks the Argon2id used by pbe-record-v1 against the RFC 9106 section 5.3 test vector (pyca/cryptography,
which is OpenSSL's Argon2), so the recipe's vectors rest on a published reference, not on one library agreeing with itself."""
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

tag = Argon2id(salt=bytes([2]) * 16, length=32, iterations=3, lanes=4, memory_cost=32,
               ad=bytes([4]) * 12, secret=bytes([3]) * 8).derive(bytes([1]) * 32)
expected = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
assert tag.hex() == expected, tag.hex()
print("argon2id: RFC 9106 section 5.3 vector OK")
