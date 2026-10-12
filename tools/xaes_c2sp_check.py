"""Checks the Python XAES-256-GCM core against the C2SP specification: the two published vectors
and the accumulated randomized test (SHAKE-128 stream, 10 000 iterations)."""
import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "impl", "python"))
from aead_record_v1 import xaes_seal, _xaes_subkey  # noqa: E402

kx, nx = _xaes_subkey(bytes([1]) * 32, b"ABCDEFGHIJKLMNOPQRSTUVWX")
assert kx.hex() == "c8612c9ed53fe43e8e005b828a1631a0bbcb6ab2f46514ec4f439fcfd0fa969b" and nx == b"MNOPQRSTUVWX"
assert xaes_seal(bytes([1]) * 32, b"ABCDEFGHIJKLMNOPQRSTUVWX", b"XAES-256-GCM", b"").hex() == "ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271"
kx, nx = _xaes_subkey(bytes([3]) * 32, b"ABCDEFGHIJKLMNOPQRSTUVWX")
assert kx.hex() == "e9c621d4cdd9b11b00a6427ad7e559aeedd66b3857646677748f8ca796cb3fd8"
assert xaes_seal(bytes([3]) * 32, b"ABCDEFGHIJKLMNOPQRSTUVWX", b"XAES-256-GCM", b"c2sp.org/XAES-256-GCM").hex() == "986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d"

iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 10_000
expected = {10_000: "e6b9edf2df6cec60c8cbd864e2211b597fb69a529160cd040d56c0c210081939",
            1_000_000: "2163ae1445985a30b60585ee67daa55674df06901b890593e824b8a7c885ab15"}[iterations]
# One SHAKE-128 instance read sequentially; hashlib has no streaming read, so read a large prefix and slice.
need = iterations * (32 + 24 + 1 + 255 + 1 + 255)
stream = hashlib.shake_128(b"").digest(need)
assert stream[:16].hex() == "7f9c2ba4e88f827d616045507605853e"
pos = 0
def take(n):
    global pos
    out = stream[pos:pos + n]; pos += n; return out
acc = hashlib.shake_128()
for _ in range(iterations):
    key = take(32); nonce = take(24)
    plaintext = take(take(1)[0]); aad = take(take(1)[0])
    acc.update(xaes_seal(key, nonce, plaintext, aad))
got = acc.hexdigest(32)
assert got == expected, got
print(f"xaes: C2SP vectors and the {iterations}-iteration accumulated test OK")
