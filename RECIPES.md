# Recipes

One section per recipe identifier. A section is frozen once the first vectors are committed; later changes to parameters or layout get a new identifier.

## pbe-record-pbkdf2-gcm-v1

**Task.** Encrypt a short record (a token, a configuration value, a document up to a few megabytes) with a password, so that any of the implementations can decrypt it.

**Not for.** Files too large to hold in memory (use [age](https://age-encryption.org)), encrypting to someone else's public key (see `hpke-envelope-v1`), or storing passwords for login (see `password-hash-v1`). If you must interoperate with code you do not control, JWE with `PBES2-HS256+A128KW` and `A256GCM` is the standard; this recipe is the smaller choice when both ends are yours.

**Key.** PBKDF2-HMAC-SHA256, 600,000 iterations, random 16-byte salt, 32-byte output, over the UTF-8 bytes of the password. The iteration count is the 2023 OWASP figure and is the floor, not a tunable.

**Cipher.** AES-256-GCM, random 12-byte nonce, 16-byte tag, no additional authenticated data.

**Layout.** Base64 (standard alphabet, with padding) of

```
version (1 byte, 0x01) || salt (16) || nonce (12) || ciphertext || tag (16)
```

A decoder rejects anything shorter than 45 bytes or with a different first byte before it derives a key.

**Limits.** With a random 12-byte nonce and a fresh salt per message, the per-key message count is one, so nonce reuse is not a concern. The salt and nonce are not secret. There is no key commitment: a ciphertext may decrypt under two different passwords to two different plaintexts, which does not matter for this task.

**Vectors.** [`vectors/pbe-record-pbkdf2-gcm-v1/`](vectors/pbe-record-pbkdf2-gcm-v1/). The fixed salt and nonce in `cases.json` exist only to make the output reproducible. Real encryptions use random ones; the optional salt and nonce parameters on `encrypt` exist only so the harness can replay the vectors.

**Implementations.**

| Language | File | Primitives from |
|---|---|---|
| Swift | [`impl/swift/pbe_record_pbkdf2_gcm_v1.swift`](impl/swift/pbe_record_pbkdf2_gcm_v1.swift) | CryptoKit (AES-GCM), CommonCrypto (PBKDF2) |
| TypeScript | [`impl/typescript/pbe_record_pbkdf2_gcm_v1.mjs`](impl/typescript/pbe_record_pbkdf2_gcm_v1.mjs) | WebCrypto (browser and Node 20+) |
| Python | [`impl/python/pbe_record_pbkdf2_gcm_v1.py`](impl/python/pbe_record_pbkdf2_gcm_v1.py) | pyca/cryptography |

**Relation to `pbe-record-v1`.** This is the fallback profile: PBKDF2 where Argon2id is not in the allowed list, and plain AES-GCM where the XAES-256-GCM construction is more than a reader wants. The two recipes do not interoperate.

## pbe-record-v1

Planned. Argon2id (64 MiB, 3 iterations, 1 lane) and XAES-256-GCM (C2SP) with a 24-byte nonce. Layout `0x01 || salt (16) || nonce (24) || ciphertext || tag (16)`. The C2SP vectors are imported for the cipher.

## hpke-envelope-v1, hpke-envelope-pq-v1

Planned. HPKE base mode (RFC 9180) with `DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, `AES-256-GCM`, info string `cryptorecipes/hpke-envelope-v1`. The post-quantum variant uses the hybrid X25519 + ML-KEM-768 KEM from the IETF draft current at the time of writing; the page will record the exact draft.

## sign-detached-v1, sign-detached-pq-v1

Planned. Ed25519 and ML-DSA-44 detached signatures over `"cryptorecipes/sign-detached-v1" || 0x00 || message`.

## password-hash-v1

Planned. Argon2id in PHC string format, with a PBKDF2 profile for platforms without Argon2id.
