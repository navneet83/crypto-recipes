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
| Swift | [`impl/swift/Sources/Recipes/PbeRecordPbkdf2GcmV1.swift`](impl/swift/Sources/Recipes/PbeRecordPbkdf2GcmV1.swift) | CryptoKit (AES-GCM), CommonCrypto (PBKDF2) |
| TypeScript | [`impl/typescript/pbe_record_pbkdf2_gcm_v1.mjs`](impl/typescript/pbe_record_pbkdf2_gcm_v1.mjs) | WebCrypto (browser and Node 20+) |
| Python | [`impl/python/pbe_record_pbkdf2_gcm_v1.py`](impl/python/pbe_record_pbkdf2_gcm_v1.py) | pyca/cryptography |
| Go | [`impl/go/pbe_record_pbkdf2_gcm_v1.go`](impl/go/pbe_record_pbkdf2_gcm_v1.go) | standard library (`crypto/pbkdf2` needs Go 1.24; older Go uses `golang.org/x/crypto/pbkdf2`) |
| Java, Kotlin | [`impl/java/PbeRecordPbkdf2GcmV1.java`](impl/java/PbeRecordPbkdf2GcmV1.java) | JCA (`javax.crypto`), Java 17+ and Android API 26+ |
| C# | [`impl/csharp/PbeRecordPbkdf2GcmV1.cs`](impl/csharp/PbeRecordPbkdf2GcmV1.cs) | `System.Security.Cryptography`, .NET 6+ |

**Relation to `pbe-record-v1`.** This is the fallback profile: PBKDF2 where Argon2id is not in the allowed list, and plain AES-GCM where the XAES-256-GCM construction is more than a reader wants. The two recipes do not interoperate.

## aead-record-v1

**Task.** Encrypt a short record with a 32-byte key you already have, from a KMS, a key store or a key derivation step, so that any of the implementations can decrypt it. Optional additional data binds the record to a context (a tenant, a column name, a header) without being stored in it.

**Not for.** Passwords (see `pbe-record-pbkdf2-gcm-v1` and `pbe-record-v1`), files too large to hold in memory, or anything that needs the ciphertext to commit to the key.

**Cipher.** XAES-256-GCM as specified at [c2sp.org/XAES-256-GCM](https://c2sp.org/XAES-256-GCM): a 24-byte random nonce; the first 12 bytes and the key go through one block of AES-CMAC (NIST SP 800-108r1 counter mode) to derive a per-message AES-256-GCM key; the last 12 bytes are the GCM nonce. The point of the construction is that random nonces are safe under one key for any number of messages you will ever send, which plain AES-GCM's 12-byte nonce cannot promise. Tag 16 bytes.

**Layout.** Base64 (standard alphabet, with padding) of

```
version (1 byte, 0x01) || nonce (24) || ciphertext || tag (16)
```

A decoder rejects anything shorter than 41 bytes or with a different first byte before it touches the key.

**Limits.** Not nonce misuse resistant and not key committing, same as AES-GCM. The additional data is authenticated but not stored; the reader has to know it.

**Vectors.** [`vectors/aead-record-v1/`](vectors/aead-record-v1/). Cases `c2sp-1` and `c2sp-2` wrap the two vectors from the specification, so bytes 25 onward of the decoded output are the published ciphertexts. The Python implementation, which generates the vectors, also passes the specification's accumulated randomized test for 10,000 and 1,000,000 iterations (`tools/xaes_c2sp_check.py`). The other implementations are checked by reproducing the vectors byte for byte and by the cross-language round trip.

**Implementations.** Each one builds the key derivation from the platform's AES block operation and uses the platform's AES-GCM.

| Language | File | AES block from |
|---|---|---|
| Swift | [`impl/swift/Sources/Recipes/AeadRecordV1.swift`](impl/swift/Sources/Recipes/AeadRecordV1.swift) | CommonCrypto ECB; GCM from CryptoKit |
| TypeScript | [`impl/typescript/aead_record_v1.mjs`](impl/typescript/aead_record_v1.mjs) | WebCrypto AES-CBC with a zero IV, first block kept |
| Python | [`impl/python/aead_record_v1.py`](impl/python/aead_record_v1.py) | pyca/cryptography ECB |
| Go | [`impl/go/aead_record_v1.go`](impl/go/aead_record_v1.go) | `crypto/aes` block |
| Java, Kotlin | [`impl/java/AeadRecordV1.java`](impl/java/AeadRecordV1.java) | JCA `AES/ECB/NoPadding` |
| C# | [`impl/csharp/AeadRecordV1.cs`](impl/csharp/AeadRecordV1.cs) | `Aes.EncryptEcb` |

## pbe-record-v1

Planned. Argon2id (64 MiB, 3 iterations, 1 lane) and XAES-256-GCM (C2SP) with a 24-byte nonce. Layout `0x01 || salt (16) || nonce (24) || ciphertext || tag (16)`. The C2SP vectors are imported for the cipher.

## hpke-envelope-v1, hpke-envelope-pq-v1

Planned. HPKE base mode (RFC 9180) with `DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, `AES-256-GCM`, info string `crypto-recipes/hpke-envelope-v1`. The post-quantum variant uses the hybrid X25519 + ML-KEM-768 KEM from the IETF draft current at the time of writing; the page will record the exact draft.

## sign-detached-v1, sign-detached-pq-v1

Planned. Ed25519 and ML-DSA-44 detached signatures over `"crypto-recipes/sign-detached-v1" || 0x00 || message`.

## password-hash-v1

Planned. Argon2id in PHC string format, with a PBKDF2 profile for platforms without Argon2id.
