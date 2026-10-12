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

**Task.** The same as `pbe-record-pbkdf2-gcm-v1`: encrypt a short record with a password. This is the recipe to use when the platform has Argon2id; the PBKDF2 recipe exists for the platforms that do not.

**Key.** Argon2id (RFC 9106), 64 MiB memory, 3 passes, 1 lane, random 16-byte salt, 32-byte output, over the UTF-8 bytes of the password. These are the OWASP first-choice parameters; the memory cost is the one that must not be lowered.

**Cipher.** AES-256-GCM, random 12-byte nonce, 16-byte tag, no additional data. The scope first paired Argon2id with XAES-256-GCM. That was dropped on purpose: the salt is fresh for every record, so every derived key encrypts exactly one message, and the 12-byte random nonce of plain AES-GCM is already safe. XAES earns its place in `aead-record-v1`, where one key encrypts many records.

**Layout.** Base64 (standard alphabet, with padding) of

```
version (1 byte, 0x01) || salt (16) || nonce (12) || ciphertext || tag (16)
```

Same shape as the PBKDF2 recipe. The two are told apart by which recipe the application chose, not by the bytes; an application that must accept both wraps them in its own envelope.

**Vectors.** [`vectors/pbe-record-v1/`](vectors/pbe-record-v1/), generated by the Python implementation. Its Argon2id is OpenSSL's, checked against the RFC 9106 section 5.3 test vector by `tools/argon2_rfc9106_check.py`. The Go implementation is an independent Argon2id (x/crypto) and reproduces the vectors byte for byte, as does Node's.

**Implementations.**

| Language | File | Argon2id from |
|---|---|---|
| TypeScript | [`impl/typescript/pbe_record_v1.mjs`](impl/typescript/pbe_record_v1.mjs) | `node:crypto` (Node 26+; browsers have none) |
| Python | [`impl/python/pbe_record_v1.py`](impl/python/pbe_record_v1.py) | pyca/cryptography (OpenSSL 3.2+) |
| Go | [`impl/go/pbe_record_v1.go`](impl/go/pbe_record_v1.go) | `golang.org/x/crypto/argon2` |
| Swift, Java, Kotlin, C# | use `pbe-record-pbkdf2-gcm-v1` | CryptoKit, the JDK and .NET ship no Argon2. Adding libsodium or Bouncy Castle would make a recipe that is only as portable as that dependency; the PBKDF2 recipe is the honest answer until the platforms catch up. |

## hpke-envelope-v1, hpke-envelope-pq-v1

Planned. HPKE base mode (RFC 9180) with `DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, `AES-256-GCM`, info string `crypto-recipes/hpke-envelope-v1`. The post-quantum variant uses the hybrid X25519 + ML-KEM-768 KEM from the IETF draft current at the time of writing; the page will record the exact draft.

## sign-detached-v1

**Task.** Sign a message with a key you hold and let anyone with the public key check it: release artifacts, webhooks, tokens, audit records. The signature travels next to the message, not around it.

**Not for.** Encryption (nothing here hides the message), long-lived signatures that must survive a cryptographically relevant quantum computer (see `sign-detached-pq-v1`), or protocols that already define their own signing input (JWS, COSE, SSH, X.509); use those as they are.

**Keys.** Ed25519 (RFC 8032). The private key is the 32-byte seed; the public key is the 32-byte encoded point. Both are Base64 when transported. Libraries show the private key in several shapes: a 32-byte seed (CryptoKit, pyca), a 64-byte seed-plus-public (Go), or a PKCS#8 blob (JCA, WebCrypto). They are all the same key; store the seed and wrap it as the library needs. The two fixed DER prefixes for PKCS#8 and X.509 are in the TypeScript and Java files.

**Input.** The signed bytes are

```
"crypto-recipes/sign-detached-v1" || 0x00 || message
```

A signature made for this recipe therefore means nothing to another protocol that signs raw bytes with the same key, and a raw signature from elsewhere does not pass here. The negative case `no-domain-separation` is a plain Ed25519 signature over the message; an implementation that accepts it forgot the prefix.

**Signature.** The 64 raw Ed25519 bytes, Base64. Verification fails, by exception rather than by a boolean a caller might ignore, for anything that is not exactly 64 bytes.

**Vectors.** [`vectors/sign-detached-v1/`](vectors/sign-detached-v1/). Every implementation must derive the vector's public key from its seed and must verify the vector's signature. RFC 8032 signing is deterministic, so Python, TypeScript, Go and Java also reproduce the signatures byte for byte. CryptoKit does not: Apple randomizes Ed25519 signing, which is permitted and verifies everywhere, so the Swift harness checks that its own signatures verify instead of comparing bytes. Case `rfc8032-key-1` uses the first key pair of RFC 8032 section 7.1.

**Implementations.**

| Language | File | Ed25519 from |
|---|---|---|
| Swift | [`impl/swift/Sources/Recipes/SignDetachedV1.swift`](impl/swift/Sources/Recipes/SignDetachedV1.swift) | CryptoKit (randomized signatures) |
| TypeScript | [`impl/typescript/sign_detached_v1.mjs`](impl/typescript/sign_detached_v1.mjs) | WebCrypto, Node 20+ and current browsers |
| Python | [`impl/python/sign_detached_v1.py`](impl/python/sign_detached_v1.py) | pyca/cryptography |
| Go | [`impl/go/sign_detached_v1.go`](impl/go/sign_detached_v1.go) | `crypto/ed25519` |
| Java, Kotlin | [`impl/java/SignDetachedV1.java`](impl/java/SignDetachedV1.java) | JCA, Java 15+, Android API 33+; the JDK does not expose the public half of a private key, so the pair is regenerated from the seed |
| C# | none | `System.Security.Cryptography` has no Ed25519 as of .NET 10. Verifying with a dependency-free .NET is not possible; NSec (libsodium) or Bouncy Castle are the usual choices, and a .NET service that only needs to verify can also be handed ML-DSA signatures instead once `sign-detached-pq-v1` exists. |

## sign-detached-pq-v1

**Task.** The same as `sign-detached-v1`, for signatures that must still hold once a cryptographically relevant quantum computer exists: software releases, firmware, documents with a long life, anything a verifier might check in 2040. Conservative deployments carry both an Ed25519 and an ML-DSA signature and require both; this recipe is the second half of that pair.

**Not for.** Anything with tight size limits. An ML-DSA-65 public key is 1952 bytes and a signature is 3309, against 32 and 64 for Ed25519.

**Keys.** ML-DSA-65 (FIPS 204). The scope said ML-DSA-44; 65 is the set every platform that ships ML-DSA has in common (CryptoKit offers 65 and 87 only) and the one most guidance picks as the default. The private key is the 32-byte seed; the public key is the 1952-byte FIPS 204 encoding. Both are Base64 when transported. All six platforms rebuild the same key pair from the seed, which was checked by deriving the public key for one fixed seed on each of them. Two fixed DER wrappers appear in the files: the PKCS#8 form of a seed is the 22-byte prefix `3034020100300b060960864801650304031204228020` followed by the seed, and the X.509 form of a public key is `308207b2300b0609608648016503040312038207a100` followed by the 1952 bytes. The JDK and Node produce and accept exactly these.

**Input.** The signed bytes are

```
"crypto-recipes/sign-detached-pq-v1" || 0x00 || message
```

with an empty FIPS 204 context string. FIPS 204 has a context parameter made for this purpose, and Node, pyca, Go, CryptoKit and .NET expose it; the JDK does not as of Java 27. A prefix in the message works everywhere and is checked by the negative case `prefix-as-context`, which is the raw message signed with the recipe name as the context string and must not verify.

**Signature.** The 3309 raw bytes, Base64. ML-DSA signing is randomized by default on every platform here (Go also offers a deterministic mode), so two signatures of one message differ and both verify. Verification fails by exception for anything that is not exactly 3309 bytes.

**Vectors.** [`vectors/sign-detached-pq-v1/`](vectors/sign-detached-pq-v1/). Every implementation must derive the vector's public key from its seed and verify the vector's signature; its own signatures are checked by verification. Case `seed-07` uses the seed of 32 bytes `0x07`, the one used for the cross-platform key derivation check.

**Implementations.**

| Language | File | ML-DSA from |
|---|---|---|
| Swift | [`impl/swift/Sources/Recipes/SignDetachedPqV1.swift`](impl/swift/Sources/Recipes/SignDetachedPqV1.swift) | CryptoKit, macOS 26 and iOS 26 |
| TypeScript | [`impl/typescript/sign_detached_pq_v1.mjs`](impl/typescript/sign_detached_pq_v1.mjs) | `node:crypto`, Node 26; WebCrypto has no ML-DSA yet |
| Python | [`impl/python/sign_detached_pq_v1.py`](impl/python/sign_detached_pq_v1.py) | pyca/cryptography 46+ (OpenSSL 3.5) |
| Go | [`impl/go/sign_detached_pq_v1.go`](impl/go/sign_detached_pq_v1.go) | `crypto/mldsa`, Go 1.27 |
| Java, Kotlin | [`impl/java/SignDetachedPqV1.java`](impl/java/SignDetachedPqV1.java) | JCA, Java 24+ |
| C# | [`impl/csharp/SignDetachedPqV1.cs`](impl/csharp/SignDetachedPqV1.cs) | `System.Security.Cryptography.MLDsa`, .NET 10, Linux and Windows only |

## password-hash-v1

Planned. Argon2id in PHC string format, with a PBKDF2 profile for platforms without Argon2id.
