# crypto-recipes

A record encrypted in Swift should open in Go, and a record sealed from Python to an X-Wing post-quantum public key should open on an iPhone. Each recipe here is one small file per language, built only on that platform's standard cryptography, with frozen test vectors and a CI job that makes every implementation open every other implementation's output. Copy the file you need, or point your own code at the vectors.

There is no library and no package to install. A file you copy brings no new dependency, and CI has already checked it against the other five languages.

## Recipes

| Recipe | What it does | Swift | TypeScript | Python | Java (and Kotlin) | C# | Go |
|---|---|---|---|---|---|---|---|
| [`pbe-record-pbkdf2-gcm-v1`](RECIPES.md#pbe-record-pbkdf2-gcm-v1) | encrypt a short record with a password (PBKDF2 + AES-256-GCM) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| [`aead-record-v1`](RECIPES.md#aead-record-v1) | encrypt a short record with a key you already have (XAES-256-GCM) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| [`pbe-record-v1`](RECIPES.md#pbe-record-v1) | encrypt a short record with a password (Argon2id + AES-256-GCM) | PBKDF2¹ | ✅ Node | ✅ | PBKDF2¹ | PBKDF2¹ | ✅ |
| [`hpke-envelope-v1`](RECIPES.md#hpke-envelope-v1) | encrypt to a recipient's public key (HPKE, X25519) | ✅ | ✅ | ✅ | ✅ Java 26 | none⁴ | ✅ |
| [`hpke-envelope-pq-v1`](RECIPES.md#hpke-envelope-pq-v1) | the same, post-quantum hybrid (X-Wing) | ✅ macOS 26 | ✅ Node | ✅ | none⁵ | none⁴ | ✅ |
| [`sign-detached-v1`](RECIPES.md#sign-detached-v1) | sign a message and verify the signature (Ed25519) | ✅ | ✅ | ✅ | ✅ | none² | ✅ |
| [`sign-detached-pq-v1`](RECIPES.md#sign-detached-pq-v1) | the same, post-quantum (ML-DSA-65) | ✅ macOS 26 | ✅ Node | ✅ | ✅ Java 24 | ✅ Linux/Windows³ | ✅ |
| `password-hash-v1` | store and verify a password | planned | | | | | |

¹ No Argon2id in the platform's standard library. These platforms use `pbe-record-pbkdf2-gcm-v1`, which is the same recipe with PBKDF2; the two do not interoperate, and the recipe page explains the choice.
² .NET has no Ed25519 in `System.Security.Cryptography`; the recipe page says what to do.
³ .NET 10 enables ML-DSA on Linux with OpenSSL 3.5+ and on Windows, not on macOS. Ubuntu runners still ship OpenSSL 3.0, so CI checks the C# file in the Alpine 3.24 .NET image, against the vectors only.
⁴ .NET has no X25519, so it cannot take part in X25519 HPKE.
⁵ The JDK's HPKE has no hybrid KEMs and its SHAKE256 output is fixed at 64 bytes, so Java cannot build X-Wing without a library.

[RECIPES.md](RECIPES.md) has one page per recipe: what it is for, what it is not for, the exact byte layout, and the parameters that must not be lowered.

## How it is tested

- Where an upstream specification publishes vectors, the recipe uses them. XAES-256-GCM passes the C2SP vectors and the specification's accumulated test at one million iterations. Argon2id is checked against RFC 9106. HPKE is checked against the CFRG vectors for RFC 9180, and the X-Wing hybrid against the vectors from both the X-Wing and the HPKE post-quantum drafts. Ed25519 uses the RFC 8032 key.
- Each recipe has frozen vectors. Deterministic recipes must reproduce the expected output byte for byte. Randomized ones, such as HPKE and ML-DSA, must open or verify the stored records and have their own output checked by the others.
- Every recipe has 10 to 15 inputs that must fail: flipped bits in each field, truncation, a wrong key, a missing version byte, a signature without the domain prefix, a classical record handed to the post-quantum recipe. An implementation that returns plaintext for any of them fails CI.
- On every push, each implementation writes 30 random records per recipe and every other implementation opens them: 172 pairs on macOS, and the same without Swift on Linux. The C# post-quantum file runs in a separate container, because .NET only enables ML-DSA with OpenSSL 3.5.

Two files assemble a construction instead of calling one: the Node HPKE and X-Wing recipes, because Node has neither. They use only Node's own primitives and are checked against the upstream vectors at every intermediate value, not only the final output.

## Why not Tink, libsodium or age?

Use them if you can. [Tink](https://github.com/tink-crypto/tink) covers several languages with its own interop tests, [libsodium](https://libsodium.org) has bindings everywhere, and [age](https://age-encryption.org) is the answer for files. All three are dependencies, though, and each defines its own formats. This repository is for the case where you cannot add one: an iOS app that should only use CryptoKit, a browser that only has WebCrypto, a backend team that will not take a new crypto library. In that case you need the exact bytes each platform's own API produces and proof that the other side can read them.

## Platform gaps

These turned up while making six standard libraries agree. Each one is documented on the recipe page where it applies.

- CryptoKit randomizes Ed25519 signatures. RFC 8032 signing is deterministic, and every other platform here reproduces the vectors exactly, so Swift is checked by verification instead.
- The JDK cannot give you the public half of an Ed25519, X25519 or ML-DSA private key. The files rebuild the key pair from the seed.
- The JDK's SHAKE256 always returns 64 bytes, so Java cannot expand an X-Wing seed and has no post-quantum HPKE here.
- .NET 10 turns off ML-DSA on macOS and on Ubuntu's OpenSSL 3.0, and has no Ed25519 or X25519 at all.
- CryptoKit has ML-DSA-65 and 87 but not 44, which is why the signing recipe uses 65.
- WebCrypto has no ML-KEM, ML-DSA or Argon2id, so the post-quantum and Argon2id recipes run in Node 26 but not in browsers.

## Layout

```
impl/<language>/<recipe>.<ext>   one file per recipe and language, plus a harness
vectors/<recipe>/cases.json      inputs with fixed salt and nonce, and the expected output
vectors/<recipe>/negative.json   inputs that every implementation must refuse
tools/                           vector generators and the C2SP conformance check
```

## Running the checks

Each harness replays the vectors, then fails on any mismatch. The cross-language check has every implementation emit random records and every other implementation open them.

```sh
python3 -m venv .venv && .venv/bin/pip install cryptography
sh tools/crosscheck.sh          # all six harnesses, then every pair
```

Or one language at a time:

```sh
.venv/bin/python impl/python/harness.py
node impl/typescript/harness.mjs
(cd impl/swift && swift run harness)
(cd impl/go && go run .)
java -Drecipes.root=. impl/java/Harness.java
RECIPES_ROOT=. dotnet run --project impl/csharp
```

Every harness takes the same arguments: none to replay the vectors, `--list` to print the recipes it supports, `<recipe> --emit N FILE` to write random records, `<recipe> --consume FILE` to open another implementation's records. Needs Node 26+ (20+ without the Argon2id and ML-DSA recipes), Python 3.10+, Swift 5.9+, Go 1.27+, Java 26+ for the harness (most recipe classes run on 17+) and .NET 8+. CI runs the crosscheck on macOS and, without Swift, on Linux on every push.

## Rules

1. **No primitives.** Nothing in this repository implements a cipher, hash, KDF, KEM or signature. Every implementation calls the platform's standard library, or one named audited library listed in [CONTRIBUTING.md](CONTRIBUTING.md).
2. **A recipe identifier never changes meaning.** New parameters or a new layout get a new identifier. The old one stays as long as any implementation ships it.
3. **Negative vectors are part of conformance.** An implementation that returns plaintext for a tampered, truncated or wrong-password input does not pass.
4. **Existing formats win.** A recipe reuses a public specification where one exists and says so. Where none fits the task, it defines a minimal layout with a version byte and freezes it.

## Status

Seven recipes work today; `password-hash-v1` (Argon2id in PHC format) is next, then Rust. Recipe identifiers and vectors are frozen once published. The post-quantum HPKE recipe follows an Internet-Draft, and if a later draft changes its bytes it gets a new identifier. Nothing here has had an independent review yet, and review of the recipe pages is the most useful contribution.

## Background

This repository replaces [Cross-platform-AES-encryption](https://github.com/navneet83/Cross-platform-AES-encryption) from 2014, which made the same cross-platform promise with the practice of its time (CBC without authentication, a truncated SHA-256 key). Nothing in that project ever checked that its four implementations agreed, so they drifted apart over the years. Vectors and CI are the fix.

## License

Apache-2.0. See [LICENSE](LICENSE).
