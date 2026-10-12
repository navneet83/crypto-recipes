# crypto-recipes

Cross-language cryptographic recipes, verified by test vectors.

Every platform ships good primitives now, and plenty of guides say which ones to use. What is missing is proof that the recipe built from those primitives in Swift produces bytes that the same recipe in Python or TypeScript can open, and the other way round. This repository is that proof: a few recipes for tasks application developers actually have, one reference implementation per language written only over that language's standard or audited cryptography, a frozen vector set per recipe, and a CI run that fails the moment any pair stops interoperating.

It is a test suite with worked examples, not a library to depend on. Copy the file for your language, or point your own implementation at the vectors.

## Recipes

| Recipe | What it does | Swift | TypeScript | Python | Java (and Kotlin) | C# | Go |
|---|---|---|---|---|---|---|---|
| [`pbe-record-pbkdf2-gcm-v1`](RECIPES.md#pbe-record-pbkdf2-gcm-v1) | encrypt a short record with a password (PBKDF2 + AES-256-GCM) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| [`aead-record-v1`](RECIPES.md#aead-record-v1) | encrypt a short record with a key you already have (XAES-256-GCM) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| [`pbe-record-v1`](RECIPES.md#pbe-record-v1) | encrypt a short record with a password (Argon2id + AES-256-GCM) | PBKDF2¹ | ✅ Node | ✅ | PBKDF2¹ | PBKDF2¹ | ✅ |
| `hpke-envelope-v1` | encrypt to a recipient's public key (RFC 9180, X25519) | planned | | | | | |
| `hpke-envelope-pq-v1` | same, hybrid X25519 + ML-KEM-768 | planned | | | | | |
| `sign-detached-v1` | sign and verify (Ed25519, then ML-DSA-65) | planned | | | | | |
| `password-hash-v1` | store and verify a password | planned | | | | | |

¹ No Argon2id in the platform's standard library. These platforms use `pbe-record-pbkdf2-gcm-v1`, which is the same recipe with PBKDF2; the two do not interoperate, and the recipe page explains the choice.

[RECIPES.md](RECIPES.md) has one page per recipe: what it is for, what it is not for, the exact layout, and the parameters that must not be lowered. [SCOPE.md](SCOPE.md) is the plan for version 1.

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

Every harness takes the same arguments: none to replay the vectors, `--list` to print the recipes it supports, `<recipe> --emit N FILE` to write random records, `<recipe> --consume FILE` to open another implementation's records. Needs Node 26+ (20+ without `pbe-record-v1`), Python 3.10+, Swift 5.9+, Go 1.26+, Java 22+ for the harness (the recipe classes run on 17+) and .NET 8+. CI runs the crosscheck on macOS and, without Swift, on Linux on every push.

## Rules

1. **No primitives.** Nothing in this repository implements a cipher, hash, KDF, KEM or signature. Every implementation calls the platform's standard library, or one named audited library listed in [CONTRIBUTING.md](CONTRIBUTING.md).
2. **A recipe identifier never changes meaning.** New parameters or a new layout get a new identifier. The old one stays as long as any implementation ships it.
3. **Negative vectors are part of conformance.** An implementation that returns plaintext for a tampered, truncated or wrong-password input does not pass.
4. **Existing formats win.** A recipe reuses a public specification where one exists and says so. Where none fits the task, it defines a minimal layout with a version byte and freezes it.

## Background

This repository replaces [Cross-platform-AES-encryption](https://github.com/navneet83/Cross-platform-AES-encryption) from 2014, which made the same cross-platform promise with the practice of its time (CBC without authentication, a truncated SHA-256 key). Nothing in that project ever checked that its four implementations agreed, so they drifted apart over the years. Vectors and CI are the fix.

## License

Apache-2.0. See [LICENSE](LICENSE).
