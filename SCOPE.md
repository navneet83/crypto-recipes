# Cross-language cryptographic recipes, verified by vectors: scope for version 1

Working name: `cryptorecipes` (alternatives: `interop-recipes`, `vectorbook`). Status: draft scope, 2026-10-12, reweighted the same day toward the current recipes (hybrid post-quantum HPKE, XAES-256-GCM, ML-DSA) after the question "are these cutting edge".

## 1. The one-paragraph pitch

Every platform now ships good primitives, and every "right answers" list tells developers which ones to use. What nobody provides is proof that the recipe built from those primitives in Swift produces bytes that the same recipe in Java, C#, TypeScript, Python and Go can open, and the other way round. This repository is that proof: a small set of recipes for the tasks application developers actually have, one reference implementation per language written only over that language's standard or audited cryptography, a frozen vector set per recipe, and a CI matrix that fails the moment any pair stops interoperating. It is a test suite with worked examples, not a library to depend on; copy the file for your language, or point your own implementation at the vectors.

## 2. Goals

1. For each recipe, implementations in six languages produce identical output for the vector inputs and open each other's output for random inputs, checked in CI on every change.
2. Zero cryptographic primitives implemented in this repository. Every implementation calls the platform's standard library, or one named audited library where the platform lacks the primitive. The allowed list per language is part of the repository and reviewed like code.
3. Each recipe reuses an existing public format where one exists, and says so. Where none exists for the task, the recipe defines a minimal layout with a version byte and freezes it.
4. Vectors include negative cases: tampered ciphertext, wrong password, truncation, swapped fields, each with the expected failure. An implementation that returns plaintext on any of them fails the suite.
5. Every recipe page states what it is for, what it is not for, and the parameters that must not be lowered.

## 3. Non-goals for version 1

- Not a library with a release cadence and a dependency to add. Files are meant to be copied or used as conformance references.
- No new primitives, no constant-time code, no field arithmetic, no KEM or signature implementations, ever.
- No streaming or chunked encryption of large files: there is no consensus format yet (age's STREAM is the nearest, and age itself is the answer for files). Version 1 covers records up to tens of megabytes held in memory.
- No key management: no key storage, rotation, escrow or hardware tokens. Each recipe takes keys or passwords as inputs.
- No case-insensitive, searchable or format-preserving encryption.
- No languages beyond the six in §5 until all six pass all recipes.

## 4. Recipes

Each recipe has an identifier that never changes meaning. A change to parameters or layout is a new recipe identifier; the old one stays in the suite as long as any implementation ships it.

### R1 `pbe-record-v1`: encrypt a short record with a password

- Key: Argon2id, 64 MiB memory, 3 iterations, 1 lane, 32-byte output, random 16-byte salt. Fallback profile `pbe-record-pbkdf2-v1` with PBKDF2-HMAC-SHA256 at 600,000 iterations for platforms without Argon2id in the allowed list; the two are distinct recipes and do not interoperate.
- Cipher: XAES-256-GCM (C2SP specification, 2024): a 24-byte random nonce, from which a per-message AES-256-GCM key is derived with AES-CMAC, so random nonces are safe at any message volume. Built from two primitives every platform has, AES-ECB for the CMAC step and AES-GCM; the C2SP vectors are imported. Fallback profile `pbe-record-gcm-v1` with plain AES-256-GCM and a 12-byte nonce for readers who cannot take the extra construction; distinct identifier, distinct vectors.
- Layout, Base64 (standard alphabet, padding): `version (1 byte = 0x01) || salt (16) || nonce (24 or 12) || ciphertext || tag (16)`.
- Reuses: the XAES-256-GCM specification and vectors for the cipher; nothing public covers the password envelope exactly, so the layout is the one shipped in the archived AES repository's examples with a version byte and the extended nonce. The page says plainly that for interoperability with code you do not control, JWE with `PBES2-HS256+A128KW` and `A256GCM` is the standard, and gives the mapping.
- Why both KDFs: Argon2id is the right answer; it is not in WebCrypto, CryptoKit, Java or .NET, so those need an audited library, and some readers cannot add one.
- Why XAES: both current right-answers lists (Latacora 2024/2026, Valsorda 2026) name it as the symmetric choice, no platform ships it natively, and there is no cross-language reference set. It is the first of the three recipes that justify the repository.

### R2 `hpke-envelope-v1`: encrypt to a recipient's public key

- HPKE (RFC 9180) base mode, `DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, `AES-256-GCM`, with a fixed application info string `cryptorecipes/hpke-envelope-v1`.
- Layout: `version (0x01) || enc (32) || ciphertext || tag (16)`, Base64. Recipient public key: raw 32 bytes, Base64. Private key: raw 32 bytes.
- Reuses: RFC 9180 test vectors for the HPKE core, plus this suite's vectors for the envelope.
- Implementations use native HPKE where it exists (Go, CryptoKit, pyca) and otherwise build the RFC recipe from native X25519, HKDF and AES-GCM, which is the one place in the suite where a construction is assembled from parts; the RFC vectors are the check.

### R2pq `hpke-envelope-pq-v1`: the same, post-quantum hybrid

- HPKE with the hybrid KEM `X25519 + ML-KEM-768` as specified in the IETF post-quantum HPKE work (X-Wing, or the hpke-pq draft's combiner, whichever is further along when the recipe is written; the recipe page records the exact draft version and the identifier changes if the draft changes the bytes).
- Allowed primitive sources: the platform's ML-KEM where present (Java 24+, .NET 10+, Go 1.24+, newest CryptoKit), otherwise liboqs bindings; the X25519 and HKDF parts come from the same sources as R2.
- First-class target, built in the same milestone as R2, not an afterthought: platform support arrived in the last twelve months, the only cross-language references live inside TLS stacks, and this is the recipe that answers "strong encryption no platform supports yet", by binding audited implementations rather than writing one. It carries the `experimental` label only until the draft it follows is published as an RFC; its vectors are versioned like every other recipe's.

### R3 `sign-detached-v1`: sign and verify a message

- Ed25519 detached signatures over a domain-separated input: `"cryptorecipes/sign-detached-v1" || 0x00 || message`.
- Keys: raw 32-byte seed and 32-byte public key, Base64. Signature: raw 64 bytes, Base64.
- Reuses: the C2SP Ed25519 vectors for the primitive, this suite's vectors for the domain separation.
- `sign-detached-pq-v1` with ML-DSA-44 follows the same pattern and is built alongside R3, not after it: ML-DSA is final (FIPS 204), it is in Java 24, .NET 10, Go 1.24 and liboqs, and anyone signing long-lived artifacts has to plan for it under the 2030 and 2035 deprecation dates. Its page also shows the hybrid form, Ed25519 and ML-DSA-44 signatures side by side with both required, which is what the conservative deployments do today.

### R4 `password-hash-v1`: store and verify a password

- Argon2id with the same parameters as R1, output in PHC string format, which is already the cross-library standard; the recipe's job is to show the verification path and to provide vectors including the PHC parsing edge cases.
- Fallback `password-hash-pbkdf2-v1` in PHC format as well.

Also in version 1 as a small recipe: `aead-record-v1`, XAES-256-GCM with an existing 32-byte key and no KDF, the recipe people reach for when a KMS or key store already gives them the key; it shares R1's cipher code and vectors. Deferred to version 2: `hkdf-derive-v1` (sub-keys from a master key with explicit context strings), JWE and COSE profiles of R1 and R2.

## 5. Languages and their allowed cryptography

| language | runs where | allowed sources, in order of preference |
|---|---|---|
| Swift | iOS 13+, macOS 10.15+ | CryptoKit; CommonCrypto for PBKDF2; swift-crypto on Linux; for Argon2id and ML-KEM: libsodium / liboqs through their Swift packages |
| Kotlin/Java | JVM 17+, Android API 26+ | `javax.crypto`; Bouncy Castle for Argon2id, HPKE, ML-KEM, ML-DSA where the JDK lacks them |
| C# | .NET 8+ | `System.Security.Cryptography`; for Argon2id: `Konscious.Security.Cryptography` or libsodium (`Sodium.Core`); .NET 10 for ML-KEM/ML-DSA |
| TypeScript | browsers, Node 20+ | WebCrypto; for Argon2id, X25519 where missing, ML-KEM: libsodium.js / `@noble/*` (audited); one build runs in both environments |
| Python | 3.10+ | `cryptography` (pyca); `argon2-cffi`; liboqs-python for ML-KEM |
| Go | 1.22+ | standard library including `crypto/mlkem`, `golang.org/x/crypto` for Argon2id and HPKE |

Rust is deliberately not in version 1: its ecosystem already has the best coverage, and the suite is most useful for the platforms where developers struggle. It is the first addition for version 2.

Rule: a pull request that adds a dependency outside this table, or any file that implements a cipher, hash, KDF, KEM or signature, is rejected. The rule is written in `CONTRIBUTING.md` and the dependency manifests are checked in CI against the table.

## 6. Vectors

- One directory per recipe: `vectors/<recipe-id>/`.
- `cases.json`: a list of positive cases, each with every input in hex or UTF-8 (password, salt, nonce, plaintext, keys), the expected output in Base64, and a free-text `note`. Inputs that are random in real use are fixed in vectors and the page says so.
- `negative.json`: cases that must fail: flipped byte in the tag, flipped byte in the ciphertext, wrong password, truncated input, wrong version byte, empty input, oversized salt; each with `expect: "error"`. No case may expect partial plaintext.
- `random-roundtrip.json`: not a file but a CI stage: each implementation encrypts 50 random inputs and writes them as artifacts; every other implementation must decrypt all of them. This is the test that catches encoding and endianness mistakes vectors miss.
- Vectors are frozen when a recipe leaves `experimental`; changing a frozen vector is a new recipe identifier.
- Where a recipe reuses a public format, the suite imports that format's official vectors verbatim (RFC 9180, C2SP CCTV) and adds its own on top; it never re-derives them.

## 7. Repository layout

```
README.md                  what this is, the recipe table, how to run the suite
RECIPES.md                 one page per recipe: purpose, parameters, layout, what not to do
CONTRIBUTING.md            the no-primitives rule, the allowed-dependency table, how a recipe is added
SECURITY.md                how to report a problem; what the suite does and does not guarantee
vectors/<recipe-id>/       cases.json, negative.json
impl/swift/ ... impl/go/   one directory per language, one file per recipe, one harness per language
tools/                     vector generation (from the Go implementation, cross-checked by Python), consistency checks
.github/workflows/         per-language jobs and the cross-language round-trip job
```

Each implementation file is self-contained and readable in one sitting: 40 to 80 lines, the recipe's parameters as named constants at the top, no shared helper library across recipes beyond Base64 and hex. Readability is a goal because the files will be copied.

## 8. CI

1. Per language: build, run the harness over every `cases.json` and `negative.json`, fail on any mismatch or any negative case that returns plaintext.
2. Cross-language: a matrix of (producer, consumer) pairs over the random round trips; all 30 pairs must pass for every recipe that both implement.
3. Dependency check: the manifest of each language against the allowed table.
4. A nightly run against the latest toolchains, since platform APIs move; a failure there opens an issue rather than blocking.

## 9. What the suite guarantees and what it does not

Guarantees: that the reference implementations agree with the vectors and with each other, that the negative cases fail, and that no cryptographic primitive is implemented in the repository. Does not guarantee: that a copied file is used correctly, that the chosen parameters are right for every threat model, or anything about the audited libraries it calls. `SECURITY.md` says this in plain words, and every recipe page starts with "use this when … do not use this when …".

## 10. Milestones

| milestone | content | estimate |
|---|---|---|
| M1 | repository; R1 fallback profile (PBKDF2 + AES-GCM) in Swift, TypeScript, Python from the archived repository's examples, with version byte and negative vectors; CI for those three | 1 week of evenings |
| M2 | the same in Go, Java, C#; cross-language round-trip job over all six; Go becomes the vector generator, Python the cross-check | 2 weeks |
| M3 | XAES-256-GCM: `aead-record-v1` and the R1 main profile in all six, C2SP vectors imported; Argon2id profile where the allowed table permits | 2 weeks |
| M4 | R2 HPKE and R2pq hybrid post-quantum in all six, RFC 9180 vectors imported; this is the milestone that makes the repository worth announcing | 3 weeks |
| M5 | R3 Ed25519 and ML-DSA-44, R4 password hashing; `RECIPES.md` complete; practitioner review; first tagged vector set v1.0; announce | 3 weeks |

Total to v1.0: about eleven weeks of part-time work, most of it in the languages you do not write daily; the reviews from people who do are the main dependency. The order puts the three differentiating recipes, XAES-256-GCM, hybrid post-quantum HPKE and ML-DSA, in weeks four to eleven rather than at the end.

## 11. Risks and how the scope handles them

- **Blessing a format.** Mitigated by reusing public formats where they exist, versioning the minimal layouts, and saying on every page which standard to use instead when the reader needs interoperability with the outside world.
- **Being read as "crypto from GitHub".** Mitigated by the no-primitives rule, the allowed-dependency table, the negative vectors, and by naming the "right answers" lists as the source of every parameter rather than our own judgment.
- **Parameter drift and draft churn.** Argon2id memory, PBKDF2 iterations, the XAES specification and the post-quantum HPKE draft will all move; the post-quantum one may change its bytes before it is an RFC. Recipe identifiers absorb that: a new parameter set or a new draft is a new identifier; the old one stays verifiable and is marked superseded.
- **Maintenance.** Six toolchains break in six different months. The nightly job and the "one file per recipe per language" layout keep each fix local.
- **The author's own expertise.** The suite is deliberately shaped so that the hard decisions are taken from standards and the work is verification, which is the part a careful engineer can do without being a cryptographer, and the part that benefits most from outside review. Asking two or three known practitioners to review the recipe pages before v1.0 is part of M5.

## 12. First steps

1. Pick the name and create the repository, Apache 2.0, with README, CONTRIBUTING and SECURITY from this scope.
2. Move the three verified examples in as R1's PBKDF2 profile, add the version byte and the negative vectors, regenerate the vector set with two independent implementations agreeing.
3. Write the Go implementation next, because Go's standard library covers the most and it becomes the vector generator.
4. Open the repository when M2 passes: six languages, one recipe, all pairs green; announce it after M4, when the hybrid post-quantum envelope works across all six, because that is the result nobody else has.
