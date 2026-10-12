// Recipe hpke-envelope-v1: encrypt a short record to a recipient's public key.
// WebCrypto only (X25519, HMAC-SHA256, AES-GCM); runs in Node 20+ and current browsers.
//
// Suite:  HPKE (RFC 9180) base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, single-shot, no additional data.
// Info:   "crypto-recipes/hpke-envelope-v1", which binds every record to this recipe.
// Keys:   recipient private key is the 32-byte X25519 scalar, public key the 32-byte point.
// Output: Base64 of  version (1 byte, 0x01) || enc (32) || ciphertext || tag (16).
//
// WebCrypto has no HPKE, so this file composes RFC 9180 sections 4 and 5.1 from the primitives above. It is the
// one place in the suite where a construction is assembled; tools/hpke_rfc9180_check.mjs checks every intermediate
// value against the CFRG test vector for this suite.

export const RECIPE = "hpke-envelope-v1";
const VERSION = 0x01;
const INFO = new TextEncoder().encode("crypto-recipes/hpke-envelope-v1");
const KEY_BYTES = 32, ENC_BYTES = 32, TAG_BYTES = 16;
const PKCS8_PREFIX = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);
const subtle = globalThis.crypto.subtle;
const utf8 = s => new TextEncoder().encode(s);
const concat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };
const i2osp = (n, len) => { const b = new Uint8Array(len); for (let i = len - 1; i >= 0; i--, n >>= 8) b[i] = n & 0xff; return b; };

const KEM_SUITE = concat(utf8("KEM"), i2osp(0x0020, 2));
const HPKE_SUITE = concat(utf8("HPKE"), i2osp(0x0020, 2), i2osp(0x0001, 2), i2osp(0x0002, 2));

// HKDF-SHA256 (RFC 5869) over WebCrypto HMAC. An empty salt is HashLen zero bytes, which HMAC treats identically.
async function hmac(key, data) {
    const k = await subtle.importKey("raw", key.length ? key : new Uint8Array(32), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return new Uint8Array(await subtle.sign("HMAC", k, data));
}
async function expand(prk, info, length) {
    let t = new Uint8Array(0), out = new Uint8Array(0);
    for (let i = 1; out.length < length; i++) { t = await hmac(prk, concat(t, info, Uint8Array.of(i))); out = concat(out, t); }
    return out.subarray(0, length);
}
const labeledExtract = (suite, salt, label, ikm) => hmac(salt, concat(utf8("HPKE-v1"), suite, utf8(label), ikm));
const labeledExpand = (suite, prk, label, info, length) => expand(prk, concat(i2osp(length, 2), utf8("HPKE-v1"), suite, utf8(label), info), length);

async function importPrivate(scalar) {
    return subtle.importKey("pkcs8", concat(PKCS8_PREFIX, scalar), "X25519", true, ["deriveBits"]);
}
async function publicOf(privateCryptoKey) {
    const jwk = await subtle.exportKey("jwk", privateCryptoKey);
    return Uint8Array.from(atob(jwk.x.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
}
async function dh(scalar, point) {
    const pub = await subtle.importKey("raw", point, "X25519", false, []);
    return new Uint8Array(await subtle.deriveBits({ name: "X25519", public: pub }, await importPrivate(scalar), 256));
}

// DHKEM(X25519, HKDF-SHA256), RFC 9180 section 4.1.
async function sharedSecret(dhValue, enc, pkR) {
    const prk = await labeledExtract(KEM_SUITE, new Uint8Array(0), "eae_prk", dhValue);
    return labeledExpand(KEM_SUITE, prk, "shared_secret", concat(enc, pkR), 32);
}
// Key schedule, base mode, RFC 9180 section 5.1.
async function keySchedule(shared, info) {
    const empty = new Uint8Array(0);
    const context = concat(Uint8Array.of(0x00), await labeledExtract(HPKE_SUITE, empty, "psk_id_hash", empty), await labeledExtract(HPKE_SUITE, empty, "info_hash", info));
    const secret = await labeledExtract(HPKE_SUITE, shared, "secret", empty);
    return { key: await labeledExpand(HPKE_SUITE, secret, "key", context, 32), baseNonce: await labeledExpand(HPKE_SUITE, secret, "base_nonce", context, 12) };
}

/** RFC 9180 DeriveKeyPair for X25519; used only by the conformance check. */
export async function deriveKeyPair(ikm) {
    const prk = await labeledExtract(KEM_SUITE, new Uint8Array(0), "dkp_prk", ikm);
    return labeledExpand(KEM_SUITE, prk, "sk", new Uint8Array(0), 32);
}

/** Single-shot SealBase with a caller-chosen ephemeral key; exported for the conformance check, never for use. */
export async function sealWithEphemeral(skE, pkR, info, aad, plaintext) {
    const enc = await publicOf(await importPrivate(skE));
    const shared = await sharedSecret(await dh(skE, pkR), enc, pkR);
    const { key, baseNonce } = await keySchedule(shared, info);
    const k = await subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
    const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: baseNonce, additionalData: aad, tagLength: 128 }, k, plaintext));
    return { enc, shared, key, baseNonce, ct };
}

async function openBase(skR, enc, info, aad, sealed) {
    const pkR = await publicOf(await importPrivate(skR));
    const shared = await sharedSecret(await dh(skR, enc), enc, pkR);
    const { key, baseNonce } = await keySchedule(shared, info);
    const k = await subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
    return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: baseNonce, additionalData: aad, tagLength: 128 }, k, sealed));
}

export async function publicKey(privateKey) {
    if (privateKey.length !== KEY_BYTES) throw new Error("private key must be 32 bytes");
    return publicOf(await importPrivate(privateKey));
}

export async function encrypt(publicKeyBytes, plaintext) {
    if (publicKeyBytes.length !== KEY_BYTES) throw new Error("public key must be 32 bytes");
    const eph = await subtle.generateKey("X25519", true, ["deriveBits"]);
    const pkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", eph.privateKey));
    const { enc, ct } = await sealWithEphemeral(pkcs8.subarray(PKCS8_PREFIX.length), publicKeyBytes, INFO, new Uint8Array(0), utf8(plaintext));
    return btoa(String.fromCharCode(...concat(Uint8Array.of(VERSION), enc, ct)));
}

// A wrong key or any modification fails with an exception; there is never partial output.
export async function decrypt(privateKey, base64) {
    if (privateKey.length !== KEY_BYTES) throw new Error("private key must be 32 bytes");
    const bytes = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
    if (bytes.length < 1 + ENC_BYTES + TAG_BYTES || bytes[0] !== VERSION) throw new Error("not an hpke-envelope-v1 record");
    const opened = await openBase(privateKey, bytes.subarray(1, 1 + ENC_BYTES), INFO, new Uint8Array(0), bytes.subarray(1 + ENC_BYTES));
    return new TextDecoder("utf-8", { fatal: true }).decode(opened);
}
