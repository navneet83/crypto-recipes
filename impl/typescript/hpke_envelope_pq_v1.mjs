// Recipe hpke-envelope-pq-v1: encrypt a short record to a recipient's public key, post-quantum hybrid.
// Node 26+ only (node:crypto ML-KEM-768, X25519, SHA3-256, SHAKE256, HMAC, AES-GCM); WebCrypto has no ML-KEM yet.
//
// Suite:  HPKE base mode with the KEM MLKEM768-X25519 (X-Wing, KEM id 0x647a, draft-ietf-hpke-pq), HKDF-SHA256,
//         AES-256-GCM, single-shot, no additional data. A record stays confidential unless both ML-KEM-768 and X25519 fall.
// Info:   "crypto-recipes/hpke-envelope-pq-v1".
// Keys:   recipient private key is the 32-byte X-Wing seed; public key is ML-KEM-768 (1184) || X25519 (32).
// Output: Base64 of  version (1 byte, 0x01) || enc (1120) || ciphertext || tag (16).
//
// Node has neither HPKE nor X-Wing, so this file composes both: X-Wing from draft-connolly-cfrg-xwing-kem, the key
// schedule from RFC 9180 section 5.1. tools/hpke_pq_check.mjs checks it against the X-Wing draft's vectors and the
// draft-ietf-hpke-pq vector for this KEM.
import { createCipheriv, createDecipheriv, createHash, createHmac, createPrivateKey, createPublicKey, decapsulate, diffieHellman, encapsulate, generateKeyPairSync } from "node:crypto";

export const RECIPE = "hpke-envelope-pq-v1";
const VERSION = 0x01;
const INFO = Buffer.from("crypto-recipes/hpke-envelope-pq-v1");
const SEED_BYTES = 32, PUBLIC_BYTES = 1216, MLKEM_PUBLIC_BYTES = 1184, ENC_BYTES = 1120, MLKEM_CT_BYTES = 1088, TAG_BYTES = 16;
const MLKEM_PKCS8_SEED_PREFIX = Buffer.from("3054020100300b060960864801650304040204428040", "hex");
const MLKEM_SPKI_PREFIX = Buffer.from("308204b2300b0609608648016503040402038204a100", "hex");
const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");
const XWING_LABEL = Buffer.from("5c2e2f2f5e5c", "hex"); // the six ASCII characters \.//^\
const HPKE_SUITE_AES256GCM = Buffer.from("48504b45647a00010002", "hex"); // "HPKE" || 0x647a || 0x0001 || 0x0002

export const available = (() => { try { createPrivateKey({ key: Buffer.concat([MLKEM_PKCS8_SEED_PREFIX, Buffer.alloc(64)]), format: "der", type: "pkcs8" }); return true; } catch { return false; } })();

const x25519Private = scalar => createPrivateKey({ key: Buffer.concat([X25519_PKCS8_PREFIX, scalar]), format: "der", type: "pkcs8" });
const x25519Public = point => createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, point]), format: "der", type: "spki" });
const rawPublic = (key, len) => { const spki = (key.type === "public" ? key : createPublicKey(key)).export({ format: "der", type: "spki" }); return spki.subarray(spki.length - len); };

// X-Wing key expansion: SHAKE256(seed, 96) = ML-KEM-768 seed (64) || X25519 scalar (32).
function expand(seed) {
    if (seed.length !== SEED_BYTES) throw new Error("private key must be the 32-byte X-Wing seed");
    const e = createHash("shake256", { outputLength: 96 }).update(seed).digest();
    const mlkem = createPrivateKey({ key: Buffer.concat([MLKEM_PKCS8_SEED_PREFIX, e.subarray(0, 64)]), format: "der", type: "pkcs8" });
    const x = x25519Private(e.subarray(64));
    return { mlkem, x, pkM: rawPublic(mlkem, MLKEM_PUBLIC_BYTES), pkX: rawPublic(x, 32) };
}
const combine = (ssM, ssX, ctX, pkX) => createHash("sha3-256").update(Buffer.concat([ssM, ssX, ctX, pkX, XWING_LABEL])).digest();

export function xwingDecapsulate(seed, enc) {
    const { mlkem, x, pkX } = expand(Buffer.from(seed));
    const ctM = enc.subarray(0, MLKEM_CT_BYTES), ctX = enc.subarray(MLKEM_CT_BYTES);
    const ssM = decapsulate(mlkem, ctM);
    const ssX = diffieHellman({ privateKey: x, publicKey: x25519Public(ctX) });
    return combine(ssM, ssX, ctX, pkX);
}
function xwingEncapsulate(pk) {
    const pkM = pk.subarray(0, MLKEM_PUBLIC_BYTES), pkX = pk.subarray(MLKEM_PUBLIC_BYTES);
    const { sharedKey: ssM, ciphertext: ctM } = encapsulate(createPublicKey({ key: Buffer.concat([MLKEM_SPKI_PREFIX, pkM]), format: "der", type: "spki" }));
    const eph = generateKeyPairSync("x25519");
    const ctX = rawPublic(eph.publicKey, 32);
    const ssX = diffieHellman({ privateKey: eph.privateKey, publicKey: x25519Public(pkX) });
    return { enc: Buffer.concat([ctM, ctX]), shared: combine(ssM, ssX, ctX, pkX) };
}

// RFC 9180 key schedule, base mode, HKDF-SHA256. An empty salt is HashLen zero bytes, which HMAC treats identically.
const extract = (salt, ikm) => createHmac("sha256", salt.length ? salt : Buffer.alloc(32)).update(ikm).digest();
function expandHkdf(prk, info, length) {
    let t = Buffer.alloc(0), out = Buffer.alloc(0);
    for (let i = 1; out.length < length; i++) { t = createHmac("sha256", prk).update(Buffer.concat([t, info, Buffer.of(i)])).digest(); out = Buffer.concat([out, t]); }
    return out.subarray(0, length);
}
const labeledExtract = (suite, salt, label, ikm) => extract(salt, Buffer.concat([Buffer.from("HPKE-v1"), suite, Buffer.from(label), ikm]));
const labeledExpand = (suite, prk, label, info, length) => expandHkdf(prk, Buffer.concat([Buffer.from([length >> 8, length & 0xff]), Buffer.from("HPKE-v1"), suite, Buffer.from(label), info]), length);

/** Exported for the conformance check, which uses the draft vector's own suite id. */
export function keySchedule(suite, shared, info) {
    const empty = Buffer.alloc(0);
    const context = Buffer.concat([Buffer.of(0), labeledExtract(suite, empty, "psk_id_hash", empty), labeledExtract(suite, empty, "info_hash", info)]);
    const secret = labeledExtract(suite, shared, "secret", empty);
    return { key: labeledExpand(suite, secret, "key", context, 32), baseNonce: labeledExpand(suite, secret, "base_nonce", context, 12) };
}

export async function publicKey(seed) {
    const { pkM, pkX } = expand(Buffer.from(seed));
    return new Uint8Array(Buffer.concat([pkM, pkX]));
}

export async function encrypt(publicKeyBytes, plaintext) {
    if (publicKeyBytes.length !== PUBLIC_BYTES) throw new Error("public key must be 1216 bytes");
    const { enc, shared } = xwingEncapsulate(Buffer.from(publicKeyBytes));
    const { key, baseNonce } = keySchedule(HPKE_SUITE_AES256GCM, shared, INFO);
    const c = createCipheriv("aes-256-gcm", key, baseNonce);
    const ct = Buffer.concat([c.update(Buffer.from(plaintext, "utf8")), c.final(), c.getAuthTag()]);
    return Buffer.concat([Buffer.of(VERSION), enc, ct]).toString("base64");
}

// A wrong key or any modification fails with an exception; there is never partial output.
export async function decrypt(seed, base64) {
    const data = Buffer.from(base64, "base64");
    if (data.toString("base64") !== base64 || data.length < 1 + ENC_BYTES + TAG_BYTES || data[0] !== VERSION) throw new Error("not an hpke-envelope-pq-v1 record");
    const enc = data.subarray(1, 1 + ENC_BYTES), sealed = data.subarray(1 + ENC_BYTES);
    const { key, baseNonce } = keySchedule(HPKE_SUITE_AES256GCM, xwingDecapsulate(seed, enc), INFO);
    const d = createDecipheriv("aes-256-gcm", key, baseNonce);
    d.setAuthTag(sealed.subarray(sealed.length - TAG_BYTES));
    const opened = Buffer.concat([d.update(sealed.subarray(0, sealed.length - TAG_BYTES)), d.final()]);
    return new TextDecoder("utf-8", { fatal: true }).decode(opened);
}

