// Recipe pbe-record-v1: encrypt a short record with a password.
// Node 26+ only: Argon2id comes from node:crypto, the rest from WebCrypto. Browsers have no Argon2id;
// use pbe-record-pbkdf2-gcm-v1 there (the two do not interoperate).
//
// Key:    Argon2id, 64 MiB memory, 3 passes, 1 lane, random 16-byte salt, 32-byte output, over the UTF-8 bytes of the password.
// Cipher: AES-256-GCM, random 12-byte nonce, 16-byte tag, no additional data. The salt is fresh per record, so the
//         derived key is used once and a 12-byte random nonce is safe; the extended-nonce cipher of aead-record-v1 is not needed.
// Output: Base64 of  version (1 byte, 0x01) || salt (16) || nonce (12) || ciphertext || tag (16).
import { argon2 } from "node:crypto";

export const RECIPE = "pbe-record-v1";
export const available = typeof argon2 === "function";
const VERSION = 0x01;
const MEMORY_KIB = 64 * 1024;
const PASSES = 3;
const LANES = 1;
const SALT_BYTES = 16;
const NONCE_BYTES = 12;
const TAG_BITS = 128;

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });

async function deriveKey(password, salt, usage) {
    if (!available) throw new Error("this Node has no built-in Argon2id; use pbe-record-pbkdf2-gcm-v1");
    const raw = await new Promise((resolve, reject) =>
        argon2("argon2id", { message: enc.encode(password), nonce: salt, parallelism: LANES, tagLength: 32, memory: MEMORY_KIB, passes: PASSES },
            (err, key) => err ? reject(err) : resolve(key)));
    return subtle.importKey("raw", raw, "AES-GCM", false, [usage]);
}

export async function encrypt(password, plaintext, salt = null, nonce = null) {
    salt ??= crypto.getRandomValues(new Uint8Array(SALT_BYTES));
    nonce ??= crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
    if (salt.length !== SALT_BYTES || nonce.length !== NONCE_BYTES) throw new Error("bad salt or nonce length");
    const key = await deriveKey(password, salt, "encrypt");
    const sealed = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce, tagLength: TAG_BITS }, key, enc.encode(plaintext)));
    const out = new Uint8Array(1 + SALT_BYTES + NONCE_BYTES + sealed.length);
    out[0] = VERSION; out.set(salt, 1); out.set(nonce, 1 + SALT_BYTES); out.set(sealed, 1 + SALT_BYTES + NONCE_BYTES);
    return btoa(String.fromCharCode(...out));
}

export async function decrypt(password, base64) {
    const bytes = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
    if (bytes.length < 1 + SALT_BYTES + NONCE_BYTES + TAG_BITS / 8 || bytes[0] !== VERSION) throw new Error("not a pbe-record-v1 record");
    const salt = bytes.subarray(1, 1 + SALT_BYTES);
    const nonce = bytes.subarray(1 + SALT_BYTES, 1 + SALT_BYTES + NONCE_BYTES);
    const key = await deriveKey(password, salt, "decrypt");
    // A wrong password or any modification fails here with an exception; there is never partial output.
    return dec.decode(await subtle.decrypt({ name: "AES-GCM", iv: nonce, tagLength: TAG_BITS }, key, bytes.subarray(1 + SALT_BYTES + NONCE_BYTES)));
}
