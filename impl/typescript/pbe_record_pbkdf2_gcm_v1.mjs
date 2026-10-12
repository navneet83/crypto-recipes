// Recipe pbe-record-pbkdf2-gcm-v1: encrypt a short record with a password.
// WebCrypto only; runs in browsers and in Node 20+.
//
// Key:    PBKDF2-HMAC-SHA256, 600000 iterations, random 16-byte salt, over the UTF-8 bytes of the password.
// Cipher: AES-256-GCM, random 12-byte nonce, 16-byte tag, no additional data.
// Output: Base64 of  version (1 byte, 0x01) || salt (16) || nonce (12) || ciphertext || tag (16).
// This is the fallback profile of recipe R1; see RECIPES.md for the Argon2id and XAES-256-GCM profiles.

export const RECIPE = "pbe-record-pbkdf2-gcm-v1";
const VERSION = 0x01;
const ITERATIONS = 600000;
const SALT_BYTES = 16;
const NONCE_BYTES = 12;
const TAG_BITS = 128;

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });

async function deriveKey(password, salt, usage) {
    const material = await subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
    return subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations: ITERATIONS },
        material, { name: "AES-GCM", length: 256 }, false, [usage]);
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
    if (bytes.length < 1 + SALT_BYTES + NONCE_BYTES + TAG_BITS / 8 || bytes[0] !== VERSION) throw new Error("not a pbe-record-pbkdf2-gcm-v1 record");
    const salt = bytes.subarray(1, 1 + SALT_BYTES);
    const nonce = bytes.subarray(1 + SALT_BYTES, 1 + SALT_BYTES + NONCE_BYTES);
    const sealed = bytes.subarray(1 + SALT_BYTES + NONCE_BYTES);
    const key = await deriveKey(password, salt, "decrypt");
    // A wrong password or any modification fails here with an exception; there is never partial output.
    return dec.decode(await subtle.decrypt({ name: "AES-GCM", iv: nonce, tagLength: TAG_BITS }, key, sealed));
}
