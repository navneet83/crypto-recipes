// Recipe aead-record-v1: encrypt a short record with a 32-byte key you already have.
// WebCrypto only; runs in browsers and in Node 20+. Cipher is XAES-256-GCM (https://c2sp.org/XAES-256-GCM):
// a 24-byte random nonce, from which a per-message AES-256-GCM key is derived with one block of AES-CMAC,
// so random nonces are safe for any number of messages under one key.
//
// Key:    32 bytes, from a KMS, a key store or a KDF; never a password (see pbe-record-v1).
// Cipher: XAES-256-GCM, random 24-byte nonce, 16-byte tag, optional additional data (not stored).
// Output: Base64 of  version (1 byte, 0x01) || nonce (24) || ciphertext || tag (16).

export const RECIPE = "aead-record-v1";
const VERSION = 0x01;
const KEY_BYTES = 32;
const NONCE_BYTES = 24;
const TAG_BITS = 128;

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });

// WebCrypto has no raw AES block operation. AES-CBC with a zero IV encrypts the first block exactly as
// the block cipher does; the padding block it appends is discarded.
async function aesBlock(key, block) {
    const k = await subtle.importKey("raw", key, "AES-CBC", false, ["encrypt"]);
    const out = new Uint8Array(await subtle.encrypt({ name: "AES-CBC", iv: new Uint8Array(16) }, k, block));
    return out.subarray(0, 16);
}

// Steps 1-6 of the XAES-256-GCM key derivation: returns the AES-256-GCM key and the 12-byte nonce.
async function xaesSubkey(key, nonce) {
    const l = await aesBlock(key, new Uint8Array(16));
    const k1 = new Uint8Array(16);
    for (let i = 0; i < 16; i++) k1[i] = ((l[i] << 1) | (i < 15 ? l[i + 1] >> 7 : 0)) & 0xff;
    if (l[0] & 0x80) k1[15] ^= 0x87;
    const m = counter => { const b = new Uint8Array(16); b.set([0x00, counter, 0x58, 0x00]); b.set(nonce.subarray(0, 12), 4); for (let i = 0; i < 16; i++) b[i] ^= k1[i]; return b; };
    const kx = new Uint8Array(32);
    kx.set(await aesBlock(key, m(1)), 0);
    kx.set(await aesBlock(key, m(2)), 16);
    return { kx, nx: nonce.subarray(12) };
}

async function gcmKey(kx, usage) { return subtle.importKey("raw", kx, "AES-GCM", false, [usage]); }

export async function encrypt(key, plaintext, aad = "", nonce = null) {
    if (key.length !== KEY_BYTES) throw new Error("key must be 32 bytes");
    nonce ??= crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
    if (nonce.length !== NONCE_BYTES) throw new Error("bad nonce length");
    const { kx, nx } = await xaesSubkey(key, nonce);
    const sealed = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nx, additionalData: enc.encode(aad), tagLength: TAG_BITS }, await gcmKey(kx, "encrypt"), enc.encode(plaintext)));
    const out = new Uint8Array(1 + NONCE_BYTES + sealed.length);
    out[0] = VERSION; out.set(nonce, 1); out.set(sealed, 1 + NONCE_BYTES);
    return btoa(String.fromCharCode(...out));
}

export async function decrypt(key, base64, aad = "") {
    if (key.length !== KEY_BYTES) throw new Error("key must be 32 bytes");
    const bytes = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
    if (bytes.length < 1 + NONCE_BYTES + TAG_BITS / 8 || bytes[0] !== VERSION) throw new Error("not an aead-record-v1 record");
    const { kx, nx } = await xaesSubkey(key, bytes.subarray(1, 1 + NONCE_BYTES));
    // A wrong key, wrong additional data or any modification fails here with an exception; there is never partial output.
    return dec.decode(await subtle.decrypt({ name: "AES-GCM", iv: nx, additionalData: enc.encode(aad), tagLength: TAG_BITS }, await gcmKey(kx, "decrypt"), bytes.subarray(1 + NONCE_BYTES)));
}
