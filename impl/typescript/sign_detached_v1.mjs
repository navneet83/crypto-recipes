// Recipe sign-detached-v1: sign a message and verify the signature.
// WebCrypto only (Ed25519 is in Node 20+ and in current browsers).
//
// Keys:      Ed25519 (RFC 8032). Private key is the 32-byte seed, public key is the 32-byte point, both Base64 when
//            transported. WebCrypto imports a private key only in PKCS#8 or JWK form, so the seed is wrapped in the
//            fixed 16-byte PKCS#8 prefix below; that is an encoding, not a different key.
// Input:     "crypto-recipes/sign-detached-v1" || 0x00 || message. The prefix stops a signature made for this recipe
//            from meaning anything in another protocol that signs raw bytes with the same key, and the other way round.
// Signature: the 64 raw Ed25519 bytes, Base64 (standard alphabet, with padding). The public key and the message
//            travel separately, which is what "detached" means.

export const RECIPE = "sign-detached-v1";
const DOMAIN = new TextEncoder().encode("crypto-recipes/sign-detached-v1\0");
const SEED_BYTES = 32, PUBLIC_BYTES = 32, SIGNATURE_BYTES = 64;
const PKCS8_PREFIX = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);
const subtle = globalThis.crypto.subtle;

function input(message) {
    const m = new TextEncoder().encode(message);
    const out = new Uint8Array(DOMAIN.length + m.length);
    out.set(DOMAIN); out.set(m, DOMAIN.length);
    return out;
}

async function privateKey(seed) {
    if (seed.length !== SEED_BYTES) throw new Error("seed must be 32 bytes");
    const pkcs8 = new Uint8Array(PKCS8_PREFIX.length + SEED_BYTES);
    pkcs8.set(PKCS8_PREFIX); pkcs8.set(seed, PKCS8_PREFIX.length);
    return subtle.importKey("pkcs8", pkcs8, "Ed25519", true, ["sign"]);
}

export async function publicKey(seed) {
    // WebCrypto derives the public half only through JWK export of the private key.
    const jwk = await subtle.exportKey("jwk", await privateKey(seed));
    return Uint8Array.from(atob(jwk.x.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
}

export async function sign(seed, message) {
    const sig = new Uint8Array(await subtle.sign("Ed25519", await privateKey(seed), input(message)));
    return btoa(String.fromCharCode(...sig));
}

// Resolves for a valid signature and throws for anything else; callers never get a boolean to ignore.
export async function verify(pub, message, signature) {
    if (pub.length !== PUBLIC_BYTES) throw new Error("public key must be 32 bytes");
    const sig = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
    if (sig.length !== SIGNATURE_BYTES) throw new Error("signature must be 64 bytes");
    const key = await subtle.importKey("raw", pub, "Ed25519", false, ["verify"]);
    if (!await subtle.verify("Ed25519", key, sig, input(message))) throw new Error("invalid signature");
}
