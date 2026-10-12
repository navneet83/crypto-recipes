// Recipe sign-detached-pq-v1: sign a message and verify the signature, post-quantum.
// Node 26+ only (node:crypto ML-DSA); WebCrypto has no ML-DSA yet, so this file does not run in browsers.
//
// Keys:      ML-DSA-65 (FIPS 204). Private key is the 32-byte seed; public key is the 1952-byte encoding. Both Base64
//            when transported. Node imports the seed through its PKCS#8 form (fixed 22-byte prefix + seed) and the
//            public key through its X.509 form (fixed 22-byte prefix + 1952 bytes); the prefixes are below.
// Input:     "crypto-recipes/sign-detached-pq-v1" || 0x00 || message, with an empty FIPS 204 context string.
// Signature: the 3309 raw ML-DSA-65 bytes, Base64. Signing is randomized: two signatures of one message differ.
import { createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from "node:crypto";

export const RECIPE = "sign-detached-pq-v1";
export const available = (() => { try { createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX(), Buffer.alloc(32)]), format: "der", type: "pkcs8" }); return true; } catch { return false; } })();
const DOMAIN = Buffer.from("crypto-recipes/sign-detached-pq-v1\0");
const SEED_BYTES = 32, PUBLIC_BYTES = 1952, SIGNATURE_BYTES = 3309;
function PKCS8_PREFIX() { return Buffer.from("3034020100300b060960864801650304031204228020", "hex"); }
const X509_PREFIX = Buffer.from("308207b2300b0609608648016503040312038207a100", "hex");

const input = message => Buffer.concat([DOMAIN, Buffer.from(message, "utf8")]);

function privateKey(seed) {
    if (seed.length !== SEED_BYTES) throw new Error("seed must be 32 bytes");
    return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX(), Buffer.from(seed)]), format: "der", type: "pkcs8" });
}

export async function publicKey(seed) {
    const spki = createPublicKey(privateKey(seed)).export({ format: "der", type: "spki" });
    return new Uint8Array(spki.subarray(spki.length - PUBLIC_BYTES));
}

export async function sign(seed, message) {
    return nodeSign(null, input(message), privateKey(seed)).toString("base64");
}

// Resolves for a valid signature and throws for anything else; callers never get a boolean to ignore.
export async function verify(pub, message, signature) {
    if (pub.length !== PUBLIC_BYTES) throw new Error("public key must be 1952 bytes");
    const sig = Buffer.from(signature, "base64");
    if (sig.length !== SIGNATURE_BYTES || sig.toString("base64") !== signature) throw new Error("signature must be 3309 bytes");
    const key = createPublicKey({ key: Buffer.concat([X509_PREFIX, Buffer.from(pub)]), format: "der", type: "spki" });
    if (!nodeVerify(null, input(message), key, sig)) throw new Error("invalid signature");
}
