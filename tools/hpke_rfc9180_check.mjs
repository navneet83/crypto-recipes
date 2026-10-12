// Checks the assembled HPKE in impl/typescript/hpke_envelope_v1.mjs against the CFRG test vector for base mode,
// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM: key derivation, encapsulation, shared secret, key schedule
// and the first encryption.
import { readFile } from "node:fs/promises";
import { deriveKeyPair, sealWithEphemeral, publicKey } from "../impl/typescript/hpke_envelope_v1.mjs";

const hex = h => Uint8Array.from(h.match(/../g) ?? [], b => parseInt(b, 16));
const toHex = b => [...b].map(x => x.toString(16).padStart(2, "0")).join("");
const v = JSON.parse(await readFile(new URL("../vectors/hpke-envelope-v1/rfc9180.json", import.meta.url), "utf8"));
const eq = (name, got, want) => { if (toHex(got) !== want) throw new Error(`${name}: got ${toHex(got)}, want ${want}`); };

eq("DeriveKeyPair(ikmR)", await deriveKeyPair(hex(v.ikmR)), v.skRm);
eq("DeriveKeyPair(ikmE)", await deriveKeyPair(hex(v.ikmE)), v.skEm);
eq("pkRm", await publicKey(hex(v.skRm)), v.pkRm);
const e0 = v.encryptions[0];
const r = await sealWithEphemeral(hex(v.skEm), hex(v.pkRm), hex(v.info), hex(e0.aad), hex(e0.pt));
eq("enc", r.enc, v.enc);
eq("shared_secret", r.shared, v.shared_secret);
eq("key", r.key, v.key);
eq("base_nonce", r.baseNonce, v.base_nonce);
eq("ciphertext", r.ct, e0.ct);
console.log("hpke: CFRG test vector OK (DeriveKeyPair, enc, shared_secret, key, base_nonce, ciphertext)");
