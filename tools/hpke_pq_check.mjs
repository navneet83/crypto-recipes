// Checks the assembled X-Wing and HPKE in impl/typescript/hpke_envelope_pq_v1.mjs against
// draft-connolly-cfrg-xwing-kem (key expansion and decapsulation for every vector) and draft-ietf-hpke-pq
// (MLKEM768-X25519 + HKDF-SHA256 + ChaCha20-Poly1305: public key, shared secret, key schedule, first ciphertext).
import { readFile } from "node:fs/promises";
import { createDecipheriv } from "node:crypto";
import { publicKey, xwingDecapsulate, keySchedule } from "../impl/typescript/hpke_envelope_pq_v1.mjs";

const dir = new URL("../vectors/hpke-envelope-pq-v1/", import.meta.url);
const hex = h => Buffer.from(h, "hex");
const eq = (name, got, want) => { if (Buffer.from(got).toString("hex") !== want) throw new Error(`${name}: got ${Buffer.from(got).toString("hex").slice(0, 64)}…, want ${want.slice(0, 64)}…`); };

const xwing = JSON.parse(await readFile(new URL("draft-xwing.json", dir), "utf8"));
for (const [i, v] of xwing.entries()) {
    eq(`xwing[${i}] pk`, await publicKey(hex(v.seed ?? v.sk)), v.pk);
    eq(`xwing[${i}] ss`, xwingDecapsulate(hex(v.seed ?? v.sk), hex(v.ct)), v.ss);
}

const v = JSON.parse(await readFile(new URL("draft-hpke-pq.json", dir), "utf8"));
eq("pkRm", await publicKey(hex(v.skRm)), v.pkRm);
const shared = xwingDecapsulate(hex(v.skRm), hex(v.enc));
eq("shared_secret", shared, v.shared_secret);
const { key, baseNonce } = keySchedule(hex(v.suite_id), shared, hex(v.info));
eq("key", key, v.key);
eq("base_nonce", baseNonce, v.base_nonce);
const e0 = v.encryptions[0], ct = hex(e0.ct);
const d = createDecipheriv("chacha20-poly1305", key, baseNonce, { authTagLength: 16 });
d.setAAD(hex(e0.aad)); d.setAuthTag(ct.subarray(ct.length - 16));
eq("plaintext of encryption 0", Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]), e0.pt);
console.log(`hpke-pq: ${xwing.length} X-Wing vectors and the draft-ietf-hpke-pq vector OK (pk, shared_secret, key, base_nonce, ciphertext)`);
