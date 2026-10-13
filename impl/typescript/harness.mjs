// Runs the recipes over their vectors, emits random records, or consumes another implementation's records.
//   harness.mjs                          replay cases.json and negative.json for every recipe
//   harness.mjs --list                   print the recipes this implementation supports, one per line
//   harness.mjs <recipe> --emit N FILE   write N random records for the cross-language check
//   harness.mjs <recipe> --consume FILE  open records produced by another implementation
import { readFile, writeFile } from "node:fs/promises";
import * as pbe from "./pbe_record_pbkdf2_gcm_v1.mjs";
import * as aead from "./aead_record_v1.mjs";
import * as argon2 from "./pbe_record_v1.mjs";
import * as sign from "./sign_detached_v1.mjs";
import * as signPq from "./sign_detached_pq_v1.mjs";
import * as hpke from "./hpke_envelope_v1.mjs";
import * as hpkePq from "./hpke_envelope_pq_v1.mjs";

const hex = h => Uint8Array.from(h.match(/../g) ?? [], b => parseInt(b, 16));
const toHex = b => [...b].map(x => x.toString(16).padStart(2, "0")).join("");
const plaintextFor = i => i % 3 === 0 ? "" : `record ${i} ${"x".repeat(i * 7)} ünïcödé ✓`;
const root = new URL("../../", import.meta.url);

const passwordRecipe = r => ({
    replay: c => r.encrypt(c.password, c.plaintext, hex(c.salt_hex), hex(c.nonce_hex)),
    open: (c, field) => r.decrypt(c.password, c[field]),
    emit: async i => { const password = `pw-${i}-${crypto.randomUUID()}`; return { password, plaintext: plaintextFor(i), record: await r.encrypt(password, plaintextFor(i)) }; },
    consume: it => r.decrypt(it.password, it.record),
});
const RECIPES = {
    [pbe.RECIPE]: passwordRecipe(pbe),
    [aead.RECIPE]: {
        replay: c => aead.encrypt(hex(c.key_hex), c.plaintext, c.aad, hex(c.nonce_hex)),
        open: (c, field) => aead.decrypt(hex(c.key_hex), c[field], c.aad),
        emit: async i => { const key = crypto.getRandomValues(new Uint8Array(32)); const aad = i % 2 ? "" : `aad-${i}`; return { key_hex: toHex(key), aad, plaintext: plaintextFor(i), record: await aead.encrypt(key, plaintextFor(i), aad) }; },
        consume: it => aead.decrypt(hex(it.key_hex), it.record, it.aad),
    },
    ...(argon2.available ? { [argon2.RECIPE]: passwordRecipe(argon2) } : {}),
    [hpke.RECIPE]: envelopeRecipe(hpke),
    ...(hpkePq.available ? { [hpkePq.RECIPE]: envelopeRecipe(hpkePq) } : {}),
    [sign.RECIPE]: signatureRecipe(sign, true),
    ...(signPq.available ? { [signPq.RECIPE]: signatureRecipe(signPq, false) } : {}),
};
// Public-key encryption: a fresh ephemeral key per record, so own output is opened, not compared.
function envelopeRecipe(r) {
    const check = async c => { if (toHex(await r.publicKey(hex(c.private_hex))) !== c.public_hex) throw new Error("public key mismatch"); };
    return {
        deterministic: false,
        replay: async c => { await check(c); return r.encrypt(hex(c.public_hex), c.plaintext); },
        open: (c, field) => r.decrypt(hex(c.private_hex), c[field]),
        emit: async i => { const priv = crypto.getRandomValues(new Uint8Array(32)); const pub = await r.publicKey(priv); return { private_hex: toHex(priv), public_hex: toHex(pub), plaintext: plaintextFor(i), record: await r.encrypt(pub, plaintextFor(i)) }; },
        consume: async it => { await check(it); return r.decrypt(hex(it.private_hex), it.record); },
    };
}
function signatureRecipe(r, deterministic) {
    return {
        deterministic, // ML-DSA signing is randomized; own output is checked by verification.
        replay: async c => { if (toHex(await r.publicKey(hex(c.seed_hex))) !== c.public_hex) throw new Error(`${c.id}: public key mismatch`); return r.sign(hex(c.seed_hex), c.message); },
        open: async (c, field) => { await r.verify(hex(c.public_hex), c.message, c[field]); return c.message; },
        emit: async i => { const seed = crypto.getRandomValues(new Uint8Array(32)); return { seed_hex: toHex(seed), public_hex: toHex(await r.publicKey(seed)), message: plaintextFor(i), record: await r.sign(seed, plaintextFor(i)) }; },
        consume: async it => { if (toHex(await r.publicKey(hex(it.seed_hex))) !== it.public_hex) throw new Error("public key mismatch"); await r.verify(hex(it.public_hex), it.message, it.record); return it.message; },
    };
}
// Encryption vectors carry the plaintext, signature vectors the message.
const expected = c => "message" in c ? c.message : c.plaintext;

async function replay(name, impl) {
    const dir = new URL(`vectors/${name}/`, root);
    const cases = JSON.parse(await readFile(new URL("cases.json", dir), "utf8")).cases;
    for (const c of cases) {
        const produced = await impl.replay(c);
        const field = ["signature_base64", "record_base64", "output_base64"].find(f => f in c);
        if (impl.deterministic === false) {
            if (await impl.open({ ...c, [field]: produced }, field) !== expected(c)) throw new Error(`${name} case ${c.id}: own output does not verify`);
        } else if (produced !== c[field]) throw new Error(`${name} case ${c.id}: produced ${produced}`);
        if (await impl.open(c, field) !== expected(c)) throw new Error(`${name} case ${c.id}: open mismatch`);
    }
    const negative = JSON.parse(await readFile(new URL("negative.json", dir), "utf8")).cases;
    for (const c of negative) {
        let opened;
        try { opened = await impl.open(c, "input_base64"); } catch { continue; }
        throw new Error(`${name} negative case ${c.id} (${c.note}) returned plaintext: ${JSON.stringify(opened)}`);
    }
    console.log(`typescript: ${cases.length} cases and ${negative.length} negative cases OK for ${name}`);
}

const args = process.argv.slice(2);
if (args[0] === "--list") {
    console.log(Object.keys(RECIPES).join("\n"));
} else if (args.length === 0) {
    for (const [name, impl] of Object.entries(RECIPES)) await replay(name, impl);
} else {
    const name = args[0], impl = RECIPES[name];
    if (!impl) throw new Error(`unknown recipe ${name}`);
    if (args[1] === "--emit") {
        const n = Number(args[2]); const items = [];
        for (let i = 0; i < n; i++) items.push(await impl.emit(i));
        await writeFile(args[3], JSON.stringify({ recipe: name, producer: "typescript", items }, null, 1));
        console.log(`typescript: emitted ${n} records to ${args[3]} for ${name}`);
    } else if (args[1] === "--consume") {
        const { items, producer, recipe } = JSON.parse(await readFile(args[2], "utf8"));
        if (recipe !== name) throw new Error("recipe mismatch");
        for (const it of items) if (await impl.consume(it) !== expected(it)) throw new Error(`typescript could not open a ${name} record from ${producer}`);
        console.log(`typescript: opened ${items.length} ${name} records from ${producer}`);
    }
}
