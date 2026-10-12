// Runs the recipes over their vectors, emits random records, or consumes another implementation's records.
//   harness.mjs                          replay cases.json and negative.json for every recipe
//   harness.mjs <recipe> --emit N FILE   write N random records for the cross-language check
//   harness.mjs <recipe> --consume FILE  open records produced by another implementation
import { readFile, writeFile } from "node:fs/promises";
import * as pbe from "./pbe_record_pbkdf2_gcm_v1.mjs";
import * as aead from "./aead_record_v1.mjs";

const hex = h => Uint8Array.from(h.match(/../g) ?? [], b => parseInt(b, 16));
const toHex = b => [...b].map(x => x.toString(16).padStart(2, "0")).join("");
const plaintextFor = i => i % 3 === 0 ? "" : `record ${i} ${"x".repeat(i * 7)} ünïcödé ✓`;
const root = new URL("../../", import.meta.url);

const RECIPES = {
    [pbe.RECIPE]: {
        replay: c => pbe.encrypt(c.password, c.plaintext, hex(c.salt_hex), hex(c.nonce_hex)),
        open: (c, field) => pbe.decrypt(c.password, c[field]),
        emit: async i => { const password = `pw-${i}-${crypto.randomUUID()}`; return { password, plaintext: plaintextFor(i), record: await pbe.encrypt(password, plaintextFor(i)) }; },
        consume: it => pbe.decrypt(it.password, it.record),
    },
    [aead.RECIPE]: {
        replay: c => aead.encrypt(hex(c.key_hex), c.plaintext, c.aad, hex(c.nonce_hex)),
        open: (c, field) => aead.decrypt(hex(c.key_hex), c[field], c.aad),
        emit: async i => { const key = crypto.getRandomValues(new Uint8Array(32)); const aad = i % 2 ? "" : `aad-${i}`; return { key_hex: toHex(key), aad, plaintext: plaintextFor(i), record: await aead.encrypt(key, plaintextFor(i), aad) }; },
        consume: it => aead.decrypt(hex(it.key_hex), it.record, it.aad),
    },
};

async function replay(name, impl) {
    const dir = new URL(`vectors/${name}/`, root);
    const cases = JSON.parse(await readFile(new URL("cases.json", dir), "utf8")).cases;
    for (const c of cases) {
        const produced = await impl.replay(c);
        if (produced !== c.output_base64) throw new Error(`${name} case ${c.id}: produced ${produced}`);
        if (await impl.open(c, "output_base64") !== c.plaintext) throw new Error(`${name} case ${c.id}: decrypt mismatch`);
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
if (args.length === 0) {
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
        for (const it of items) if (await impl.consume(it) !== it.plaintext) throw new Error(`typescript could not open a ${name} record from ${producer}`);
        console.log(`typescript: opened ${items.length} ${name} records from ${producer}`);
    }
}
