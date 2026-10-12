// Runs a recipe over its vectors: positive cases must reproduce the expected output and decrypt back;
// negative cases must fail. With --emit N it writes N random records for the cross-language check,
// with --consume FILE it decrypts records produced by another implementation.
import { readFile, writeFile } from "node:fs/promises";
import * as r from "./pbe_record_pbkdf2_gcm_v1.mjs";

const hex = h => Uint8Array.from(h.match(/../g) ?? [], b => parseInt(b, 16));
const root = new URL("../../", import.meta.url);
const dir = new URL(`vectors/${r.RECIPE}/`, root);
const args = process.argv.slice(2);

if (args[0] === "--emit") {
    const n = Number(args[1] ?? 20); const out = [];
    for (let i = 0; i < n; i++) {
        const password = `pw-${i}-${crypto.randomUUID()}`;
        const plaintext = i % 3 === 0 ? "" : `record ${i} ${"x".repeat(i * 7)} ünïcödé ✓`;
        out.push({ password, plaintext, record: await r.encrypt(password, plaintext) });
    }
    await writeFile(args[2], JSON.stringify({ recipe: r.RECIPE, producer: "typescript", items: out }, null, 1));
    console.log(`typescript: emitted ${n} records to ${args[2]}`);
} else if (args[0] === "--consume") {
    const { items, producer, recipe } = JSON.parse(await readFile(args[1], "utf8"));
    if (recipe !== r.RECIPE) throw new Error("recipe mismatch");
    for (const it of items) if (await r.decrypt(it.password, it.record) !== it.plaintext) throw new Error(`typescript could not open a record from ${producer}`);
    console.log(`typescript: opened ${items.length} records from ${producer}`);
} else {
    const cases = JSON.parse(await readFile(new URL("cases.json", dir), "utf8"));
    for (const c of cases.cases) {
        const produced = await r.encrypt(c.password, c.plaintext, hex(c.salt_hex), hex(c.nonce_hex));
        if (produced !== c.output_base64) throw new Error(`case ${c.id}: produced ${produced}`);
        if (await r.decrypt(c.password, c.output_base64) !== c.plaintext) throw new Error(`case ${c.id}: decrypt mismatch`);
    }
    const negative = JSON.parse(await readFile(new URL("negative.json", dir), "utf8"));
    for (const c of negative.cases) {
        let opened = null;
        try { opened = await r.decrypt(c.password, c.input_base64); } catch { continue; }
        throw new Error(`negative case ${c.id} (${c.note}) returned plaintext: ${JSON.stringify(opened)}`);
    }
    console.log(`typescript: ${cases.cases.length} cases and ${negative.cases.length} negative cases OK for ${r.RECIPE}`);
}
