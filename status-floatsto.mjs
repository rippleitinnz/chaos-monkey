// Chaos Monkey, harness D — show progress and findings.
//
//   node status-floatsto.mjs
//   ADDRESS=r... node status-floatsto.mjs
//
// Reads the hook's state on the floatsto fuzzer account (floatsto-account.json,
// or ADDRESS=r...). Case names and expected values come from
// src/floatsto/cases.mjs — the same table the Hook is generated from.

import fs from "node:fs";
import crypto from "node:crypto";
import { XrplClient } from "xrpl-client";
import { CASES, KNOWN_DIVERGENCE, AMENDMENT_DEPENDENT } from "./src/floatsto/cases.mjs";

const WSS = process.env.WSS || "wss://pwapp.xahau-dev.net";
const address = process.env.ADDRESS ||
  JSON.parse(fs.readFileSync("floatsto-account.json", "utf8")).address;
const ns = crypto.createHash("sha256").update("chaos-fuzzer-floatsto").digest("hex").toUpperCase();

// Error names from the same header the Hook is compiled against.
const ERR = {};
for (const m of fs.readFileSync("include/hook/error.h", "utf8").matchAll(/#define\s+([A-Z_]+)\s+(-\d+)/g))
  ERR[m[2]] = m[1];
const show = (v) => (ERR[String(v)] ? `${ERR[String(v)]} (${v})` : String(v));

const client = new XrplClient(WSS);
const entries = [];
let marker;
do {
  const r = await client.send({ command: "account_namespace", account: address, namespace_id: ns, marker });
  if (r.error) { console.error(r); process.exit(1); }
  entries.push(...(r.namespace_entries || []));
  marker = r.marker;
} while (marker);
client.close();

const u32 = (h, byteOff) => parseInt(h.slice(byteOff * 2, byteOff * 2 + 8), 16);

// "STATS" is a 5-byte key, left-padded to 32 by the node; value is 16 bytes.
const stats = entries.find((e) =>
  (e.HookStateKey || "").toUpperCase().endsWith("5354415453") && (e.HookStateData || "").length === 32);

console.log(`Account   ${address}`);
console.log(`Cases     ${CASES.length} (spec-only, verified against xahaud 0f3258d; float cases run natively)`);
if (stats) {
  const d = stats.HookStateData;
  console.log(`Runs      ${u32(d, 0)}`);
  console.log(`Correct   ${u32(d, 4)}`);
  console.log(`FINDINGS  ${u32(d, 8)}`);
} else {
  console.log("No STATS yet — the hook has not run.");
}

// Finding records: key = [case, 'F', 0 x 30]; value = case(1) expected(8) actual(8).
const findings = entries
  .filter((e) => (e.HookStateKey || "").slice(2, 4).toUpperCase() === "46" && (e.HookStateData || "").length === 34)
  .map((e) => {
    const d = Buffer.from(e.HookStateData, "hex");
    return { c: d[0], exp: d.readBigInt64BE(1), act: d.readBigInt64BE(9) };
  })
  .sort((a, b) => a.c - b.c);

if (findings.length === 0) {
  console.log("\nNo findings — every case that has run returned its spec value.");
} else {
  console.log(`\n${"─".repeat(72)}\nFINDINGS (latest record per case):`);
  for (const f of findings) {
    const k = CASES[f.c];
    if (!k) { console.log(`  case ${f.c}: unknown case id (stale record?)`); continue; }
    const tag = KNOWN_DIVERGENCE[k.id] ? "  [known doc/code divergence]"
      : AMENDMENT_DEPENDENT[k.id] ? `  [amendment not active? ${AMENDMENT_DEPENDENT[k.id]}]` : "";
    console.log(`  ${String(f.c).padStart(2)} ${k.id.padEnd(9)} ${k.call}`);
    console.log(`     expected ${show(f.exp)}, got ${show(f.act)}${tag}`);
    console.log(`     spec: ${k.doc}`);
  }
  const fresh = findings.filter((f) => CASES[f.c] && !KNOWN_DIVERGENCE[CASES[f.c].id] && !AMENDMENT_DEPENDENT[CASES[f.c].id]);
  console.log(`\n${fresh.length} new finding(s) beyond the known divergences and amendment-dependent cases.` +
    (fresh.length ? " Re-check each against the release build before reporting." : ""));
}
