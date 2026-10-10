// Chaos Monkey, harness A — show progress and findings.
//
//   node status.mjs
//   ADDRESS=r... node status.mjs
//
// Reads the hook's state on the fuzzer account (fuzzer-account.json, or
// ADDRESS=r...) and prints the counters plus every recorded finding. Class
// names and must-pass flags come from src/apploader/faults.mjs, which
// tools/check-faults.mjs keeps in step with gen.h.

import fs from "node:fs";
import crypto from "node:crypto";
import { XrplClient } from "xrpl-client";
import { FAULTS } from "./src/apploader/faults.mjs";

const WSS = process.env.WSS || "wss://pwapp.xahau-dev.net";
const address = process.env.ADDRESS ||
  JSON.parse(fs.readFileSync("fuzzer-account.json", "utf8")).address;
const ns = crypto.createHash("sha256").update("chaos-fuzzer-apploader").digest("hex").toUpperCase();

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

const u32 = (h, o) => parseInt(h.slice(o * 2, o * 2 + 8), 16);

// STATS: runs, correct-pass, correct-fail, findings, harness errors (5 x u32).
const stats = entries.find((e) => (e.HookStateData || "").length === 40);
console.log(`Account         ${address}`);
console.log(`Classes         ${FAULTS.length} (spec-stated in AppLoader.h or pinned in PWALoader_test)`);
if (stats) {
  const d = stats.HookStateData;
  console.log(`Runs            ${u32(d, 0)}`);
  console.log(`Correct (pass)  ${u32(d, 4)}`);
  console.log(`Correct (fail)  ${u32(d, 8)}`);
  console.log(`FINDINGS        ${u32(d, 12)}`);
  console.log(`Harness errors  ${u32(d, 16)}`);
} else console.log("No STATS yet — the hook has not run.");

// Finding: fault(1) observed_pass(1) len(2) seed(32) head-of-document(...).
const findings = entries.filter((e) => (e.HookStateData || "").length >= 72);
if (!findings.length) console.log("\nNo findings — consensus agreed with the spec on every document so far.");
for (const e of findings) {
  const d = Buffer.from(e.HookStateData, "hex");
  const fault = d[0], observedPass = d[1], len = d.readUInt16BE(2);
  const f = FAULTS[fault];
  const seed = d.subarray(4, 36).toString("hex");
  const shown = [...d.subarray(36)]
    .map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : `\\x${b.toString(16).padStart(2, "0")}`)).join("");
  console.log(`\nFINDING  ${f ? f.name : `unknown class ${fault} (stale record?)`}: ` +
    `expected ${f ? (f.pass ? "PASS" : "FAIL") : "?"}, consensus said ${observedPass ? "PASS" : "FAIL"}`);
  console.log(`  length ${len}  seed ${seed}`);
  console.log(`  ${shown}`);
}
