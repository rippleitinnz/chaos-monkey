// Chaos Monkey, harness A — show progress and findings.
//
//   node status.mjs
//
// Reads the hook's state on the fuzzer account (from fuzzer-account.json, or
// ADDRESS=r...) and prints the counters plus every recorded finding.

import fs from "node:fs";
import crypto from "node:crypto";
import { XrplClient } from "xrpl-client";

const WSS = process.env.WSS || "wss://pwapp.xahau-dev.net";
const address = process.env.ADDRESS ||
  JSON.parse(fs.readFileSync("fuzzer-account.json", "utf8")).address;
const ns = crypto.createHash("sha256").update("chaos-fuzzer-apploader").digest("hex").toUpperCase();

const FAULTS = [
  "none (must pass)", "double BOM", "VT before opener", "<!doctype> without whitespace",
  "<htmlx> opener", "no <html> element", "missing </html>", "</html/>", "</htmlx>",
  "trailing garbage", "truncated UTF-8 at end", "4097 bytes", "U+FFFE", "U+FFFF",
  "overlong 2-byte", "overlong 3-byte", "surrogate", "above U+10FFFF",
  "lone continuation", "NUL", "DEL", "VT in body",
];

const client = new XrplClient(WSS);
const entries = [];
let marker;
do {
  const r = await client.send({ command: "account_namespace", account: address, namespace_id: ns, marker });
  if (r.error) { console.error(r); process.exit(1); }
  entries.push(...(r.namespace_entries || []));
  marker = r.marker;
} while (marker);

const u32 = (h, o) => parseInt(h.slice(o * 2, o * 2 + 8), 16);
const stats = entries.find((e) => e.HookStateData.length === 40);
if (stats) {
  const d = stats.HookStateData;
  console.log(`Account ${address}`);
  console.log(`Runs            ${u32(d, 0)}`);
  console.log(`Correct (pass)  ${u32(d, 4)}`);
  console.log(`Correct (fail)  ${u32(d, 8)}`);
  console.log(`FINDINGS        ${u32(d, 12)}`);
  console.log(`Harness errors  ${u32(d, 16)}`);
} else console.log("No STATS yet — the hook has not run.");

for (const e of entries.filter((e) => e.HookStateData.length >= 72)) {
  const d = Buffer.from(e.HookStateData, "hex");
  const fault = d[0], observedPass = d[1], len = d.readUInt16BE(2);
  const seed = d.subarray(4, 36).toString("hex");
  const head = d.subarray(36);
  const shown = [...head].map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : `\\x${b.toString(16).padStart(2, "0")}`)).join("");
  console.log(`\nFINDING  ${FAULTS[fault] || fault}: expected ${fault === 0 ? "pass" : "fail"}, consensus said ${observedPass ? "PASS" : "FAIL"}`);
  console.log(`  length ${len}  seed ${seed}`);
  console.log(`  ${shown}`);
}
client.close();
