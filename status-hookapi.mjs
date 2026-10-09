// Chaos Monkey, harness C — show progress and findings.
//
//   node status-hookapi.mjs
//
// Reads the hook's state on the hookapi fuzzer account (from hookapi-account.json,
// or ADDRESS=r...) and prints the counters plus every recorded finding.

import fs from "node:fs";
import crypto from "node:crypto";
import { XrplClient } from "xrpl-client";

const WSS = process.env.WSS || "wss://pwapp.xahau-dev.net";
const address = process.env.ADDRESS ||
  JSON.parse(fs.readFileSync("hookapi-account.json", "utf8")).address;
const ns = crypto.createHash("sha256").update("chaos-fuzzer-hookapi").digest("hex").toUpperCase();

// Case names aligned with cases.h CASE_NAMES[]
const CASE_NAMES = [
  "hook_account OOB", "nonce OOB",       "hash OOB",
  "sha512h wOOB",     "sha512h rOOB",    "state wOOB",
  "state kOOB",       "state_set vOOB",  "state_set kOOB",
  "otxn_field wOOB",  "param wOOB",      "param kOOB",
  "slot wOOB",        "etxn_det OOB",    "accid wOOB",
  "raddr wOOB",       "sha512h rEDGE",   "state kEDGE",
  "acct small",       "nonce small",     "hash small",
  "sha512h small",    "state w=0",       "state k=0",
  "state k=33",       "ss k=0",          "ss k=33",
  "param k=0",        "param k=33",      "slot empty",
  "slot_size empty",  "slot_cnt empty",  "slot_sub empty",
  "slot_arr empty",   "slot_flt empty",  "slot_type empty",
  "state missing",    "slot(0)",         "slot_clr(0)",
  "field 0x0000",     "field 0xFFFF",    "sha512 ov==",
  "sha512 ov+",       "sha512 ov-",      "state ov",
  "sha512 len=0",     "otxn sfType",     "otxn sfFee",
  "acct exact",       "nonce exact",
];

const EXPECTED = [
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 0-17 OUT_OF_BOUNDS
  -4,-4,-4,-4,-4,  // 18-22 TOO_SMALL
  -4,-3,-4,-3,-4,-3,  // 23-28 key boundaries
  -5,-5,-5,-5,-5,-5,-5,-5, // 29-36 DOESNT_EXIST
  -5,-5,   // 37-38 slot(0)/slot_clear(0) — empty slot, not invalid arg
  -17,-17, // 39-40 INVALID_FIELD — 0x0000/0xFFFF are not valid sf codes
  -43,-43,-43,-43, // 41-44 MEM_OVERLAP
  32, -5, -5, 20, 32, // 45-49: sha512h len=0, sfType/sfFee absent on Cron, acct exact, nonce exact
];

const ERROR_NAMES = {
  "-1": "OUT_OF_BOUNDS",
  "-3": "TOO_BIG",
  "-4": "TOO_SMALL",
  "-5": "DOESNT_EXIST",
  "-7": "INVALID_ARGUMENT",
  "-17": "INVALID_FIELD",
  "-43": "MEM_OVERLAP",
};

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
// STATS key is 5 bytes "STATS" = 5354415453 (rest 0), data is 16 bytes = 32 hex chars
const stats = entries.find((e) => e.HookStateKey && e.HookStateKey.toUpperCase().endsWith("5354415453") && e.HookStateData.length === 32);
if (stats) {
  const d = stats.HookStateData;
  console.log(`Account   ${address}`);
  console.log(`Runs      ${u32(d, 0)}`);
  console.log(`Correct   ${u32(d, 4)}`);
  console.log(`FINDINGS  ${u32(d, 8)}`);
} else {
  console.log(`Account   ${address}`);
  console.log("No STATS yet — the hook has not run.");
}

// Findings: key has case_id in byte 0, rest 0. Data: case(1) exp_lo(4) act_lo(4)
const findings = entries.filter((e) => {
  if (!e.HookStateData || e.HookStateData.length < 18) return false;
  if (e.HookStateKey && e.HookStateKey.toUpperCase().endsWith("5354415453")) return false;
  return true;
});

if (findings.length === 0) {
  console.log("\nNo findings — all tested cases returned expected values.");
} else {
  console.log(`\n${"─".repeat(60)}`);
  console.log("FINDINGS:");
  for (const e of findings) {
    const d = Buffer.from(e.HookStateData, "hex");
    const caseId = d[0];
    const expRaw = d.readInt32BE(1);
    const actRaw = d.readInt32BE(5);
    const name = CASE_NAMES[caseId] || `case ${caseId}`;
    const expName = ERROR_NAMES[String(expRaw)] || String(expRaw);
    const actName = ERROR_NAMES[String(actRaw)] || String(actRaw);
    console.log(`  case ${String(caseId).padStart(2)} (${name}): expected ${expName}, got ${actName}`);
  }
}
client.close();
