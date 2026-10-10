// Chaos Monkey, harness D — show progress and findings.
//
//   node status-floatsto.mjs
//
// Reads the hook's state on the floatsto fuzzer account (from floatsto-account.json,
// or ADDRESS=r...) and prints the counters plus every recorded finding.

import fs from "node:fs";
import crypto from "node:crypto";
import { XrplClient } from "xrpl-client";

const WSS = process.env.WSS || "wss://pwapp.xahau-dev.net";
const address = process.env.ADDRESS ||
  JSON.parse(fs.readFileSync("floatsto-account.json", "utf8")).address;
const ns = crypto.createHash("sha256").update("chaos-fuzzer-floatsto").digest("hex").toUpperCase();

// Case names aligned with EXP[] in fuzz_floatsto.c
const CASE_NAMES = [
  // Group 0: float_* invalid args
  "float_set exp>80",     "float_set exp<-96",  "float_negate garbage",
  "float_sum garbage",    "float_mul garbage",  "float_div by zero",
  "float_cmp mode=0",     "float_cmp garbage",  "float_int dp=16",
  "float_int neg no-abs",
  // Group 1: float_* correct results
  "float_one()",          "float_cmp equal",    "float_cmp greater",
  "float_sign neg",       "float_mantissa(1)",  "float_int(1,0)",
  "float_int(2,0)",       "float_inv(1)==1",    "float_mul(1,0)",
  "float_root(1,2)==1",
  // Group 2: sto_* OOB + invalid
  "sto_val OOB",          "sto_sub OOB",        "sto_arr OOB",
  "sto_emp OOB",          "sto_era OOB",        "sto_val len=0",
  "sto_val len=1",        "sto_sub len=0",      "sto_arr len=0",
  "sto_val zeros",
  // Group 3: etxn_* / emit
  "etxn_gen()",           "etxn_nonce OOB",     "etxn_nonce small",
  "etxn_nonce exact",     "etxn_fee_base",      "etxn_det small",
  "etxn_det ok",          "emit hash OOB",      "emit txn OOB",
  "emit len=0",
  // Group 4: float_sto / log / root edge / mulratio
  "float_sto OOB",        "float_sto_set OOB",  "float_root(0,2)",
  "float_root n=0",       "float_log(-1)",      "float_log garbage",
  "float_mulratio d=0",   "float_inv(0)",       "float_sign(0)",
  "float_cmp(0==0)",
];

const EXPECTED = [
  // Group 0
  -28,-29,-10024,-10024,-10024,-25,-7,-10024,-7,-33,
  // Group 1
  1,1,1,1,1,1,2,1,0,1,
  // Group 2
  -1,-1,-1,-1,-1,0,0,-1,-1,0,
  // Group 3
  1,-1,-4,32,1,-4,1,-1,-1,-11,
  // Group 4
  -1,-1,0,-7,-39,-10024,-25,-25,0,1,
];

const ERROR_NAMES = {
  "-1":     "OUT_OF_BOUNDS",
  "-3":     "TOO_BIG",
  "-4":     "TOO_SMALL",
  "-5":     "DOESNT_EXIST",
  "-7":     "INVALID_ARGUMENT",
  "-11":    "EMISSION_FAILURE",
  "-17":    "INVALID_FIELD",
  "-25":    "DIVISION_BY_ZERO",
  "-28":    "EXPONENT_OVERSIZED",
  "-29":    "EXPONENT_UNDERSIZED",
  "-33":    "CANT_RETURN_NEGATIVE",
  "-39":    "COMPLEX_NOT_SUPPORTED",
  "-10024": "INVALID_FLOAT",
  "-43":    "MEM_OVERLAP",
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
