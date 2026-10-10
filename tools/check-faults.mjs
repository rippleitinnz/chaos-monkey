// Fail if src/apploader/faults.mjs disagrees with src/apploader/gen.h.
//
//   node tools/check-faults.mjs
//
// Checks: every F_* id's number equals its index in FAULTS, F_COUNT equals the
// table length, and the set of must-pass ids equals what fault_is_pass() lists.
// Also writes build/apploader_fault_names.inc for test/native_check.cpp.

import fs from "node:fs";
import { FAULTS } from "../src/apploader/faults.mjs";

const die = (m) => { console.error("check-faults: " + m); process.exit(1); };
const h = fs.readFileSync("src/apploader/gen.h", "utf8");

const ids = {};
for (const m of h.matchAll(/#define\s+(F_[A-Z0-9_]+)\s+(\d+)/g)) ids[m[1]] = Number(m[2]);
if (ids.F_COUNT !== FAULTS.length) die(`F_COUNT is ${ids.F_COUNT}, faults.mjs has ${FAULTS.length}`);
FAULTS.forEach((f, i) => {
  if (ids[f.id] !== i) die(`${f.id} is ${ids[f.id]} in gen.h but index ${i} in faults.mjs`);
});

const body = h.match(/fault_is_pass\(int f\)\s*\{\s*return ([^;]+);/);
if (!body) die("fault_is_pass() not found in gen.h");
const passIds = new Set([...body[1].matchAll(/f == (F_[A-Z0-9_]+)/g)].map((m) => ids[m[1]]));
const tablePass = new Set(FAULTS.flatMap((f, i) => (f.pass ? [i] : [])));
if (passIds.size !== tablePass.size || [...passIds].some((i) => !tablePass.has(i)))
  die(`must-pass ids differ: gen.h {${[...passIds]}} vs faults.mjs {${[...tablePass]}}`);

fs.mkdirSync("build", { recursive: true });
fs.writeFileSync("build/apploader_fault_names.inc",
  FAULTS.map((f) => JSON.stringify(f.name + (f.pass ? " (pass)" : ""))).join(",\n") + "\n");

console.log(`check-faults: ${FAULTS.length} classes, must-pass {${[...tablePass].join(",")}} — gen.h and faults.mjs agree ✓`);
