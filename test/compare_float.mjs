// Compare native release-code results with the spec values in cases.mjs.
//   node test/compare_float.mjs build/native_float_0 build/native_float_1
// (binaries in order amendment OFF, amendment ON). Every case must equal its
// spec value in both; AMENDMENT_DEPENDENT cases need only the ON build to match.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { CASES, KNOWN_DIVERGENCE, AMENDMENT_DEPENDENT } from "../src/floatsto/cases.mjs";
const ERR = {};
for (const m of fs.readFileSync("include/hook/error.h", "utf8").matchAll(/#define\s+([A-Z_]+)\s+(-\d+)/g)) ERR[m[1]] = m[2];
const want = (c) => (c.exp in ERR ? ERR[c.exp] : String(c.exp));
let bad = 0;
const runs = process.argv.slice(2).map((bin) => {
  const out = {};
  for (const line of execFileSync(bin, { encoding: "utf8" }).trim().split("\n")) { const [id, v] = line.split(" "); out[id] = v; }
  return [bin, out];
});
for (const c of CASES.filter((c) => c.native)) {
  const vals = runs.map(([b, o]) => o[c.id]);
  const ok = vals.every((v) => v === want(c));
  const amend = !ok && AMENDMENT_DEPENDENT[c.id] && vals.at(-1) === want(c);
  const known = KNOWN_DIVERGENCE[c.id];
  if (!ok && !amend && !known) bad++;
  console.log(`${ok ? "OK   " : amend ? "AMEND" : known ? "KNOWN" : "FAIL "} ${c.id.padEnd(9)} spec ${want(c).padStart(20)}  release ${vals.map((v) => v.padStart(20)).join(" ")}`);
}
console.log(bad ? `\n${bad} float case(s) where release code != spec value`
  : "\nall native float cases match the spec (AMEND = only with the amendment enabled)");
process.exit(bad ? 1 : 0);
