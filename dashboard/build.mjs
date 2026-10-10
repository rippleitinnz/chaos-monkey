// Build dist/dashboard.html from dashboard/dashboard.html: minify the script
// with terser and strip CSS whitespace, so the page fits the 4096-byte
// AppLoader limit. FUZZER and NAMESPACE stay as placeholders for publish.
import fs from "node:fs";
import { minify } from "terser";
import { FAULTS } from "../src/apploader/faults.mjs";

// Labels and the must-pass set come from src/apploader/faults.mjs.
const src = fs.readFileSync(new URL("./dashboard.html", import.meta.url), "utf8")
  .replace("__LABELS__", FAULTS.map((f) => f.short).join("|"))
  .replace("__PASS__", FAULTS.flatMap((f, i) => (f.pass ? [i] : [])).join(","));
if (/__LABELS__|__PASS__/.test(src)) throw new Error("dashboard placeholders not filled");
const js = src.match(/<script>([\s\S]*)<\/script>/)[1];
const css = src.match(/<style>([\s\S]*)<\/style>/)[1];
const min = await minify(js, { compress: { passes: 2 }, mangle: { toplevel: true }, format: { ascii_only: false } });
const cssMin = css.replace(/\n/g, "").replace(/\s*([{}:;,>])\s*/g, "$1").replace(/;}/g, "}");
const out = src
  .replace(css, cssMin)
  .replace(js, min.code)
  .replace(/>\s*\n\s*</g, "><");
fs.mkdirSync(new URL("../dist/", import.meta.url), { recursive: true });
fs.writeFileSync(new URL("../dist/dashboard.html", import.meta.url), out);
const worst = Buffer.byteLength(out.replace("FUZZER", "r".padEnd(35, "A")).replace("NAMESPACE", "B".repeat(64)));
if (worst > 4096) { console.error(`dist/dashboard.html renders to ${worst} bytes; the AppLoader limit is 4096`); process.exit(1); }
console.log("dist/dashboard.html", Buffer.byteLength(out), `bytes; ${worst}/4096 once published`);
