// Build dist/dashboard.html from dashboard/dashboard.html: minify the script
// with terser and strip CSS whitespace, so the page fits the 4096-byte
// AppLoader limit. FUZZER and NAMESPACE stay as placeholders for publish.
import fs from "node:fs";
import { minify } from "terser";

const src = fs.readFileSync(new URL("./dashboard.html", import.meta.url), "utf8");
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
console.log("dist/dashboard.html", Buffer.byteLength(out), "bytes (placeholders unfilled)");
