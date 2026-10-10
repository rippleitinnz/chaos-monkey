// Assert that a Hook's linear memory is exactly the size its source assumes.
//
//   node tools/check-wasm-memory.mjs <deployed.wasm> <raw.wasm> <source.c>
//
// <deployed.wasm> is the hook-cleaner output (what SetHook installs): its
// memory section is checked. <raw.wasm> is clang's output, disassembled for
// memory.grow (llvm-objdump cannot read hook-cleaner's padded LEBs; the
// cleaner only strips sections and re-pads, it adds no instructions).
//
// Reads `#define MEM_SIZE 0x...` from the source and the memory section of the
// module. Fails if they differ, if memory is imported, if a maximum is set
// below the minimum, or if the disassembly contains memory.grow — any of
// which would make the OOB / EDGE test pointers lie. Needs llvm-objdump.

import fs from "node:fs";
import { execFileSync } from "node:child_process";

const [wasmPath, rawPath, srcPath] = process.argv.slice(2);
const die = (m) => { console.error("check-wasm-memory: " + m); process.exit(1); };
if (!wasmPath || !rawPath || !srcPath) die("usage: check-wasm-memory.mjs <deployed.wasm> <raw.wasm> <source.c>");

const m = fs.readFileSync(srcPath, "utf8").match(/#define\s+MEM_SIZE\s+(0x[0-9a-fA-F]+|\d+)u?/);
if (!m) die(`no MEM_SIZE in ${srcPath}`);
const want = Number(m[1]);

const b = fs.readFileSync(wasmPath);
const leb = (i) => { let r = 0, s = 0, x; do { x = b[i++]; r |= (x & 0x7f) << s; s += 7; } while (x & 0x80); return [r >>> 0, i]; };

let i = 8, pages = null, imported = false;
while (i < b.length) {
  const id = b[i++]; let sz; [sz, i] = leb(i); const end = i + sz;
  if (id === 2 && b.subarray(i, end).includes(Buffer.from("memory"))) imported = true;
  if (id === 5) {
    let n, j = i; [n, j] = leb(j);
    if (n !== 1) die(`expected 1 memory, found ${n}`);
    const flags = b[j++]; let min; [min, j] = leb(j);
    if (flags & 1) { let max; [max, j] = leb(j); if (max < min) die("memory max < min"); }
    pages = min;
  }
  i = end;
}
if (imported) die("memory is imported; its size is not fixed by the module");
if (pages === null) die("no memory section");
const have = pages * 65536;
if (have !== want) die(`module memory is 0x${have.toString(16)} (${pages} pages) but source assumes MEM_SIZE 0x${want.toString(16)}`);
// memory.grow would let the size change at run time: disassemble and refuse it.
let dis = "";
try { dis = execFileSync(process.env.OBJDUMP || "llvm-objdump", ["-d", rawPath], { encoding: "utf8", maxBuffer: 1 << 24, timeout: 30000 }); }
catch (e) { die("llvm-objdump failed (set OBJDUMP=...): " + e.message); }
if (!/Disassembly of section CODE/.test(dis)) die("could not disassemble " + rawPath);
if (/memory\.grow/.test(dis)) die("module contains memory.grow");
console.log(`check-wasm-memory: ${wasmPath} memory = 0x${have.toString(16)} (${pages} pages) = MEM_SIZE, no memory.grow ✓`);
