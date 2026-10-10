# Chaos Monkey

An on-ledger fuzzer for Xahau. A Hook wakes itself on a Cron schedule,
generates a test case, pushes it through the node's real transaction
pipeline from inside consensus, and records every case where consensus
disagrees with the specification. Nobody, the operator included, steers
which case runs next.

It exists to test new amendments where only a Hook can reach: emitted
transactions (`prepare()` / `emit()`, which run the real preflight), the
Hook API host functions, and invariants such as "no Hook can read the RNG
state".

## Harnesses

| Harness | Target | Network | Status |
|---|---|---|---|
| **A: AppLoader** | `featurePWALoader` document validation, via `emit()`: 26 spec-stated classes | PWA devnet | built, verified vs `98636ac` |
| B: RNG invariants | `featureRNG`: attempts to read the RNG state; `dice` / `util_random` edges | RNG devnet | planned |
| **C: Hook API boundaries** | 64 spec-only cases across 20 host functions | any | built, verified vs `0f3258d` |
| **D: float / STO / emit** | 64 spec-only cases; float results proven natively against release code | any | built, verified vs `0f3258d` |

### Harness A: AppLoader

Each wake the Hook:

1. draws 32 bytes (`ledger_nonce`; on a network with `featureRNG` this can be `util_random`),
2. builds one AppLoader document with `gen()` whose verdict is **known by construction**
   from the rules documented in `AppLoader.h`: a random mix of features that must pass
   (BOM, whitespace, mixed-case tags, `<html/>`, `</html \t>`, multi-byte UTF-8, C1
   controls, noncharacters other than U+FFFE/U+FFFF, exactly 4096 bytes) and at most
   **one** injected fault from 24 classes that must fail (double BOM, VT or other
   forbidden C0 before opener, `<!doctype>` without whitespace, `<htmlx>`, missing or
   malformed `</html>`, `</html` without `>`, trailing garbage, truncated UTF-8, 4097 bytes,
   U+FFFE/U+FFFF, overlongs, surrogates, above U+10FFFF, lone continuation, NUL, DEL, VT
   or SOH in body), or the one extra must-pass class, multiple `</html>` tags (the spec
   says the last one counts),
3. wraps it in an `AccountSet`, runs `prepare()` and `emit()`, and reads the consensus
   verdict (`emit()` succeeds or returns `EMISSION_FAILURE` from preflight),
4. records any disagreement in Hook state with the 32 input bytes, so the case can be
   regenerated exactly,
5. re-arms its own Cron schedule every 200 runs, so it runs indefinitely.

Documents that pass are applied, so the fuzzer account's own AppLoader page is
the thing under test and changes constantly.

**Spec-only (v3).** Every class is stated in `AppLoader.h` or pinned in `PWALoader_test`.
v3 removed the old "`<!doctype svg>` must pass" class. The spec requires "an HTML doctype",
so that class was testing what the validator happens to accept rather than what the
spec says; it is now listed in `docs/hookapi-doc-gaps.md`. That leaves 26 classes:
the clean document, 24 must-fail faults, and `multi✓` (multiple `</html>`; the spec says
the *last* end tag counts). The class table for reports is `src/apploader/faults.mjs`,
and `tools/check-faults.mjs` fails the build if it ever disagrees with `gen.h`.

**Verification.** `make check` (with `XAHAUD_SRC` at the `pwabootloader` branch) runs
`test/native_check.cpp`, which feeds the same generator to the real
`ripple::appLoader::validate()`. Result at `98636ac`: 500,000 cases across all 26 classes,
**0 mismatches**. An on-ledger finding therefore points at the emit path, or at the
deployed binary differing from the branch.

## Harness C: Hook API boundaries

**Rule: spec values only.** Every case is in `src/hookapi/cases.mjs` (the single
source of truth). A case is included only if its expected return value is stated
on that function's own page of the Hook API docs **and** xahaud release 2026.9.29
(`0f3258d`) returns exactly that value for exactly those arguments. Behaviour the
docs don't define is left out and listed in
[`docs/hookapi-doc-gaps.md`](docs/hookapi-doc-gaps.md) instead.

Each wake the Hook:

1. writes a fixture state entry (32 bytes) so `state()` cases have known data from run 1,
2. draws 32 bytes from `ledger_nonce` and selects one of 64 cases (`seed[0] & 63`, unbiased),
3. makes exactly one host call whose result is known in advance,
4. compares it with the expected value (exact match only) and stores any mismatch as a finding.

**64 cases across 20 host functions:** `hook_account`, `ledger_nonce`, `ledger_last_hash`,
`util_sha512h`, `state`, `state_set`, `otxn_field`, `hook_param`, `slot`, `slot_size`,
`slot_count`, `slot_float`, `slot_type`, `slot_clear`, `slot_subfield`, `etxn_details`,
`util_accid`, `util_raddr`, `sto_emplace` and `sto_erase`. The cases cover
OUT_OF_BOUNDS (including edge reads that overrun by 16 bytes), TOO_SMALL, TOO_BIG,
DOESNT_EXIST, INVALID_FIELD, INVALID_ARGUMENT, and exact success lengths.

**Known divergence.** Case `ed.ok`: the docs say `etxn_details` writes 127 bytes when
`cbak` is defined; `0f3258d` writes 138. Expect this one finding from the start.
Any other finding must be re-checked against the release build before it is
reported, because a devnet can run a different binary.

**Memory model.** The Hook's linear memory is exactly `MEM_SIZE` (0x20000, 2 pages).
`make` asserts this against the compiled module (`tools/check-wasm-memory.mjs`) and
refuses `memory.grow`, so the out-of-bounds pointer (`0xFFFFFFF0`) and the edge pointer
(`MEM_SIZE - 16`) can't silently become valid addresses. That was the mistake in the
first version, which assumed 64 KiB.

**State layout:**
- `"STATS"`: runs / correct / findings
- `0xA5 x 32`: the fixture
- `[case, 'F', 0...]`: a finding, holding the case number plus the full 64-bit expected and actual values

No loops; worst-case execution count is 1,048.

```bash
make hookapi                         # regenerate from cases.mjs, build, assert memory, guard-check
NEW=1 node deploy-hookapi.mjs        # fresh faucet account (old key file kept as .bak)
node status-hookapi.mjs              # runs, correct, findings with the spec line for each
node publish-dashboard-hookapi.mjs   # live dashboard (separate account)
```

## Harness D: float, STO, emitted transactions

Same rule and structure as harness C: 64 cases in `src/floatsto/cases.mjs`, spec values
only, exact matches only, built by `tools/gen-cases.mjs`. The cases cover `float_*`
(set, negate, sum, multiply, divide, invert, compare, int, mantissa, sign, log, root,
mulratio, sto, sto_set), `sto_validate`, `sto_subfield`, `sto_subarray`,
`etxn_generation`, `otxn_generation`, `etxn_nonce`, `etxn_fee_base` and `emit`.

**XFL values are exact.** Expected enclosing numbers are computed from the XFL spec
page's bit layout. `cases.mjs` checks that formula against the spec's own worked
examples (1, -1, PI, -PI) before it emits anything.

**Native proof against the release code.** `make check-float` does three things:
- it extracts xahaud's float implementation verbatim (`test/extract_float.py`),
- runs all 40 float cases through it natively, once with the `fixFloatDivide` amendment off and once with it on,
- and compares every result with the spec value.

Every case matches, except that `fd.three` (6/2) and `fi.half` (1/2) are only exact
**with** `fixFloatDivide`. Findings on those two mean the amendment isn't active on that network.

**Known divergences (expected findings):**
- `sv.len0` and `sv.len1`: `sto_validate` returns TOO_SMALL where the docs say 0.
- `og.none`: `otxn_generation` returns 0 where the docs say 1.

See [`docs/hookapi-doc-gaps.md`](docs/hookapi-doc-gaps.md).

**v1 errors, now corrected:** v1 used an out-of-bounds pointer that was really in bounds, so its 10 "OOB" findings were
harness errors. Its `float_set(81, 1)` and `float_set(-97, 1)` cases expected
EXPONENT_OVERSIZED and EXPONENT_UNDERSIZED. Neither is in the `float_set` docs, which
specify INVALID_FLOAT for overflow or underflow caused by mantissa adjustment, and
81/1 is not an overflow at all.

```bash
make floatsto                        # regenerate, build, assert memory, guard-check
make check-float XAHAUD_SRC=../xahaud   # native release-code check (xahaud at 0f3258d)
NEW=1 node deploy-floatsto.mjs       # fresh faucet account (old key file kept as .bak)
node status-floatsto.mjs
node publish-dashboard-floatsto.mjs
```

## Layout

```
src/apploader/fuzz_apploader.c   harness A Hook
src/apploader/gen.h              case generator, shared by the Hook and the native check
src/hookapi/cases.mjs            harness C cases: single source of truth (spec rule inside)
src/hookapi/fuzz_hookapi.c       harness C Hook
src/hookapi/cases.gen.{h,inc}    generated from cases.mjs by tools/gen-cases.mjs
src/floatsto/cases.mjs           harness D cases: single source of truth
src/floatsto/fuzz_floatsto.c     harness D Hook
tools/gen-cases.mjs              generator shared by harnesses C and D
tools/check-wasm-memory.mjs      build-time memory-size assertion
test/extract_float.py            pulls xahaud release float code out verbatim
test/native_float.cpp            runs it on harness D float cases (make check-float)
test/compare_float.mjs           compares native results with spec values
docs/hookapi-doc-gaps.md         doc gaps and doc/code divergences found
test/native_check.cpp            harness A generator vs real validator
include/hook/                    Hook API headers (pwabootloader branch)
dist/fuzz_apploader.wasm         prebuilt harness A Hook
dist/fuzz_hookapi.wasm           prebuilt harness C Hook
deploy.mjs / status.mjs                       harness A install and report
deploy-hookapi.mjs / status-hookapi.mjs       harness C install and report
publish-dashboard.mjs            publish harness A live dashboard
publish-dashboard-hookapi.mjs    publish harness C live dashboard
dashboard/                       harness A dashboard source
dashboard-hookapi/               harness C dashboard source
dist/dashboard.html              prebuilt harness A dashboard
dist/dashboard-hookapi.html      prebuilt harness C dashboard
tools/guard-checker-api.patch    adds prepare/util_random/dice to the guard checker
```

## State format

| Key | Value |
|---|---|
| `STATS` | runs, correct pass, correct fail, findings, harness errors (5 × u32 BE) |
| sha512Half(document) | fault id (1), consensus passed (1), length (u16), seed (32), first 200 bytes |
