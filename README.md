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
| **A: AppLoader** | `featurePWALoader` document validation, via `emit()` | PWA devnet | built, verified |
| B: RNG invariants | `featureRNG`: attempts to read the RNG state; `dice` / `util_random` edges | RNG devnet | planned |
| C: Hook API boundaries | pointer, length and slot edges across the host functions | any | planned |

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
   or SOH in body) and 2 "quirk pass" classes that must be accepted (`<!doctype svg>` and
   multiple `</html>` tags),
3. wraps it in an `AccountSet`, runs `prepare()` and `emit()`, and reads the consensus
   verdict (`emit()` succeeds or returns `EMISSION_FAILURE` from preflight),
4. records any disagreement in Hook state with the 32 input bytes, so the case can be
   regenerated exactly,
5. re-arms its own Cron schedule every 200 runs, so it runs indefinitely.

Documents that pass are applied, so the fuzzer account's own AppLoader page is
the thing under test and changes constantly.

**Verification.** `test/native_check.cpp` runs the same generator against the real
`ripple::appLoader::validate()` from the `pwabootloader` branch. 500,000 cases:
**0 mismatches**. The generator is correct, and the validator matches its spec offline,
so an on-ledger finding points at the emit path or at the deployed binary differing
from the branch.

**Budget.** Worst-case execution 45,098 instructions (limit 65,535).

## Quick start (PWA devnet)

Needs Node 20.19 or newer (Node 22 recommended): a dependency, `@noble/hashes` 2.x, is ESM-only and older Node cannot `require()` it. Run it anywhere with outbound internet; keep it off production
validators, since `deploy.mjs` saves a funded devnet key to `fuzzer-account.json`
(mode 600, git-ignored).

```bash
npm install
node deploy.mjs                 # faucet account, SetHook, CronSet, first Invoke
node status.mjs                 # runs, correct pass/fail, FINDINGS, harness errors
```

Options: `SEED=s... node deploy.mjs` uses your own funded account;
`DELAY=30` sets the interval in seconds (default 10);
`WSS=` and `FAUCET=` point at another network.

Cron wakes the Hook as a weak *collect call*, so `deploy.mjs` sets `asfTshCollect` on the account and installs the Hook with `hsfCOLLECT`; without both, Cron silently skips it. The Hook fires only on `Cron` and `Invoke` (`HookOn` excludes everything else, so the
`AccountSet`s it emits do not re-trigger it). `node deploy.mjs` sends one `Invoke`
so the first case runs immediately.

## Live dashboard

`dashboard/dashboard.html` is a live view of the fuzzer, itself published as an
on-ledger AppLoader page on its own account (the fuzzer account's page is the fuzz
target and changes with every passing case). It opens a WebSocket to the devnet,
replays recent wakes with `account_tx`, subscribes for new ones, and reads the
counters from Hook state. It opens in light mode (the ◐ button switches to dark for the visit; sandboxed pages have no storage, so it does not persist), explains what the fuzzer does, and shows run counters and the pass/fail split, a coverage
grid of the 22 test classes (green: must pass, amber: must fail, red: a finding),
the latest wakes with the consensus verdict, and the size of the document currently
being served.

```bash
node publish-dashboard.mjs      # second faucet account, AccountSet with the page
```

It prints the URL (`https://pwa.pwapp.xahau-dev.net/<dashboard account>`).
`dist/dashboard.html` is prebuilt (minified to fit 4096 bytes); after editing the
source, rebuild with `npm run build:dashboard` (needs the `terser` dev dependency).

## Building

```bash
make tools      # clones and builds hook-cleaner-c and guard-checker into tools/
make            # dist/fuzz_apploader.wasm, cleaned and guard-checked
make check XAHAUD_SRC=/path/to/xahaud    # native cross-check (pwabootloader branch;
                                         # needs libboost-dev and libxxhash-dev)
```

`make tools` applies `tools/guard-checker-api.patch`: the standalone guard checker
predates `prepare`, `util_random` and `dice` and rejects Hooks that import them.

`include/hook/` holds the Hook headers from the xahaud `pwabootloader` branch
(`sfAppLoader`, `ttCRON`, `ttCRON_SET`, `KEYLET_APP_LOADER`).

## Layout

```
src/apploader/fuzz_apploader.c   the Hook
src/apploader/gen.h              case generator, shared by the Hook and the native check
test/native_check.cpp            generator vs real validator
include/hook/                    Hook API headers (pwabootloader branch)
dist/fuzz_apploader.wasm         prebuilt Hook
deploy.mjs / status.mjs          install and report
publish-dashboard.mjs            publish the live dashboard page
dashboard/                       dashboard source and minifying build
dist/dashboard.html              prebuilt dashboard (placeholders filled at publish)
tools/guard-checker-api.patch    adds prepare/util_random/dice to the guard checker
```

## State format

| Key | Value |
|---|---|
| `STATS` | runs, correct pass, correct fail, findings, harness errors (5 × u32 BE) |
| sha512Half(document) | fault id (1), consensus passed (1), length (u16), seed (32), first 200 bytes |
