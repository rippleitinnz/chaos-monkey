// Chaos Monkey, harness C — deploy to the PWA devnet.
//
//   node deploy-hookapi.mjs              create a faucet account, install, start
//   NEW=1 node deploy-hookapi.mjs        start over on a fresh faucet account: the
//                                        old hookapi-account.json is kept as
//                                        hookapi-account.json.bak.<timestamp>
//   SEED=s... node deploy-hookapi.mjs    use an existing funded account instead
//
// Steps: account -> AccountSet asfTshCollect -> SetHook (HookOn: Cron +
// Invoke only, hsfCOLLECT) -> CronSet
// (every DELAY seconds, 256 repeats; the hook re-arms itself) -> one Invoke
// so the first case runs immediately.

import fs from "node:fs";
import crypto from "node:crypto";
import { XrplClient } from "xrpl-client";
import { derive, signAndSubmit, utils } from "xrpl-accountlib";

const WSS = process.env.WSS || "wss://pwapp.xahau-dev.net";
const FAUCET = process.env.FAUCET || "https://faucet.pwapp.xahau-dev.net/accounts";
const DELAY = Number(process.env.DELAY || 10);
const WASM = process.env.WASM || "dist/fuzz_hookapi.wasm";
const ACCOUNT_FILE = "hookapi-account.json";

const client = new XrplClient(WSS);

// Fires only on ttCRON (92) and ttINVOKE (99). A set bit means "do not fire",
// except ttHOOK_SET (22) whose bit is inverted, so it is cleared too.
const ALL = (1n << 256n) - 1n;
const HOOK_ON = (ALL & ~(1n << 92n) & ~(1n << 99n) & ~(1n << 22n))
  .toString(16).padStart(64, "0").toUpperCase();

async function getAccount() {
  if (process.env.SEED) return derive.familySeed(process.env.SEED);
  if (process.env.NEW === "1" && fs.existsSync(ACCOUNT_FILE)) {
    const ts = new Date().toISOString().replace(/[-:]/g, "").replace("T", "_").slice(0, 15);
    const kept = `${ACCOUNT_FILE}.bak.${ts}`;
    fs.renameSync(ACCOUNT_FILE, kept);
    console.log("NEW=1: previous account kept in", kept);
  }
  if (fs.existsSync(ACCOUNT_FILE)) {
    const saved = JSON.parse(fs.readFileSync(ACCOUNT_FILE, "utf8"));
    console.log("Using saved account", saved.address);
    return derive.familySeed(saved.secret);
  }
  console.log("Requesting faucet account from", FAUCET);
  const res = await fetch(FAUCET, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  const body = await res.json();
  const secret = body?.account?.secret || body?.secret || body?.seed || body?.account?.seed;
  if (!secret) {
    console.error("Unrecognised faucet response — fund an account yourself and rerun with SEED=...\n", JSON.stringify(body, null, 2));
    process.exit(1);
  }
  const acct = derive.familySeed(secret);
  fs.writeFileSync(ACCOUNT_FILE, JSON.stringify({ address: acct.address, secret }, null, 2), { mode: 0o600 });
  console.log("Faucet account", acct.address, "(saved to", ACCOUNT_FILE + ")");
  await new Promise((r) => setTimeout(r, 8000)); // let the funding validate
  return acct;
}

async function submit(account, tx, label) {
  const { txValues } = await utils.accountAndLedgerSequence(client, account);
  const full = { ...txValues, ...tx, Fee: "0" };
  const r = await signAndSubmit(full, client, account);
  const result = r.response?.engine_result;
  console.log(`${label.padEnd(10)} ${result}  ${r.tx_id}`);
  if (!["tesSUCCESS", "terQUEUED"].includes(result)) {
    console.error(JSON.stringify(r.response, null, 2));
    process.exit(1);
  }
  await new Promise((res) => setTimeout(res, 6000)); // wait for validation
}

const account = await getAccount();
const wasmHex = fs.readFileSync(WASM).toString("hex").toUpperCase();
const ns = crypto.createHash("sha256").update("chaos-fuzzer-hookapi").digest("hex").toUpperCase();

// Cron wakes the owner's hooks as a weak "collect call": the account must
// set lsfTshCollect and the hook must carry hsfCOLLECT, or Cron never fires it.
await submit(account, { TransactionType: "AccountSet", SetFlag: 11 /* asfTshCollect */ }, "AccountSet");

await submit(account, {
  TransactionType: "SetHook",
  Hooks: [{
    Hook: {
      CreateCode: wasmHex,
      HookOn: HOOK_ON,
      HookNamespace: ns,
      HookApiVersion: 0,
      Flags: 1 | 4, // hsfOverride | hsfCOLLECT
      HookParameters: [{
        HookParameter: {
          HookParameterName: Buffer.from("DELAY").toString("hex").toUpperCase(),
          HookParameterValue: DELAY.toString(16).padStart(8, "0").toUpperCase(),
        },
      }],
    },
  }],
}, "SetHook");

await submit(account, {
  TransactionType: "CronSet",
  StartTime: 0,
  RepeatCount: 256,
  DelaySeconds: DELAY,
}, "CronSet");

await submit(account, { TransactionType: "Invoke" }, "Invoke");

console.log(`\nHook API fuzzer running on ${account.address}, one case every ${DELAY}s.`);
console.log(`Namespace ${ns}`);
console.log("Check progress with: node status-hookapi.mjs");
client.close();
