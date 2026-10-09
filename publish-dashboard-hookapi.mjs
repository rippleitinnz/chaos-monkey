// Chaos Monkey — publish the Hook API dashboard as an on-ledger AppLoader page.
//
//   node publish-dashboard-hookapi.mjs
//   SEED=s... node publish-dashboard-hookapi.mjs
//
// Uses a separate account (hookapi-dashboard-account.json) so the fuzzer
// account's page isn't overwritten.

import fs from "node:fs";
import crypto from "node:crypto";
import { XrplClient } from "xrpl-client";
import { derive, signAndSubmit, utils } from "xrpl-accountlib";

const WSS = process.env.WSS || "wss://pwapp.xahau-dev.net";
const FAUCET = process.env.FAUCET || "https://faucet.pwapp.xahau-dev.net/accounts";
const PWA = process.env.PWA || "https://pwa.pwapp.xahau-dev.net/";
const ACCOUNT_FILE = "hookapi-dashboard-account.json";

const fuzzer = process.env.FUZZER ||
  JSON.parse(fs.readFileSync("hookapi-account.json", "utf8")).address;
const ns = crypto.createHash("sha256").update("chaos-fuzzer-hookapi").digest("hex").toUpperCase();

const page = fs.readFileSync("dist/dashboard-hookapi.html", "utf8")
  .replace("FUZZER", fuzzer)
  .replace("NAMESPACE", ns);
const bytes = Buffer.byteLength(page);
if (bytes > 4096) {
  console.error(`dashboard is ${bytes} bytes; the AppLoader limit is 4096`);
  process.exit(1);
}

async function getAccount() {
  if (process.env.SEED) return derive.familySeed(process.env.SEED);
  if (fs.existsSync(ACCOUNT_FILE))
    return derive.familySeed(JSON.parse(fs.readFileSync(ACCOUNT_FILE, "utf8")).secret);
  const res = await fetch(FAUCET, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  const body = await res.json();
  const secret = body?.account?.secret || body?.secret || body?.seed || body?.account?.seed;
  if (!secret) {
    console.error("Unrecognised faucet response — rerun with SEED=...\n", JSON.stringify(body, null, 2));
    process.exit(1);
  }
  const acct = derive.familySeed(secret);
  fs.writeFileSync(ACCOUNT_FILE, JSON.stringify({ address: acct.address, secret }, null, 2), { mode: 0o600 });
  console.log("Faucet account", acct.address, "(saved to", ACCOUNT_FILE + ")");
  await new Promise((r) => setTimeout(r, 8000));
  return acct;
}

const client = new XrplClient(WSS);
const account = await getAccount();
const { txValues } = await utils.accountAndLedgerSequence(client, account);
const r = await signAndSubmit({
  ...txValues,
  TransactionType: "AccountSet",
  AppLoader: Buffer.from(page, "utf8").toString("hex").toUpperCase(),
  Fee: "0",
}, client, account);

const result = r.response?.engine_result;
console.log(`AccountSet ${result}  ${r.tx_id}  (${bytes} bytes)`);
if (!["tesSUCCESS", "terQUEUED"].includes(result)) {
  console.error(JSON.stringify(r.response, null, 2));
  process.exit(1);
}
console.log(`\nDashboard: ${PWA}${account.address}`);
client.close();
