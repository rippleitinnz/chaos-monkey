// Chaos Monkey, harness C — the single source of truth for every test case.
//
// `node tools/gen-cases.mjs hookapi` (run by `make hookapi`) turns this table into:
//   src/hookapi/cases.gen.h        the Hook's dispatch switch + EXPECTED[]
//   dist/dashboard-hookapi.html    the dashboard's case labels
// and status-hookapi.mjs imports it directly, so the three can never drift.
//
// INCLUSION RULE (no exceptions):
//   A case is in this table only if its expected value is stated on that
//   function's own page of the Xahau Hook API docs (xahau.network/docs/hooks/
//   functions/...) AND the release build 2026.9.29 (xahaud 0f3258d) returns
//   exactly that value for exactly these arguments. Behaviour the docs do not
//   cover (slot 0, field id 0, MEM_OVERLAP, TOO_SMALL on hook_account /
//   ledger_nonce / ledger_last_hash, ...) is NOT tested here; see
//   docs/hookapi-doc-gaps.md.
//
//   One deliberate exception to "code agrees": `ed.ok`. The docs say
//   etxn_details writes 127 bytes when cbak is defined; 0f3258d writes 138.
//   The spec value is used, so this case is EXPECTED to report a finding.
//
// Memory model (asserted at build time by tools/check-wasm-memory.mjs):
//   the Hook's linear memory is exactly MEM_SIZE = 0x20000 (2 pages).
//   OOB  = 0xFFFFFFF0          start address beyond memory
//   EDGE = MEM_SIZE - 16       in bounds, but a 32-byte access overruns by 16
//
// Buffers / constants available to `call` (defined in fuzz_hookapi.c):
//   WB  256-byte write scratch      RB   256-byte read scratch (zeros)
//   PREP 600-byte scratch           FK   32-byte fixture key (0xA5..), holds 32 bytes
//   MK  32-byte key never written (0xFF..)
//   Z20 20 zero bytes (account zero)
//   RZERO "rrrrrrrrrrrrrrrrrrrrrhoLvTp" (27, valid)   RBAD same, bad checksum (27)
//   S1  STObject {Flags=0} (5)   S2 {Flags=0, Sequence=1} (10)   F1 field Sequence=1 (5)
//   K_DELAY "DELAY" (5, set by deploy, value 4 bytes)   K_NOPE "NOPE" (4, never set)
//   FIXSET  return value of this run's fixture write: state_set(RB,32,FK,32)
//
// `exp` is either an error name from include/hook/error.h or an exact number.
// `doc` quotes or paraphrases the docs line the expectation rests on.

export const CASES = [
  // ── hook_account ─────────────────────────────────────────────────────────
  { id: "ha.oob",   fn: "hook_account",     call: "hook_account(OOB, 20)",                 exp: "OUT_OF_BOUNDS",   doc: "OUT_OF_BOUNDS: pointers/lengths outside hook memory" },
  { id: "ha.ok",    fn: "hook_account",     call: "hook_account(WB, 20)",                  exp: 20,                doc: "writes the 20 byte Account ID; returns bytes written" },
  // ── ledger_nonce / ledger_last_hash ──────────────────────────────────────
  { id: "ln.oob",   fn: "ledger_nonce",     call: "ledger_nonce(OOB, 32)",                 exp: "OUT_OF_BOUNDS",   doc: "OUT_OF_BOUNDS" },
  { id: "ln.ok",    fn: "ledger_nonce",     call: "ledger_nonce(WB, 32)",                  exp: 32,                doc: "writes a 32 byte random value; returns bytes written" },
  { id: "lh.oob",   fn: "ledger_last_hash", call: "ledger_last_hash(OOB, 32)",             exp: "OUT_OF_BOUNDS",   doc: "OUT_OF_BOUNDS" },
  { id: "lh.ok",    fn: "ledger_last_hash", call: "ledger_last_hash(WB, 32)",              exp: 32,                doc: "writes the 32 byte hash; returns bytes written" },
  // ── util_sha512h ─────────────────────────────────────────────────────────
  { id: "sh.wOOB",  fn: "util_sha512h",     call: "util_sha512h(OOB, 32, RB, 32)",         exp: "OUT_OF_BOUNDS",   doc: "OUT_OF_BOUNDS" },
  { id: "sh.rOOB",  fn: "util_sha512h",     call: "util_sha512h(WB, 32, OOB, 32)",         exp: "OUT_OF_BOUNDS",   doc: "OUT_OF_BOUNDS" },
  { id: "sh.rEDGE", fn: "util_sha512h",     call: "util_sha512h(WB, 32, EDGE, 32)",        exp: "OUT_OF_BOUNDS",   doc: "OUT_OF_BOUNDS (read runs 16 bytes past the end)" },
  { id: "sh.small", fn: "util_sha512h",     call: "util_sha512h(WB, 31, RB, 32)",          exp: "TOO_SMALL",       doc: "TOO_SMALL: output buffer isn't large enough (should be at least 32)" },
  { id: "sh.len0",  fn: "util_sha512h",     call: "util_sha512h(WB, 32, RB, 0)",           exp: 32,                doc: "bytes written, should always be 32" },
  { id: "sh.ok",    fn: "util_sha512h",     call: "util_sha512h(WB, 32, RB, 32)",          exp: 32,                doc: "bytes written, should always be 32" },
  // ── state ────────────────────────────────────────────────────────────────
  { id: "st.wOOB",  fn: "state",            call: "state(OOB, 256, FK, 32)",               exp: "OUT_OF_BOUNDS",   doc: "OUT_OF_BOUNDS" },
  { id: "st.kOOB",  fn: "state",            call: "state(WB, 256, OOB, 32)",               exp: "OUT_OF_BOUNDS",   doc: "OUT_OF_BOUNDS" },
  { id: "st.kEDGE", fn: "state",            call: "state(WB, 256, EDGE, 32)",              exp: "OUT_OF_BOUNDS",   doc: "OUT_OF_BOUNDS (key runs 16 bytes past the end)" },
  { id: "st.k33",   fn: "state",            call: "state(WB, 256, RB, 33)",                exp: "TOO_BIG",         doc: "TOO_BIG: key larger than 32 bytes" },
  { id: "st.miss",  fn: "state",            call: "state(WB, 256, MK, 32)",                exp: "DOESNT_EXIST",    doc: "DOESNT_EXIST: key has no value on the ledger" },
  { id: "st.small", fn: "state",            call: "state(WB, 16, FK, 32)",                 exp: "TOO_SMALL",       doc: "TOO_SMALL: output buffer too small for the 32-byte value" },
  { id: "st.ok",    fn: "state",            call: "state(WB, 256, FK, 32)",                exp: 32,                doc: "number of bytes written to the write buffer" },
  // ── state_set ────────────────────────────────────────────────────────────
  { id: "ss.vOOB",  fn: "state_set",        call: "state_set(OOB, 32, FK, 32)",            exp: "OUT_OF_BOUNDS",   doc: "OUT_OF_BOUNDS" },
  { id: "ss.kOOB",  fn: "state_set",        call: "state_set(RB, 32, OOB, 32)",            exp: "OUT_OF_BOUNDS",   doc: "OUT_OF_BOUNDS" },
  { id: "ss.k0",    fn: "state_set",        call: "state_set(RB, 32, RB, 0)",              exp: "TOO_SMALL",       doc: "TOO_SMALL: kread_len was 0" },
  { id: "ss.k33",   fn: "state_set",        call: "state_set(RB, 32, RB, 33)",             exp: "TOO_BIG",         doc: "TOO_BIG: kread_len greater than 32" },
  { id: "ss.v257",  fn: "state_set",        call: "state_set(PREP, 257, FK, 32)",          exp: "TOO_BIG",         doc: "TOO_BIG: read_len greater than max hook data size (256)" },
  { id: "ss.ok",    fn: "state_set",        call: "FIXSET",                                exp: 32,                doc: "returns bytes written to Hook State (length of data)" },
  // ── otxn_field ───────────────────────────────────────────────────────────
  { id: "of.oob",   fn: "otxn_field",       call: "otxn_field(OOB, 32, sfAccount)",        exp: "OUT_OF_BOUNDS",   doc: "OUT_OF_BOUNDS" },
  { id: "of.badF",  fn: "otxn_field",       call: "otxn_field(WB, 64, 0xFFFFu)",           exp: "INVALID_FIELD",   doc: "INVALID_FIELD: type 0 field 65535 is not an sf field" },
  { id: "of.badT",  fn: "otxn_field",       call: "otxn_field(WB, 64, 0x7FFF0001u)",       exp: "INVALID_FIELD",   doc: "INVALID_FIELD: serialized type 0x7FFF does not exist" },
  { id: "of.miss",  fn: "otxn_field",       call: "otxn_field(WB, 64, sfDestination)",     exp: "DOESNT_EXIST",    doc: "DOESNT_EXIST: field not in the originating txn (Cron/Invoke carry no Destination)" },
  { id: "of.small", fn: "otxn_field",       call: "otxn_field(WB, 4, sfAccount)",          exp: "TOO_SMALL",       doc: "TOO_SMALL: buffer can't hold the 20-byte field" },
  { id: "of.ok",    fn: "otxn_field",       call: "otxn_field(WB, 64, sfAccount)",         exp: 20,                doc: "STI_ACCOUNT returned without the VL byte: 20 bytes" },
  // ── hook_param ───────────────────────────────────────────────────────────
  { id: "hp.wOOB",  fn: "hook_param",       call: "hook_param(OOB, 32, K_DELAY, 5)",       exp: "OUT_OF_BOUNDS",   doc: "OUT_OF_BOUNDS" },
  { id: "hp.kOOB",  fn: "hook_param",       call: "hook_param(WB, 32, OOB, 5)",            exp: "OUT_OF_BOUNDS",   doc: "OUT_OF_BOUNDS" },
  { id: "hp.k0",    fn: "hook_param",       call: "hook_param(WB, 32, RB, 0)",             exp: "TOO_SMALL",       doc: "TOO_SMALL: parameter name can't be null" },
  { id: "hp.k33",   fn: "hook_param",       call: "hook_param(WB, 32, RB, 33)",            exp: "TOO_BIG",         doc: "TOO_BIG: parameter name greater than 32 bytes" },
  { id: "hp.miss",  fn: "hook_param",       call: "hook_param(WB, 32, K_NOPE, 4)",         exp: "DOESNT_EXIST",    doc: "DOESNT_EXIST: parameter doesn't exist" },
  { id: "hp.ok",    fn: "hook_param",       call: "hook_param(WB, 32, K_DELAY, 5)",        exp: 4,                 doc: "bytes written (DELAY is a 4-byte value)" },
  // ── slots (nothing is ever slotted, so slot 1 is always empty) ───────────
  { id: "sl.oob",   fn: "slot",             call: "slot(OOB, 64, 1)",                      exp: "OUT_OF_BOUNDS",   doc: "OUT_OF_BOUNDS" },
  { id: "sl.size",  fn: "slot_size",        call: "slot_size(1)",                          exp: "DOESNT_EXIST",    doc: "DOESNT_EXIST: slot does not contain any object" },
  { id: "sl.count", fn: "slot_count",       call: "slot_count(1)",                         exp: "DOESNT_EXIST",    doc: "DOESNT_EXIST: slot does not contain any object" },
  { id: "sl.float", fn: "slot_float",       call: "slot_float(1)",                         exp: "DOESNT_EXIST",    doc: "DOESNT_EXIST: slot does not contain any object" },
  { id: "sl.type",  fn: "slot_type",        call: "slot_type(1, 0)",                       exp: "DOESNT_EXIST",    doc: "DOESNT_EXIST: slot_no does not contain an object" },
  { id: "sl.clear", fn: "slot_clear",       call: "slot_clear(1)",                         exp: "DOESNT_EXIST",    doc: "DOESNT_EXIST: slot does not contain any object" },
  { id: "sl.subf",  fn: "slot_subfield",    call: "slot_subfield(1, sfAccount, 0)",        exp: "DOESNT_EXIST",    doc: "DOESNT_EXIST: parent slot is unfilled" },
  // ── etxn_details (etxn_reserve(1) is called first; the hook defines cbak) ─
  { id: "ed.oob",   fn: "etxn_details",     call: "etxn_details(OOB, 138)",                exp: "OUT_OF_BOUNDS",   doc: "OUT_OF_BOUNDS" },
  { id: "ed.small", fn: "etxn_details",     call: "etxn_details(WB, 100)",                 exp: "TOO_SMALL",       doc: "TOO_SMALL: buffer isn't large enough to receive record" },
  { id: "ed.ok",    fn: "etxn_details",     call: "etxn_details(WB, 256)",                 exp: 127,               doc: "writes a 127 byte sfEmitDetails if cbak is defined (0f3258d writes 138: KNOWN DIVERGENCE)" },
  // ── util_accid ───────────────────────────────────────────────────────────
  { id: "ac.wOOB",  fn: "util_accid",       call: "util_accid(OOB, 20, RZERO, 27)",        exp: "OUT_OF_BOUNDS",   doc: "OUT_OF_BOUNDS" },
  { id: "ac.rOOB",  fn: "util_accid",       call: "util_accid(WB, 20, OOB, 27)",           exp: "OUT_OF_BOUNDS",   doc: "OUT_OF_BOUNDS" },
  { id: "ac.small", fn: "util_accid",       call: "util_accid(WB, 19, RZERO, 27)",         exp: "TOO_SMALL",       doc: "TOO_SMALL: write_len not large enough (should be 20)" },
  { id: "ac.big",   fn: "util_accid",       call: "util_accid(WB, 20, RB, 50)",            exp: "TOO_BIG",         doc: "TOO_BIG: read_len longer than an r-address can be" },
  { id: "ac.bad",   fn: "util_accid",       call: "util_accid(WB, 20, RBAD, 27)",          exp: "INVALID_ARGUMENT", doc: "INVALID_ARGUMENT: not a valid r-address (bad checksum)" },
  { id: "ac.ok",    fn: "util_accid",       call: "util_accid(WB, 20, RZERO, 27)",         exp: 20,                doc: "writes a 20 byte Account ID" },
  // ── util_raddr ───────────────────────────────────────────────────────────
  { id: "ra.wOOB",  fn: "util_raddr",       call: "util_raddr(OOB, 64, Z20, 20)",          exp: "OUT_OF_BOUNDS",   doc: "OUT_OF_BOUNDS" },
  { id: "ra.rOOB",  fn: "util_raddr",       call: "util_raddr(WB, 64, OOB, 20)",           exp: "OUT_OF_BOUNDS",   doc: "OUT_OF_BOUNDS" },
  { id: "ra.len19", fn: "util_raddr",       call: "util_raddr(WB, 64, Z20, 19)",           exp: "INVALID_ARGUMENT", doc: "INVALID_ARGUMENT: read_len was not 20" },
  { id: "ra.small", fn: "util_raddr",       call: "util_raddr(WB, 26, Z20, 20)",           exp: "TOO_SMALL",       doc: "TOO_SMALL: write_len can't hold the 27-char r-address" },
  { id: "ra.ok",    fn: "util_raddr",       call: "util_raddr(WB, 64, Z20, 20)",           exp: 27,                doc: "bytes written = length of the r-address (account zero is 27 chars)" },
  // ── sto_emplace / sto_erase (valid inputs only; parse paths are amendment-gated) ─
  { id: "se.wOOB",  fn: "sto_emplace",      call: "sto_emplace(OOB, 64, S1, 5, F1, 5, sfSequence)", exp: "OUT_OF_BOUNDS", doc: "OUT_OF_BOUNDS" },
  { id: "se.small", fn: "sto_emplace",      call: "sto_emplace(WB, 9, S1, 5, F1, 5, sfSequence)",   exp: "TOO_SMALL",     doc: "TOO_SMALL: output must be at least source + field (10)" },
  { id: "se.ok",    fn: "sto_emplace",      call: "sto_emplace(WB, 64, S1, 5, F1, 5, sfSequence)",  exp: 10,              doc: "bytes written: {Flags, Sequence} = 10" },
  { id: "er.small", fn: "sto_erase",        call: "sto_erase(WB, 4, S1, 5, sfFlags)",               exp: "TOO_SMALL",     doc: "TOO_SMALL: output must be at least as large as the source" },
  { id: "er.miss",  fn: "sto_erase",        call: "sto_erase(WB, 64, S1, 5, sfSequence)",           exp: "DOESNT_EXIST",  doc: "DOESNT_EXIST: field_id isn't present in the STObject" },
  { id: "er.ok",    fn: "sto_erase",        call: "sto_erase(WB, 64, S2, 10, sfSequence)",          exp: 5,               doc: "bytes written: {Flags} = 5" },
];

// The one case whose spec value is known to differ from release 0f3258d.
export const KNOWN_DIVERGENCE = { "ed.ok": "docs: 127 bytes with cbak; 0f3258d writes 138" };
