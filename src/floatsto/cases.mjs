// Chaos Monkey, harness D — single source of truth for every test case.
//
// `node tools/gen-cases.mjs floatsto` (run by `make floatsto`) turns this table into:
//   src/floatsto/cases.gen.h / cases.gen.inc   the Hook's EXPECTED[] and dispatch
//   build/native_floatsto_cases.inc            the native release-code check
//   dist/dashboard-floatsto.html               the dashboard's case labels
// and status-floatsto.mjs imports it directly.
//
// INCLUSION RULE (same as harness C, no exceptions):
//   the expected value is stated on the function's own page of the Xahau Hook
//   API docs (or, for XFL encodings, derived from the XFL spec page:
//   docs/hooks/concepts/floating-point-numbers-xfl) AND xahaud release
//   2026.9.29 (0f3258d) returns exactly that for exactly these arguments.
//   Float cases are additionally executed natively against the release float
//   code (`make check-float`), so their expected values are proven, not argued.
//
//   KNOWN_DIVERGENCE lists the cases where the docs and the release code
//   disagree. The spec value is used, so those cases are EXPECTED findings.
//
// Hook operands (computed each run through the API, exactly as a Hook would):
//   ONE = float_one()          TWO = float_set(0, 2)      THREE = float_set(0, 3)
//   SIX = float_set(0, 6)      HUNDRED = float_set(2, 1)  NONE = float_negate(ONE)
//   PI  = float_set(-15, 3141592653589793)                BAD = 0xDEADBEEFDEADBEEF
// Buffers: WB/RB 256-byte scratch (RB zeros), OOB = 0xFFFFFFF0 (beyond memory),
//   S1 = {Flags=0} (5), S2 = {Flags=0, Sequence=1} (10), T2 = {0x22,0x00} (truncated UINT32).

// XFL enclosing number from the spec: bit 62 = positive, bits 54..61 = exponent + 97,
// bits 0..53 = 16-digit mantissa. Canonical zero is 0.
const xfl = (mantissa, exponent, negative = false) =>
  mantissa === 0n ? 0n : ((negative ? 0n : 1n) << 62n) | (BigInt(exponent + 97) << 54n) | mantissa;
const E15 = 1000000000000000n;
const V = {
  ONE: xfl(E15, -15), NONE: xfl(E15, -15, true), TWO: xfl(2n * E15, -15), THREE: xfl(3n * E15, -15),
  SIX: xfl(6n * E15, -15), HALF: xfl(5n * E15, -16), PI: xfl(3141592653589793n, -15),
  NPI: xfl(3141592653589793n, -15, true),
};
// Cross-check against the worked examples printed on the XFL spec page.
const DOC = { ONE: 6089866696204910592n, NONE: 1478180677777522688n, PI: 6092008288858500385n, NPI: 1480322270431112481n };
for (const k of Object.keys(DOC)) if (V[k] !== DOC[k]) throw new Error(`XFL formula disagrees with docs for ${k}`);

const n = (x) => x.toString(); // exp values may be BigInt-as-string to keep 64-bit precision

export const CASES = [
  // ── float_one / float_set ────────────────────────────────────────────────
  { id: "fo.one",   call: "float_one()",                        native: "W_one()",                     exp: n(V.ONE),   doc: "XFL of 1 = 6089866696204910592 (spec table)" },
  { id: "fs.one",   call: "float_set(-15, 1000000000000000LL)",  native: "W_set(-15, 1000000000000000LL)", exp: n(V.ONE), doc: "1000000000000000 x 10^-15" },
  { id: "fs.adj",   call: "float_set(0, 1)",                    native: "W_set(0, 1)",                 exp: n(V.ONE),   doc: "mantissa adjusted to 16 digits: 1 x 10^0 = ONE" },
  { id: "fs.pi",    call: "float_set(-15, 3141592653589793LL)", native: "W_set(-15, 3141592653589793LL)", exp: n(V.PI), doc: "PI = 6092008288858500385 (spec table)" },
  { id: "fs.ovf",   call: "float_set(80, 100000000000000000LL)", native: "W_set(80, 100000000000000000LL)", exp: "INVALID_FLOAT", doc: "INVALID_FLOAT: adjustment to 16 digits produced an overflow (exp 82)" },
  { id: "fs.unf",   call: "float_set(-96, 1)",                  native: "W_set(-96, 1)",               exp: "INVALID_FLOAT", doc: "INVALID_FLOAT: adjustment produced an underflow (exp -111)" },
  // ── float_negate ─────────────────────────────────────────────────────────
  { id: "fn.one",   call: "float_negate(ONE)",                  native: "W_neg(ONE)",                  exp: n(V.NONE),  doc: "-1 = 1478180677777522688 (spec table)" },
  { id: "fn.pi",    call: "float_negate(PI)",                   native: "W_neg(PI)",                   exp: n(V.NPI),   doc: "-PI = 1480322270431112481 (spec table)" },
  { id: "fn.bad",   call: "float_negate(BAD)",                  native: "W_neg(BAD)",                  exp: "INVALID_FLOAT", doc: "INVALID_FLOAT: negative enclosing numbers are invalid XFLs" },
  // ── float_sum ────────────────────────────────────────────────────────────
  { id: "fa.two",   call: "float_sum(ONE, ONE)",                native: "W_sum(ONE, ONE)",             exp: n(V.TWO),   doc: "1 + 1 = 2" },
  { id: "fa.zero",  call: "float_sum(ONE, NONE)",               native: "W_sum(ONE, NONE)",            exp: "0",        doc: "1 + -1 = canonical zero (0)" },
  { id: "fa.bad",   call: "float_sum(BAD, ONE)",                native: "W_sum(BAD, ONE)",             exp: "INVALID_FLOAT", doc: "INVALID_FLOAT: parameter not a valid XFL" },
  // ── float_multiply ───────────────────────────────────────────────────────
  { id: "fm.six",   call: "float_multiply(TWO, THREE)",         native: "W_mul(TWO, THREE)",           exp: n(V.SIX),   doc: "2 x 3 = 6" },
  { id: "fm.zero",  call: "float_multiply(ONE, 0)",             native: "W_mul(ONE, 0)",               exp: "0",        doc: "x 0 = canonical zero" },
  // ── float_divide / float_invert ──────────────────────────────────────────
  { id: "fd.three", call: "float_divide(SIX, TWO)",             native: "W_div(SIX, TWO)",             exp: n(V.THREE), doc: "6 / 2 = 3" },
  { id: "fd.dz",    call: "float_divide(ONE, 0)",               native: "W_div(ONE, 0)",               exp: "DIVISION_BY_ZERO", doc: "DIVISION_BY_ZERO: divisor was zero" },
  { id: "fi.one",   call: "float_invert(ONE)",                  native: "W_inv(ONE)",                  exp: n(V.ONE),   doc: "1 / 1 = 1" },
  { id: "fi.half",  call: "float_invert(TWO)",                  native: "W_inv(TWO)",                  exp: n(V.HALF),  doc: "1 / 2 = 0.5 = 5000000000000000 x 10^-16" },
  { id: "fi.dz",    call: "float_invert(0)",                    native: "W_inv(0)",                    exp: "DIVISION_BY_ZERO", doc: "DIVISION_BY_ZERO: parameter was zero" },
  // ── float_compare ────────────────────────────────────────────────────────
  { id: "fc.eq",    call: "float_compare(ONE, ONE, COMPARE_EQUAL)",   native: "W_cmp(ONE, ONE, 1)",   exp: "1", doc: "1 == 1 is true" },
  { id: "fc.lt",    call: "float_compare(ONE, TWO, COMPARE_LESS)",    native: "W_cmp(ONE, TWO, 2)",   exp: "1", doc: "1 < 2 is true" },
  { id: "fc.gt",    call: "float_compare(ONE, TWO, COMPARE_GREATER)", native: "W_cmp(ONE, TWO, 4)",   exp: "0", doc: "1 > 2 is false: 0" },
  { id: "fc.ne",    call: "float_compare(ONE, TWO, COMPARE_LESS | COMPARE_GREATER)", native: "W_cmp(ONE, TWO, 6)", exp: "1", doc: "LESS|GREATER = not equal: true" },
  { id: "fc.all",   call: "float_compare(ONE, ONE, 7)",         native: "W_cmp(ONE, ONE, 7)",          exp: "INVALID_ARGUMENT", doc: "INVALID_ARGUMENT: EQUAL|LESS|GREATER is not a valid combination" },
  { id: "fc.bad",   call: "float_compare(BAD, ONE, COMPARE_EQUAL)", native: "W_cmp(BAD, ONE, 1)",      exp: "INVALID_FLOAT", doc: "INVALID_FLOAT: parameter not a valid XFL" },
  // ── float_int ────────────────────────────────────────────────────────────
  { id: "ft.one",   call: "float_int(ONE, 0, 0)",               native: "W_int(ONE, 0, 0)",            exp: "1",   doc: "floor(1) = 1" },
  { id: "ft.pi2",   call: "float_int(PI, 2, 0)",                native: "W_int(PI, 2, 0)",             exp: "314", doc: "shift 2 decimal places then floor: 314" },
  { id: "ft.dp16",  call: "float_int(ONE, 16, 0)",              native: "W_int(ONE, 16, 0)",           exp: "INVALID_ARGUMENT", doc: "INVALID_ARGUMENT: more than 15 decimal places" },
  { id: "ft.neg",   call: "float_int(NONE, 0, 0)",              native: "W_int(NONE, 0, 0)",           exp: "CANT_RETURN_NEGATIVE", doc: "CANT_RETURN_NEGATIVE: negative without absolute" },
  { id: "ft.abs",   call: "float_int(NONE, 0, 1)",              native: "W_int(NONE, 0, 1)",           exp: "1",   doc: "absolute = 1: |-1| = 1" },
  // ── float_mantissa / float_sign ──────────────────────────────────────────
  { id: "fx.one",   call: "float_mantissa(ONE)",                native: "W_man(ONE)",                  exp: "1000000000000000", doc: "mantissa of 1 = 1000000000000000" },
  { id: "fg.neg",   call: "float_sign(NONE)",                   native: "W_sign(NONE)",                exp: "1", doc: "1 if negative" },
  { id: "fg.pos",   call: "float_sign(ONE)",                    native: "W_sign(ONE)",                 exp: "0", doc: "0 if positive" },
  // ── float_log / float_root ───────────────────────────────────────────────
  { id: "fl.100",   call: "float_log(HUNDRED)",                 native: "W_log(HUNDRED)",              exp: n(V.TWO), doc: "log10(100) = 2" },
  { id: "fl.neg",   call: "float_log(NONE)",                    native: "W_log(NONE)",                 exp: "COMPLEX_NOT_SUPPORTED", doc: "COMPLEX_NOT_SUPPORTED: negative parameter" },
  { id: "fl.bad",   call: "float_log(BAD)",                     native: "W_log(BAD)",                  exp: "INVALID_FLOAT", doc: "INVALID_FLOAT: parameter not a valid XFL" },
  { id: "fr.neg",   call: "float_root(NONE, 2)",                native: "W_root(NONE, 2)",             exp: "COMPLEX_NOT_SUPPORTED", doc: "COMPLEX_NOT_SUPPORTED: negative parameter" },
  { id: "fr.bad",   call: "float_root(BAD, 2)",                 native: "W_root(BAD, 2)",              exp: "INVALID_FLOAT", doc: "INVALID_FLOAT: parameter not a valid XFL" },
  // ── float_mulratio ───────────────────────────────────────────────────────
  { id: "fq.three", call: "float_mulratio(ONE, 0, 3, 1)",       native: "W_mulr(ONE, 0, 3, 1)",        exp: n(V.THREE), doc: "1 x 3/1 = 3" },
  { id: "fq.dz",    call: "float_mulratio(ONE, 0, 1, 0)",       native: "W_mulr(ONE, 0, 1, 0)",        exp: "DIVISION_BY_ZERO", doc: "DIVISION_BY_ZERO: denominator was zero" },
  // ── float_sto / float_sto_set ────────────────────────────────────────────
  { id: "fz.oob",   call: "float_sto(OOB, 48, 0, 0, 0, 0, ONE, sfAmount)", exp: "OUT_OF_BOUNDS", doc: "OUT_OF_BOUNDS" },
  { id: "fz.bad",   call: "float_sto(WB, 48, 0, 0, 0, 0, BAD, sfAmount)", exp: "INVALID_FLOAT", doc: "INVALID_FLOAT: supplied float not a valid XFL" },
  { id: "fy.oob",   call: "float_sto_set(OOB, 8)",              exp: "OUT_OF_BOUNDS", doc: "OUT_OF_BOUNDS" },
  { id: "fy.short", call: "float_sto_set(RB, 4)",               exp: "NOT_AN_OBJECT", doc: "NOT_AN_OBJECT: buffer is not a serialized float (4 bytes)" },
  // ── sto_validate ─────────────────────────────────────────────────────────
  { id: "sv.oob",   call: "sto_validate(OOB, 32)",              exp: "OUT_OF_BOUNDS", doc: "OUT_OF_BOUNDS" },
  { id: "sv.ok",    call: "sto_validate(S2, 10)",               exp: "1", doc: "1: valid STObject" },
  { id: "sv.trunc", call: "sto_validate(T2, 2)",                exp: "0", doc: "0: not a valid STObject (UINT32 truncated)" },
  { id: "sv.len0",  call: "sto_validate(RB, 0)",                exp: "0", doc: "0: not a valid STObject (0f3258d: TOO_SMALL — KNOWN DIVERGENCE)" },
  { id: "sv.len1",  call: "sto_validate(S2, 1)",                exp: "0", doc: "0: not a valid STObject (0f3258d: TOO_SMALL — KNOWN DIVERGENCE)" },
  // ── sto_subfield / sto_subarray ──────────────────────────────────────────
  { id: "sf.oob",   call: "sto_subfield(OOB, 10, sfSequence)",  exp: "OUT_OF_BOUNDS", doc: "OUT_OF_BOUNDS" },
  { id: "sf.small", call: "sto_subfield(S2, 1, sfSequence)",    exp: "TOO_SMALL", doc: "TOO_SMALL: input can't possibly contain a valid STObject" },
  { id: "sf.miss",  call: "sto_subfield(S1, 5, sfSequence)",    exp: "DOESNT_EXIST", doc: "DOESNT_EXIST: field not present" },
  { id: "sf.ok",    call: "sto_subfield(S2, 10, sfSequence)",   exp: n((6n << 32n) + 4n), doc: "payload location: offset 6 (high 32), length 4 (low 32)" },
  { id: "sa.oob",   call: "sto_subarray(OOB, 10, 0)",           exp: "OUT_OF_BOUNDS", doc: "OUT_OF_BOUNDS" },
  { id: "sa.small", call: "sto_subarray(S2, 1, 0)",             exp: "TOO_SMALL", doc: "TOO_SMALL: input can't possibly contain a valid STArray" },
  // ── generation / nonce / fee / emit (etxn_reserve(1) called first) ───────
  { id: "eg.one",   call: "etxn_generation()",                  exp: "1", doc: "EmitDetails: originating txn not emitted => generation 1" },
  { id: "og.none",  call: "otxn_generation()",                  exp: "1", doc: "1 if no generation field is present (0f3258d: 0 — KNOWN DIVERGENCE)" },
  { id: "en.oob",   call: "etxn_nonce(OOB, 32)",                exp: "OUT_OF_BOUNDS", doc: "OUT_OF_BOUNDS" },
  { id: "en.ok",    call: "etxn_nonce(WB, 32)",                 exp: "32", doc: "number of bytes written (32)" },
  { id: "ef.oob",   call: "etxn_fee_base(OOB, 32)",             exp: "OUT_OF_BOUNDS", doc: "OUT_OF_BOUNDS" },
  { id: "ef.bad",   call: "etxn_fee_base(RB, 32)",              exp: "INVALID_TXN", doc: "INVALID_TXN: buffer is not a serialized transaction" },
  { id: "em.rOOB",  call: "emit(WB, 32, OOB, 32)",              exp: "OUT_OF_BOUNDS", doc: "OUT_OF_BOUNDS (transaction read)" },
  { id: "em.wOOB",  call: "emit(OOB, 32, RB, 32)",              exp: "OUT_OF_BOUNDS", doc: "OUT_OF_BOUNDS (hash write)" },
  { id: "em.bad",   call: "emit(WB, 32, RB, 32)",               exp: "EMISSION_FAILURE", doc: "EMISSION_FAILURE: not a valid transaction" },
];

export const KNOWN_DIVERGENCE = {
  "sv.len0": "docs: 0 (invalid); 0f3258d returns TOO_SMALL for < 2 bytes",
  "sv.len1": "docs: 0 (invalid); 0f3258d returns TOO_SMALL for < 2 bytes",
  "og.none": "docs: 1 when no generation field; 0f3258d returns 0",
};

// Cases that match the spec only when an amendment is enabled (proven by
// `make check-float`, which runs the release code with the switch off and on).
// A finding here means the amendment is not active on that network.
export const AMENDMENT_DEPENDENT = {
  "fd.three": "fixFloatDivide: without it 6/2 = 2.999999999999999",
  "fi.half":  "fixFloatDivide: without it 1/2 = 0.4999999999999990",
};
