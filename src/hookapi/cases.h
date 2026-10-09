/**
 * Harness C: Hook API boundary test cases.
 *
 * Each case calls one host function with boundary arguments whose expected
 * return value is known by construction from the Hook API spec:
 *
 *   - OUT_OF_BOUNDS  (-1)  pointer/length reads or writes outside WASM memory
 *   - TOO_SMALL      (-4)  output buffer or key too short
 *   - TOO_BIG        (-3)  key or length exceeds spec maximum
 *   - DOESNT_EXIST   (-5)  slot or state not populated
 *   - INVALID_ARGUMENT(-7) slot number 0 (reserved) or otherwise invalid
 *   - INVALID_FIELD  (-17) unknown sfField code passed to otxn_field
 *   - MEM_OVERLAP    (-43) read and write buffers overlap
 *
 * The switch is split across five functions (≤10 cases each) so the WASM
 * block nesting depth never exceeds the guard-checker's 16-level limit.
 *
 * WASM linear memory: 64 KiB (0x10000 bytes).
 * INVALID_PTR: well past end.
 * EDGE_PTR: last valid byte; a 32-byte read from here overruns.
 */

#ifndef CHAOS_CASES_H
#define CHAOS_CASES_H

#include "hook/error.h"
#include "hook/extern.h"

#ifndef GI
#define GI static inline __attribute__((always_inline))
#endif
/* Group functions must NOT be inlined into hook() — each must be its own
   WASM function so the guard checker sees shallow per-function block depth. */
#define GF static __attribute__((noinline))

#define MEM_SIZE    0x10000u
#define INVALID_PTR (MEM_SIZE + 1u)
#define EDGE_PTR    (MEM_SIZE - 1u)

static uint8_t WBUF[256];
static uint8_t RBUF[256];

static inline void init_bufs(void)
{
    for (int i = 0; GUARD(256), i < 256; ++i)
        { WBUF[i] = 0; RBUF[i] = (uint8_t)(i + 1); }
}

/* ---- group A: OUT_OF_BOUNDS (cases 0-9) ---- */
GF int64_t run_A(int c)
{
    if (c == 0) return hook_account(INVALID_PTR, 20);
    if (c == 1) return ledger_nonce(INVALID_PTR, 32);
    if (c == 2) return ledger_last_hash(INVALID_PTR, 32);
    if (c == 3) return util_sha512h(INVALID_PTR, 32, (uint32_t)RBUF, 32);
    if (c == 4) return util_sha512h((uint32_t)WBUF, 32, INVALID_PTR, 32);
    if (c == 5) return state(INVALID_PTR, 256, (uint32_t)RBUF, 32);
    if (c == 6) return state((uint32_t)WBUF, 256, INVALID_PTR, 32);
    if (c == 7) return state_set(INVALID_PTR, 32, (uint32_t)RBUF, 32);
    if (c == 8) return state_set((uint32_t)RBUF, 32, INVALID_PTR, 32);
    if (c == 9) return otxn_field(INVALID_PTR, 32, 0x2200);
    return 0;
}

/* ---- group B: OUT_OF_BOUNDS cont. + edge (cases 10-19) ---- */
GF int64_t run_B(int c)
{
    if (c == 10) return hook_param(INVALID_PTR, 32, (uint32_t)RBUF, 4);
    if (c == 11) return hook_param((uint32_t)WBUF, 32, INVALID_PTR, 4);
    if (c == 12) return slot(INVALID_PTR, 64, 1);
    if (c == 13) return etxn_details(INVALID_PTR, 138);
    if (c == 14) return util_accid(INVALID_PTR, 20, (uint32_t)RBUF, 46);
    if (c == 15) return util_raddr(INVALID_PTR, 46, (uint32_t)RBUF, 20);
    /* edge: read starts at last byte, length 32 → overruns */
    if (c == 16) return util_sha512h((uint32_t)WBUF, 32, EDGE_PTR, 32);
    if (c == 17) return state((uint32_t)WBUF, 256, EDGE_PTR, 32);
    /* TOO_SMALL: output buffer too short */
    if (c == 18) return hook_account((uint32_t)WBUF, 19);   /* needs 20 */
    if (c == 19) return ledger_nonce((uint32_t)WBUF, 31);   /* needs 32 */
    return 0;
}

/* ---- group C: TOO_SMALL / TOO_BIG key/length (cases 20-29) ---- */
GF int64_t run_C(int c)
{
    if (c == 20) return ledger_last_hash((uint32_t)WBUF, 31); /* needs 32 */
    if (c == 21) return util_sha512h((uint32_t)WBUF, 31, (uint32_t)RBUF, 32);
    if (c == 22) return state((uint32_t)WBUF, 0, (uint32_t)RBUF, 32); /* write_len=0 */
    if (c == 23) return state((uint32_t)WBUF, 256, (uint32_t)RBUF, 0);  /* key len=0 */
    if (c == 24) return state((uint32_t)WBUF, 256, (uint32_t)RBUF, 33); /* key len=33 */
    if (c == 25) return state_set((uint32_t)RBUF, 32, (uint32_t)RBUF, 0); /* key=0 */
    if (c == 26) return state_set((uint32_t)RBUF, 32, (uint32_t)RBUF, 33);/* key=33 */
    if (c == 27) return hook_param((uint32_t)WBUF, 32, (uint32_t)RBUF, 0); /* key=0 */
    if (c == 28) return hook_param((uint32_t)WBUF, 32, (uint32_t)RBUF, 33);/* key=33 */
    /* DOESNT_EXIST: slot never set */
    if (c == 29) return slot((uint32_t)WBUF, 64, 1);
    return 0;
}

/* ---- group D: DOESNT_EXIST + INVALID_ARGUMENT + INVALID_FIELD (30-39) ---- */
GF int64_t run_D(int c)
{
    if (c == 30) return slot_size(1);
    if (c == 31) return slot_count(1);
    if (c == 32) return slot_subfield(1, 0x2200, 2);
    if (c == 33) return slot_subarray(1, 0, 2);
    if (c == 34) return slot_float(1);
    if (c == 35) return slot_type(1, 0);
    /* state key guaranteed not to exist */
    if (c == 36) {
        uint8_t* nokey = WBUF + 128;
        for (int i = 0; GUARD(32), i < 32; ++i) nokey[i] = 0xFF;
        return state((uint32_t)WBUF, 64, (uint32_t)nokey, 32);
    }
    /* INVALID_ARGUMENT: slot 0 reserved */
    if (c == 37) return slot((uint32_t)WBUF, 64, 0);
    if (c == 38) return slot_clear(0);
    /* INVALID_FIELD */
    if (c == 39) return otxn_field((uint32_t)WBUF, 64, 0x0000);
    return 0;
}

/* ---- group E: INVALID_FIELD + MEM_OVERLAP + valid success cases (40-49) ---- */
GF int64_t run_E(int c)
{
    if (c == 40) return otxn_field((uint32_t)WBUF, 64, 0xFFFF);
    /* MEM_OVERLAP */
    if (c == 41) return util_sha512h((uint32_t)WBUF, 32, (uint32_t)WBUF, 32);
    if (c == 42) return util_sha512h((uint32_t)WBUF, 32, (uint32_t)(WBUF+16), 32);
    if (c == 43) return util_sha512h((uint32_t)(WBUF+16), 32, (uint32_t)WBUF, 32);
    if (c == 44) return state((uint32_t)WBUF, 32, (uint32_t)(WBUF+16), 32);
    /* Success cases: zero-length sha512h (hash of empty = valid) */
    if (c == 45) return util_sha512h((uint32_t)WBUF, 32, (uint32_t)RBUF, 0);
    /* Valid otxn_field reads: sfTransactionType and sfFee exist on every txn */
    if (c == 46) return otxn_field((uint32_t)WBUF, 64, 0x1200); /* sfTransactionType */
    if (c == 47) return otxn_field((uint32_t)WBUF, 64, 0x6800); /* sfFee */
    /* hook_account with exact buffer size (20) must succeed */
    if (c == 48) return hook_account((uint32_t)WBUF, 20);
    /* ledger_nonce with exact buffer size (32) must succeed */
    if (c == 49) return ledger_nonce((uint32_t)WBUF, 32);
    return 0;
}

/* Forward declarations */
GF int64_t run_A(int c);
GF int64_t run_B(int c);
GF int64_t run_C(int c);
GF int64_t run_D(int c);
GF int64_t run_E(int c);

/* Top-level dispatcher */
static inline int64_t run_case(int c)
{
    if (c < 10) return run_A(c);
    if (c < 20) return run_B(c);
    if (c < 30) return run_C(c);
    if (c < 40) return run_D(c);
    return run_E(c);
}

/* Expected returns. Positive means "must return >= 1". */
static const int64_t EXPECTED[50] = {
    /* 0-9: OUT_OF_BOUNDS */
    OUT_OF_BOUNDS, OUT_OF_BOUNDS, OUT_OF_BOUNDS, OUT_OF_BOUNDS,
    OUT_OF_BOUNDS, OUT_OF_BOUNDS, OUT_OF_BOUNDS, OUT_OF_BOUNDS,
    OUT_OF_BOUNDS, OUT_OF_BOUNDS,
    /* 10-17: OUT_OF_BOUNDS cont. + edge */
    OUT_OF_BOUNDS, OUT_OF_BOUNDS, OUT_OF_BOUNDS, OUT_OF_BOUNDS,
    OUT_OF_BOUNDS, OUT_OF_BOUNDS, OUT_OF_BOUNDS, OUT_OF_BOUNDS,
    /* 18-19: TOO_SMALL output */
    TOO_SMALL, TOO_SMALL,
    /* 20-22: TOO_SMALL output cont. */
    TOO_SMALL, TOO_SMALL, TOO_SMALL,
    /* 23: TOO_SMALL key=0 */
    TOO_SMALL,
    /* 24: TOO_BIG key=33 */
    TOO_BIG,
    /* 25: state_set key=0 */
    TOO_SMALL,
    /* 26: state_set key=33 */
    TOO_BIG,
    /* 27: hook_param key=0 */
    TOO_SMALL,
    /* 28: hook_param key=33 */
    TOO_BIG,
    /* 29-35: DOESNT_EXIST */
    DOESNT_EXIST, DOESNT_EXIST, DOESNT_EXIST, DOESNT_EXIST,
    DOESNT_EXIST, DOESNT_EXIST, DOESNT_EXIST,
    /* 36: DOESNT_EXIST (state missing key) */
    DOESNT_EXIST,
    /* 37-38: INVALID_ARGUMENT (slot 0) */
    INVALID_ARGUMENT, INVALID_ARGUMENT,
    /* 39-40: INVALID_FIELD */
    INVALID_FIELD, INVALID_FIELD,
    /* 41-44: MEM_OVERLAP */
    MEM_OVERLAP, MEM_OVERLAP, MEM_OVERLAP, MEM_OVERLAP,
    /* 45: sha512h len=0 — succeeds, returns 32 */
    32,
    /* 46-47: valid otxn_field — must return > 0 */
    1, 1,
    /* 48: hook_account exact buf — must return 20 */
    20,
    /* 49: ledger_nonce exact buf — must return 32 */
    32,
};

static inline int case_matches(int c, int64_t actual)
{
    int64_t exp = EXPECTED[c];
    /* exp==1 means "any positive value is correct" */
    if (exp == 1) return actual >= 1;
    return actual == exp;
}

#define CASE_COUNT 50

static const char* const CASE_NAMES[CASE_COUNT] = {
    "hook_account OOB", "nonce OOB",       "hash OOB",
    "sha512h wOOB",     "sha512h rOOB",    "state wOOB",
    "state kOOB",       "state_set vOOB",  "state_set kOOB",
    "otxn_field wOOB",  "param wOOB",      "param kOOB",
    "slot wOOB",        "etxn_det OOB",    "accid wOOB",
    "raddr wOOB",       "sha512h rEDGE",   "state kEDGE",
    "acct small",       "nonce small",     "hash small",
    "sha512h small",    "state w=0",       "state k=0",
    "state k=33",       "ss k=0",          "ss k=33",
    "param k=0",        "param k=33",      "slot empty",
    "slot_size empty",  "slot_cnt empty",  "slot_sub empty",
    "slot_arr empty",   "slot_flt empty",  "slot_type empty",
    "state missing",    "slot(0)",         "slot_clr(0)",
    "field 0x0000",     "field 0xFFFF",    "sha512 ov==",
    "sha512 ov+",       "sha512 ov-",      "state ov",
    "sha512 len=0",     "otxn sfType",     "otxn sfFee",
    "acct exact",       "nonce exact",
};

#endif /* CHAOS_CASES_H */
