/**
 * Chaos Monkey, harness C: Hook API boundary testing.
 * Target: any Xahau network (PWA devnet used here).
 *
 * On every wake (ttCRON or ttINVOKE) the Hook:
 *   1. draws 32 bytes (ledger_nonce),
 *   2. selects one test case: seed[0] % CASE_COUNT,
 *   3. calls one host function with boundary arguments whose expected
 *      return value is known by construction,
 *   4. records any mismatch as a finding.
 *
 * Guard-checker constraints met:
 *   - No internal WASM function calls (only whitelisted host imports).
 *   - Block/guard tree depth ≤ 16: achieved via 2-level nested switch
 *     (outer: c/10 → br_table of 5; inner: c%10 → br_table of 10).
 *     Empirically verified: max raw WASM block depth = 5.
 *   - GUARD loops at top level only, never nested inside switch cases.
 *
 * State:
 *   "STATS"  runs(4) correct(4) findings(4) (12 bytes, 4th word unused)
 *   key[0]=case_id, rest 0  ->  case(1) expected_lo(4) actual_lo(4)
 */

#include "hook/hookapi.h"

#define REARM_EVERY 200
#define CASE_COUNT  50

/* WASM linear memory ceiling */
#define MEM_SIZE    0x10000u
#define INVALID_PTR (MEM_SIZE + 1u)
#define EDGE_PTR    (MEM_SIZE - 1u)

#define PUT32(b,o,v) \
    {(b)[(o)]=(uint8_t)((v)>>24);(b)[(o)+1]=(uint8_t)((v)>>16); \
     (b)[(o)+2]=(uint8_t)((v)>>8);(b)[(o)+3]=(uint8_t)(v);}
#define GET32(b,o) \
    (((uint32_t)(b)[(o)]<<24)|((uint32_t)(b)[(o)+1]<<16)| \
     ((uint32_t)(b)[(o)+2]<<8)|(uint32_t)(b)[(o)+3])

/* BSS buffers — zero-initialised by WASM runtime at module load. */
static uint8_t WB[256];   /* write scratch  */
static uint8_t RB[256];   /* read scratch   */
static uint8_t prepared[600];

/* Expected return values. 1 means "any positive value". */
static const int64_t EXP[CASE_COUNT] = {
    /* 0-17: OUT_OF_BOUNDS */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    /* 18-22: TOO_SMALL output */
    -4,-4,-4,-4,-4,
    /* 23: state key=0 TOO_SMALL */    -4,
    /* 24: state key=33 TOO_BIG */     -3,
    /* 25: state_set key=0 TOO_SMALL */-4,
    /* 26: state_set key=33 TOO_BIG */ -3,
    /* 27: hook_param key=0 TOO_SMALL */-4,
    /* 28: hook_param key=33 TOO_BIG */ -3,
    /* 29-36: DOESNT_EXIST */
    -5,-5,-5,-5,-5,-5,-5,-5,
    /* 37-38: slot(0)/slot_clear(0) — slot 0 is empty, not invalid */ -5,-5,
    /* 39-40: INVALID_FIELD — 0x0000/0xFFFF are not valid sf codes */           -17,-17,
    /* 41-44: MEM_OVERLAP */             -43,-43,-43,-43,
    /* 45: sha512h(len=0) returns 32 */  32,
    /* 46-47: sfType/sfFee absent on Cron/Invoke */ -5,-5,
    /* 48: hook_account exact=20 */      20,
    /* 49: ledger_nonce exact=32 */      32
};

int64_t cbak(uint32_t r) { accept(0,0,0); return 0; }

int64_t hook(uint32_t reserved)
{
    _g(1, 1);

    int64_t tt = otxn_type();
    if (tt != ttCRON && tt != ttINVOKE)
        accept(SBUF("hookapi: not a wake"), 0);

    /* Load stats (explicit zero, no loop) */
    uint8_t stats[16];
    stats[0]=stats[1]=stats[2]=stats[3]=0;
    stats[4]=stats[5]=stats[6]=stats[7]=0;
    stats[8]=stats[9]=stats[10]=stats[11]=0;
    stats[12]=stats[13]=stats[14]=stats[15]=0;
    state(SBUF(stats), (uint32_t)"STATS", 5);
    uint32_t runs = GET32(stats, 0) + 1;

    etxn_reserve(1);

    /* Randomness — no pre-zero loop; host fills the buffer */
    uint8_t seed[32];
    if (ledger_nonce(SBUF(seed)) != 32)
        rollback(SBUF("hookapi: no nonce"), 1);

    int c = (int)(seed[0] % CASE_COUNT);

    /*
     * Pre-build the "missing state" key used by case 36.
     * Unrolled — no loop, no WCE tree node.
     */
    uint8_t nk[32];
    {
        uint32_t *p = (uint32_t *)nk;
        p[0]=0xFFFFFFFFu; p[1]=0xFFFFFFFFu; p[2]=0xFFFFFFFFu; p[3]=0xFFFFFFFFu;
        p[4]=0xFFFFFFFFu; p[5]=0xFFFFFFFFu; p[6]=0xFFFFFFFFu; p[7]=0xFFFFFFFFu;
    }

    /*
     * Pre-build the finding key (case id in byte 0, rest 0).
     * Unrolled — no loop, no WCE tree node.
     */
    uint8_t fkey[32];
    {
        uint32_t *p = (uint32_t *)fkey;
        p[0]=0u; p[1]=0u; p[2]=0u; p[3]=0u;
        p[4]=0u; p[5]=0u; p[6]=0u; p[7]=0u;
    }
    fkey[0] = (uint8_t)c;

    /*
     * 2-level nested switch: outer on c/10 (groups 0-4 → br_table),
     * inner on c%10 (cases 0-9 → br_table). Max WASM block depth = 5.
     * No GUARD needed inside switch — no loops here.
     */
    int64_t actual = 0;
    int grp = c / 10;
    int sub = c % 10;

    switch (grp)
    {
    /* Group 0: cases 0-9 — OUT_OF_BOUNDS part 1 */
    case 0:
        switch (sub)
        {
        case 0: actual = hook_account(INVALID_PTR, 20); break;
        case 1: actual = ledger_nonce(INVALID_PTR, 32); break;
        case 2: actual = ledger_last_hash(INVALID_PTR, 32); break;
        case 3: actual = util_sha512h(INVALID_PTR, 32, (uint32_t)RB, 32); break;
        case 4: actual = util_sha512h((uint32_t)WB, 32, INVALID_PTR, 32); break;
        case 5: actual = state(INVALID_PTR, 256, (uint32_t)RB, 32); break;
        case 6: actual = state((uint32_t)WB, 256, INVALID_PTR, 32); break;
        case 7: actual = state_set(INVALID_PTR, 32, (uint32_t)RB, 32); break;
        case 8: actual = state_set((uint32_t)RB, 32, INVALID_PTR, 32); break;
        case 9: actual = otxn_field(INVALID_PTR, 32, 0x2200); break;
        default: break;
        }
        break;

    /* Group 1: cases 10-19 — OUT_OF_BOUNDS part 2 + edge + TOO_SMALL start */
    case 1:
        switch (sub)
        {
        case 0: actual = hook_param(INVALID_PTR, 32, (uint32_t)RB, 4); break;
        case 1: actual = hook_param((uint32_t)WB, 32, INVALID_PTR, 4); break;
        case 2: actual = slot(INVALID_PTR, 64, 1); break;
        case 3: actual = etxn_details(INVALID_PTR, 138); break;
        case 4: actual = util_accid(INVALID_PTR, 20, (uint32_t)RB, 46); break;
        case 5: actual = util_raddr(INVALID_PTR, 46, (uint32_t)RB, 20); break;
        case 6: actual = util_sha512h((uint32_t)WB, 32, EDGE_PTR, 32); break;
        case 7: actual = state((uint32_t)WB, 256, EDGE_PTR, 32); break;
        case 8: actual = hook_account((uint32_t)WB, 19); break;
        case 9: actual = ledger_nonce((uint32_t)WB, 31); break;
        default: break;
        }
        break;

    /* Group 2: cases 20-29 — TOO_SMALL cont. + key boundaries + DOESNT_EXIST start */
    case 2:
        switch (sub)
        {
        case 0: actual = ledger_last_hash((uint32_t)WB, 31); break;
        case 1: actual = util_sha512h((uint32_t)WB, 31, (uint32_t)RB, 32); break;
        case 2: actual = state((uint32_t)WB, 0, (uint32_t)RB, 32); break;
        case 3: actual = state((uint32_t)WB, 256, (uint32_t)RB, 0); break;
        case 4: actual = state((uint32_t)WB, 256, (uint32_t)RB, 33); break;
        case 5: actual = state_set((uint32_t)RB, 32, (uint32_t)RB, 0); break;
        case 6: actual = state_set((uint32_t)RB, 32, (uint32_t)RB, 33); break;
        case 7: actual = hook_param((uint32_t)WB, 32, (uint32_t)RB, 0); break;
        case 8: actual = hook_param((uint32_t)WB, 32, (uint32_t)RB, 33); break;
        case 9: actual = slot((uint32_t)WB, 64, 1); break;
        default: break;
        }
        break;

    /* Group 3: cases 30-39 — DOESNT_EXIST cont. + INVALID_ARGUMENT + INVALID_FIELD start */
    case 3:
        switch (sub)
        {
        case 0: actual = slot_size(1); break;
        case 1: actual = slot_count(1); break;
        case 2: actual = slot_subfield(1, 0x2200, 2); break;
        case 3: actual = slot_subarray(1, 0, 2); break;
        case 4: actual = slot_float(1); break;
        case 5: actual = slot_type(1, 0); break;
        /* case 36 = grp3/sub6: missing state key — nk[] pre-filled above */
        case 6: actual = state((uint32_t)WB, 64, (uint32_t)nk, 32); break;
        case 7: actual = slot((uint32_t)WB, 64, 0); break;
        case 8: actual = slot_clear(0); break;
        case 9: actual = otxn_field((uint32_t)WB, 64, 0x0000); break;
        default: break;
        }
        break;

    /* Group 4: cases 40-49 — INVALID_FIELD cont. + MEM_OVERLAP + success */
    case 4:
        switch (sub)
        {
        case 0: actual = otxn_field((uint32_t)WB, 64, 0xFFFF); break;
        case 1: actual = util_sha512h((uint32_t)WB, 32, (uint32_t)WB, 32); break;
        case 2: actual = util_sha512h((uint32_t)WB, 32, (uint32_t)(WB+16), 32); break;
        case 3: actual = util_sha512h((uint32_t)(WB+16), 32, (uint32_t)WB, 32); break;
        case 4: actual = state((uint32_t)WB, 32, (uint32_t)(WB+16), 32); break;
        case 5: actual = util_sha512h((uint32_t)WB, 32, (uint32_t)RB, 0); break;
        case 6: actual = otxn_field((uint32_t)WB, 64, 0x1200); break;
        case 7: actual = otxn_field((uint32_t)WB, 64, 0x6800); break;
        case 8: actual = hook_account((uint32_t)WB, 20); break;
        case 9: actual = ledger_nonce((uint32_t)WB, 32); break;
        default: break;
        }
        break;

    default: break;
    }

    /* Evaluate */
    int64_t exp = EXP[c];
    int correct = (exp == 1) ? (actual >= 1) : (actual == exp);

    if (correct)
    {
        PUT32(stats, 4, GET32(stats, 4) + 1);
    }
    else
    {
        PUT32(stats, 8, GET32(stats, 8) + 1);
        /* fkey already has case id in byte 0, rest zero */
        uint8_t f[9];
        f[0] = (uint8_t)c;
        f[1] = (uint8_t)((uint64_t)exp >> 24);
        f[2] = (uint8_t)((uint64_t)exp >> 16);
        f[3] = (uint8_t)((uint64_t)exp >> 8);
        f[4] = (uint8_t)(uint64_t)exp;
        f[5] = (uint8_t)((uint64_t)actual >> 24);
        f[6] = (uint8_t)((uint64_t)actual >> 16);
        f[7] = (uint8_t)((uint64_t)actual >> 8);
        f[8] = (uint8_t)(uint64_t)actual;
        state_set(SBUF(f), SBUF(fkey));
    }

    PUT32(stats, 0, runs);
    state_set(SBUF(stats), (uint32_t)"STATS", 5);

    /* Re-arm Cron every REARM_EVERY wakes */
    if (runs % REARM_EVERY == 0)
    {
        uint32_t delay = 10;
        uint8_t p[4];
        if (hook_param(SBUF(p), (uint32_t)"DELAY", 5) == 4)
            delay = GET32(p, 0);

        uint8_t cronbuf[3 + 3 * 6];
        cronbuf[0] = 0x12; cronbuf[1] = 0x00; cronbuf[2] = ttCRON_SET;
        cronbuf[3]  = 0x20; cronbuf[4]  = 93; PUT32(cronbuf,  5, 0);
        cronbuf[9]  = 0x20; cronbuf[10] = 94; PUT32(cronbuf, 11, 256);
        cronbuf[15] = 0x20; cronbuf[16] = 95; PUT32(cronbuf, 17, delay);
        int64_t cl = prepare(SBUF(prepared), (uint32_t)cronbuf, sizeof(cronbuf));
        uint8_t h[32];
        if (cl > 0) emit(SBUF(h), (uint32_t)prepared, cl);
    }

    if (!correct)
        accept(SBUF("hookapi: FINDING recorded"), c);
    accept(SBUF("hookapi: case ok"), c);
    return 0;
}
