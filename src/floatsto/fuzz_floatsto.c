/**
 * Chaos Monkey, harness D: float_* / sto_* / etxn_* / emit boundary testing.
 * Target: Xahau PWA devnet.
 *
 * On every wake (ttCRON or ttINVOKE) the Hook:
 *   1. draws 32 bytes (ledger_nonce),
 *   2. selects one test case: seed[0] % CASE_COUNT,
 *   3. calls one host function with boundary/known arguments,
 *   4. records any mismatch as a finding.
 *
 * Guard-checker constraints: same as harness C.
 *   - No internal WASM function calls.
 *   - Block/guard tree depth ≤ 16 (2-level nested switch, max raw depth 5).
 *   - GUARD loops at top level only.
 *
 * State:
 *   "STATS"  runs(4) correct(4) findings(4) (4th word unused, 16 bytes total)
 *   key[0]=case_id, rest 0  ->  case(1) expected_lo(4) actual_lo(4)
 */

#include "hook/hookapi.h"

#define REARM_EVERY 200
#define CASE_COUNT  50

/* WASM linear memory ceiling */
#define MEM_SIZE    0x10000u
#define INVALID_PTR (MEM_SIZE + 1u)

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

/*
 * Expected return values.
 * Special sentinel: 1 means "any value >= 1 is correct" (any success).
 * INVALID_FLOAT is -10024 (not -24 — verified against Xahau error.h).
 */
#define INVALID_FLOAT_VAL (-10024LL)
#define DIVISION_BY_ZERO_VAL (-25LL)
#define EXPONENT_OVERSIZED_VAL (-28LL)
#define EXPONENT_UNDERSIZED_VAL (-29LL)
#define CANT_RETURN_NEGATIVE_VAL (-33LL)
#define COMPLEX_NOT_SUPPORTED_VAL (-39LL)

static const int64_t EXP[CASE_COUNT] = {
    /* Group 0 (0-9): float_* — invalid XFL / argument errors */
    /* 0: float_set(81,1) — exp > 80 */                  EXPONENT_OVERSIZED_VAL,
    /* 1: float_set(-97,1) — exp < -96 */                 EXPONENT_UNDERSIZED_VAL,
    /* 2: float_negate(garbage) */                        INVALID_FLOAT_VAL,
    /* 3: float_sum(garbage, float_one()) */              INVALID_FLOAT_VAL,
    /* 4: float_multiply(garbage, float_one()) */         INVALID_FLOAT_VAL,
    /* 5: float_divide(float_one(), 0) — div by XFL zero */ DIVISION_BY_ZERO_VAL,
    /* 6: float_compare(f1,f1, mode=0) — invalid mode */ -7,
    /* 7: float_compare(garbage, f1, COMPARE_EQUAL) */   INVALID_FLOAT_VAL,
    /* 8: float_int(f1, 16, 0) — decimal_places > 15 */  -7,
    /* 9: float_int(-f1, 0, 0) — negative, no abs */     CANT_RETURN_NEGATIVE_VAL,
    /* Group 1 (10-19): float_* — correct / known results */
    /* 10: float_one() — any valid XFL (positive) */          1,
    /* 11: float_compare(f1,f1,EQUAL) = 1 */                  1,
    /* 12: float_compare(f1, 0, GREATER) = 1 */               1,
    /* 13: float_sign(float_negate(f1)) = 1 (negative) */     1,
    /* 14: float_mantissa(float_one()) = 1000000000000000 */   1,
    /* 15: float_int(float_one(), 0, 0) = 1 */                 1,
    /* 16: float_int(float_sum(f1,f1), 0, 0) = 2 */            2,
    /* 17: float_compare(float_invert(f1), f1, EQUAL) = 1 */   1,
    /* 18: float_multiply(f1, 0) = 0 — underflow → XFL zero */ 0,
    /* 19: float_root(float_one(), 2) → compare(r, f1, EQUAL)= 1 */ 1,
    /* Group 2 (20-29): sto_* — OOB + invalid STO */
    /* 20: sto_validate(INVALID_PTR, 32) */              -1,
    /* 21: sto_subfield(INVALID_PTR, 32, 0x2200) */      -1,
    /* 22: sto_subarray(INVALID_PTR, 32, 0) */           -1,
    /* 23: sto_emplace(INVALID_PTR,32,RB,32,RB,32,0x2200) */ -1,
    /* 24: sto_erase(INVALID_PTR,32,RB,32,0x2200) */     -1,
    /* 25: sto_validate(RB, 0) — 0-byte → invalid */      0,
    /* 26: sto_validate(RB, 1) — 1-byte → invalid */      0,
    /* 27: sto_subfield(RB, 0, 0x2200) — 0-len → TOO_SMALL */ -4,
    /* 28: sto_subarray(RB, 0, 0) — 0-len → TOO_SMALL */  -4,
    /* 29: sto_validate(RB, 256) — all-zeros → invalid */ 0,
    /* Group 3 (30-39): etxn_* / emit boundaries */
    /* 30: etxn_generation() — top-level hook always 1 */     1,
    /* 31: etxn_nonce(INVALID_PTR, 32) */                    -1,
    /* 32: etxn_nonce(WB, 31) — buf too small (<32) */       -4,
    /* 33: etxn_nonce(WB, 32) — exact size succeeds */       32,
    /* 34: etxn_fee_base(RB, 32) — zeros not a valid tx → INVALID_TXN */ -37,
    /* 35: etxn_details(WB, 137) — 137 < 138 minimum */      -4,
    /* 36: etxn_details(WB, 256) — large buf succeeds */      1,
    /* 37: emit(INVALID_PTR, 32, RB, 32) — OOB hash write */ -1,
    /* 38: emit(WB, 32, INVALID_PTR, 32) — OOB txn read */   -1,
    /* 39: emit(WB, 32, RB, 0) — zero-len txn → failure */  -11,
    /* Group 4 (40-49): float_sto, float_log, float_root edge, float_mulratio */
    /* 40: float_sto(INVALID_PTR,32,RB,32,RB,32,0x6000) */  -1,
    /* 41: float_sto_set(INVALID_PTR, 32) */                 -1,
    /* 42: float_root(0, 2) — sqrt(0) = 0 (XFL zero) */      0,
    /* 43: float_root(float_one(), 0) — n=0 undefined */     -7,
    /* 44: float_log(float_negate(float_one())) → COMPLEX */ COMPLEX_NOT_SUPPORTED_VAL,
    /* 45: float_log(garbage) */                             INVALID_FLOAT_VAL,
    /* 46: float_mulratio(f1, 0, 1, 0) — denom=0 */         DIVISION_BY_ZERO_VAL,
    /* 47: float_invert(0) — 1/0 */                         DIVISION_BY_ZERO_VAL,
    /* 48: float_sign(0) = 0 (zero has no sign) */            0,
    /* 49: float_compare(0, 0, COMPARE_EQUAL) = 1 */          1,
};

int64_t cbak(uint32_t r) { accept(0,0,0); return 0; }

int64_t hook(uint32_t reserved)
{
    _g(1, 1);

    int64_t tt = otxn_type();
    if (tt != ttCRON && tt != ttINVOKE)
        accept(SBUF("floatsto: not a wake"), 0);

    /* Load stats (explicit zero, no loop) */
    uint8_t stats[16];
    stats[0]=stats[1]=stats[2]=stats[3]=0;
    stats[4]=stats[5]=stats[6]=stats[7]=0;
    stats[8]=stats[9]=stats[10]=stats[11]=0;
    stats[12]=stats[13]=stats[14]=stats[15]=0;
    state(SBUF(stats), (uint32_t)"STATS", 5);
    uint32_t runs = GET32(stats, 0) + 1;

    etxn_reserve(1);

    /* Randomness */
    uint8_t seed[32];
    if (ledger_nonce(SBUF(seed)) != 32)
        rollback(SBUF("floatsto: no nonce"), 1);

    int c = (int)(seed[0] % CASE_COUNT);

    /*
     * Cache float_one() — used by many cases without making the depth worse,
     * since this is a plain assignment, not a block/loop.
     */
    int64_t f1 = float_one();

    /*
     * Pre-build finding key (case id in byte 0, rest 0). Unrolled.
     */
    uint8_t fkey[32];
    {
        uint32_t *p = (uint32_t *)fkey;
        p[0]=0u; p[1]=0u; p[2]=0u; p[3]=0u;
        p[4]=0u; p[5]=0u; p[6]=0u; p[7]=0u;
    }
    fkey[0] = (uint8_t)c;

    /*
     * 2-level nested switch: outer on c/10, inner on c%10.
     * Max WASM block depth = 5. No GUARD inside switch.
     */
    int64_t actual = 0;
    int grp = c / 10;
    int sub = c % 10;

    switch (grp)
    {
    /* Group 0: cases 0-9 — float_* invalid argument errors */
    case 0:
        switch (sub)
        {
        /* float_set: exponent out of range */
        case 0: actual = float_set(81,  1); break;
        case 1: actual = float_set(-97, 1); break;
        /* float_negate / sum / multiply with garbage XFL */
        case 2: actual = float_negate(0xDEADBEEFDEADBEEFLL); break;
        case 3: actual = float_sum(0xDEADBEEFDEADBEEFLL, f1); break;
        case 4: actual = float_multiply(0xDEADBEEFDEADBEEFLL, f1); break;
        /* float_divide by XFL canonical zero */
        case 5: actual = float_divide(f1, 0); break;
        /* float_compare invalid mode */
        case 6: actual = float_compare(f1, f1, 0); break;
        case 7: actual = float_compare(0xDEADBEEFDEADBEEFLL, f1, COMPARE_EQUAL); break;
        /* float_int bad decimal_places */
        case 8: actual = float_int(f1, 16, 0); break;
        /* float_int negative without abs flag */
        case 9: actual = float_int(float_negate(f1), 0, 0); break;
        default: break;
        }
        break;

    /* Group 1: cases 10-19 — float_* correct/known results */
    case 1:
        switch (sub)
        {
        case 0: actual = float_one(); break;                                /* > 0 */
        case 1: actual = float_compare(f1, f1, COMPARE_EQUAL); break;      /* 1 */
        case 2: actual = float_compare(f1, 0, COMPARE_GREATER); break;     /* 1 */
        case 3: actual = float_sign(float_negate(f1)); break;              /* 1 */
        case 4: actual = float_mantissa(f1); break;                        /* > 0 */
        case 5: actual = float_int(f1, 0, 0); break;                       /* 1 */
        case 6: actual = float_int(float_sum(f1, f1), 0, 0); break;        /* 2 */
        case 7: actual = float_compare(float_invert(f1), f1, COMPARE_EQUAL); break; /* 1 */
        case 8: actual = float_multiply(f1, 0); break;                     /* 0 */
        case 9: actual = float_compare(float_root(f1, 2), f1, COMPARE_EQUAL); break; /* 1 */
        default: break;
        }
        break;

    /* Group 2: cases 20-29 — sto_* OOB + invalid STO */
    case 2:
        switch (sub)
        {
        case 0: actual = sto_validate(INVALID_PTR, 32); break;
        case 1: actual = sto_subfield(INVALID_PTR, 32, 0x2200); break;
        case 2: actual = sto_subarray(INVALID_PTR, 32, 0); break;
        case 3: actual = sto_emplace(INVALID_PTR, 32,
                                     (uint32_t)RB, 32,
                                     (uint32_t)RB, 32, 0x2200); break;
        case 4: actual = sto_erase(INVALID_PTR, 32,
                                   (uint32_t)RB, 32, 0x2200); break;
        /* sto_validate on empty / too-short / all-zero buffers */
        case 5: actual = sto_validate((uint32_t)RB, 0); break;
        case 6: actual = sto_validate((uint32_t)RB, 1); break;
        case 7: actual = sto_subfield((uint32_t)RB, 0, 0x2200); break;
        case 8: actual = sto_subarray((uint32_t)RB, 0, 0); break;
        case 9: actual = sto_validate((uint32_t)RB, 256); break;
        default: break;
        }
        break;

    /* Group 3: cases 30-39 — etxn_* / emit boundaries */
    case 3:
        switch (sub)
        {
        case 0: actual = etxn_generation(); break;
        case 1: actual = etxn_nonce(INVALID_PTR, 32); break;
        case 2: actual = etxn_nonce((uint32_t)WB, 31); break;
        case 3: actual = etxn_nonce((uint32_t)WB, 32); break;
        case 4: actual = etxn_fee_base((uint32_t)RB, 32); break;
        case 5: actual = etxn_details((uint32_t)WB, 137); break;
        case 6: actual = etxn_details((uint32_t)WB, 256); break;
        case 7: actual = emit(INVALID_PTR, 32, (uint32_t)RB, 32); break;
        case 8: actual = emit((uint32_t)WB, 32, INVALID_PTR, 32); break;
        case 9: actual = emit((uint32_t)WB, 32, (uint32_t)RB, 0); break;
        default: break;
        }
        break;

    /* Group 4: cases 40-49 — float_sto, float_log, float_root edge, float_mulratio */
    case 4:
        switch (sub)
        {
        case 0: actual = float_sto(INVALID_PTR, 32,
                                   (uint32_t)RB, 32,
                                   (uint32_t)RB, 32,
                                   f1, 0x6000); break;
        case 1: actual = float_sto_set(INVALID_PTR, 32); break;
        case 2: actual = float_root(0, 2); break;                  /* sqrt(0) = 0 */
        case 3: actual = float_root(f1, 0); break;                 /* n=0 */
        case 4: actual = float_log(float_negate(f1)); break;       /* log(-1) */
        case 5: actual = float_log(0xDEADBEEFDEADBEEFLL); break;  /* garbage */
        case 6: actual = float_mulratio(f1, 0, 1, 0); break;      /* denom=0 */
        case 7: actual = float_invert(0); break;                   /* 1/0 */
        case 8: actual = float_sign(0); break;                     /* sign of 0 */
        case 9: actual = float_compare(0, 0, COMPARE_EQUAL); break;/* 0==0 */
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
        accept(SBUF("floatsto: FINDING recorded"), c);
    accept(SBUF("floatsto: case ok"), c);
    return 0;
}
