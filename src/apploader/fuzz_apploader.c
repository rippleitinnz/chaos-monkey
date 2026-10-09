/**
 * Chaos Monkey, harness A: AppLoader validation through the emit path.
 * Target: PWA devnet (featurePWALoader, Cron, HooksUpdate2, fixHookAPI20251128).
 *
 * On every wake (ttCRON, or ttINVOKE for a manual run) the Hook:
 *   1. draws 32 bytes (ledger_nonce here; util_random on an RNG network),
 *   2. builds one AppLoader document with gen(), whose verdict is known,
 *   3. wraps it in an AccountSet, runs prepare() and emit(); emit() runs the
 *      node's real preflight, so its success or EMISSION_FAILURE is the
 *      consensus verdict,
 *   4. records any disagreement as a finding, with the 32 input bytes so the
 *      case can be regenerated exactly (gen() is deterministic).
 *
 * It re-arms its own Cron schedule every REARM_EVERY wakes.
 *
 * Install with HookOn allowing only ttCRON and ttINVOKE, so the AccountSets it
 * emits do not re-trigger it.
 *
 * Parameters (optional):
 *   DELAY   Cron interval in seconds, 4 bytes big-endian (default 10)
 *
 * State:
 *   "STATS"  runs(4) ok_pass(4) ok_fail(4) findings(4) harness_errors(4)
 *   <sha512h(document)> -> finding: fault(1) observed_pass(1) len(2)
 *                          seed(32) document head(up to 200)
 */

#include "hook/hookapi.h"
#include "gen.h"

#define REARM_EVERY 200
#define HEAD 200

/* Transaction buffer. The document is generated at DOC_OFF so the AccountSet
   header and VL prefix can be written immediately in front of it. */
#define DOC_OFF 8
static uint8_t txn[DOC_OFF + GEN_MAX_LEN + 8];
static uint8_t prepared[GEN_MAX_LEN + 600];

#define PUT32(b, o, v)                \
    {                                 \
        (b)[(o)] = (uint8_t)((v) >> 24);  \
        (b)[(o) + 1] = (uint8_t)((v) >> 16); \
        (b)[(o) + 2] = (uint8_t)((v) >> 8);  \
        (b)[(o) + 3] = (uint8_t)(v);      \
    }
#define GET32(b, o)                                                  \
    (((uint32_t)(b)[(o)] << 24) | ((uint32_t)(b)[(o) + 1] << 16) |   \
     ((uint32_t)(b)[(o) + 2] << 8) | (uint32_t)(b)[(o) + 3])

int64_t cbak(uint32_t reserved)
{
    accept(0, 0, 0);
    return 0;
}

int64_t hook(uint32_t reserved)
{
    _g(1, 1);

    int64_t tt = otxn_type();
    if (tt != ttCRON && tt != ttINVOKE)
        accept(SBUF("fuzz: not a wake, passing"), 0);

    uint8_t stats[20];
    for (int i = 0; GUARD(20), i < 20; ++i)
        stats[i] = 0;
    state(SBUF(stats), (uint32_t)"STATS", 5);
    uint32_t runs = GET32(stats, 0) + 1;

    etxn_reserve(2);

    /* 1. Randomness */
    uint8_t seed[32];
    if (ledger_nonce(SBUF(seed)) != 32)
        rollback(SBUF("fuzz: no nonce"), 1);

    /* 2. Generate the case directly into the transaction buffer. */
    int len = 0;
    int fault = gen(seed, txn + DOC_OFF, &len);

    /* 3. AccountSet { TransactionType, AppLoader } in front of the document. */
    int vl = len <= 192 ? 1 : 2;
    int start = DOC_OFF - (5 + vl);
    uint8_t* t = txn + start;
    t[0] = 0x12;
    t[1] = 0x00;
    t[2] = ttACCOUNT_SET;
    t[3] = 0x70; /* VL type 7, field 96 (sfAppLoader) */
    t[4] = 0x60;
    if (vl == 1)
        t[5] = (uint8_t)len;
    else
    {
        int l = len - 193;
        t[5] = (uint8_t)(193 + (l >> 8));
        t[6] = (uint8_t)(l & 0xFF);
    }

    int64_t plen =
        prepare(SBUF(prepared), (uint32_t)t, (uint32_t)(5 + vl + len));

    int harness_error = 0;
    int observed_pass = 0;
    if (plen < 0)
        harness_error = 1;
    else
    {
        uint8_t h[32];
        observed_pass = emit(SBUF(h), (uint32_t)prepared, plen) == 32;
    }

    int expected_pass = fault == F_NONE;

    /* 4. Record */
    if (harness_error)
        PUT32(stats, 16, GET32(stats, 16) + 1)
    else if (observed_pass == expected_pass)
    {
        if (expected_pass)
            PUT32(stats, 4, GET32(stats, 4) + 1)
        else
            PUT32(stats, 8, GET32(stats, 8) + 1)
    }
    else
    {
        PUT32(stats, 12, GET32(stats, 12) + 1);

        uint8_t key[32];
        util_sha512h(SBUF(key), (uint32_t)(txn + DOC_OFF), len);

        uint8_t f[4 + 32 + HEAD];
        f[0] = (uint8_t)fault;
        f[1] = (uint8_t)observed_pass;
        f[2] = (uint8_t)(len >> 8);
        f[3] = (uint8_t)len;
        for (int i = 0; GUARD(32), i < 32; ++i)
            f[4 + i] = seed[i];
        int head = len < HEAD ? len : HEAD;
        for (int i = 0; GUARD(HEAD), i < head; ++i)
            f[36 + i] = txn[DOC_OFF + i];
        state_set((uint32_t)f, 36 + head, SBUF(key));
    }

    PUT32(stats, 0, runs);
    state_set(SBUF(stats), (uint32_t)"STATS", 5);

    /* Re-arm: CronSet { StartTime 0, RepeatCount 256, DelaySeconds }. */
    if (runs % REARM_EVERY == 0)
    {
        uint32_t delay = 10;
        uint8_t p[4];
        if (hook_param(SBUF(p), (uint32_t)"DELAY", 5) == 4)
            delay = GET32(p, 0);

        uint8_t c[3 + 3 * 6];
        c[0] = 0x12;
        c[1] = 0x00;
        c[2] = ttCRON_SET;
        c[3] = 0x20; c[4] = 93;                 /* sfStartTime    */
        PUT32(c, 5, 0);
        c[9] = 0x20; c[10] = 94;                /* sfRepeatCount  */
        PUT32(c, 11, 256);
        c[15] = 0x20; c[16] = 95;               /* sfDelaySeconds */
        PUT32(c, 17, delay);

        int64_t cl = prepare(SBUF(prepared), (uint32_t)c, sizeof(c));
        uint8_t h[32];
        if (cl > 0)
            emit(SBUF(h), (uint32_t)prepared, cl);
    }

    if (observed_pass != expected_pass && !harness_error)
        accept(SBUF("fuzz: FINDING recorded"), fault);
    accept(SBUF("fuzz: case ok"), fault);
    return 0;
}
