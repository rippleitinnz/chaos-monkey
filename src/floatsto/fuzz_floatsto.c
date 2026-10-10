/**
 * Chaos Monkey, harness D: float_* / sto_* / etxn_* / emit testing.
 *
 * The test cases live in src/floatsto/cases.mjs (single source of truth) and
 * are compiled in via the generated cases.gen.h / cases.gen.inc. Every
 * expected value is stated in the Hook API docs (XFL encodings derived from
 * the XFL spec page) and checked against xahaud release 0f3258d; the float
 * cases are also executed natively against the release float code
 * (`make check-float`). See cases.mjs for the rule and the known divergences.
 *
 * On every wake (ttCRON or ttINVOKE) the Hook:
 *   1. reserves one emission (needed by etxn_* / emit and the Cron re-arm),
 *   2. builds its XFL operands through the API (float_one, float_set, ...),
 *   3. draws 32 bytes (ledger_nonce) and selects case = seed[0] & 63,
 *   4. makes exactly one host call whose result is known in advance,
 *   5. records any mismatch as a finding, counts the run, re-arms Cron
 *      every REARM_EVERY runs.
 *
 * Hook state (namespace sha256("chaos-fuzzer-floatsto")):
 *   "STATS" (5-byte key)  runs(4) correct(4) findings(4) unused(4), big-endian
 *   [c, 'F', 0 x 30]      finding for case c: c(1) expected(8) actual(8), BE
 *
 * Memory model: linear memory is exactly MEM_SIZE bytes, asserted against the
 * compiled module at build time (tools/check-wasm-memory.mjs).
 *
 * No loops anywhere: the only guard is _g(1,1) at entry.
 */

#include "hook/hookapi.h"

#define REARM_EVERY 200

#define MEM_SIZE 0x20000u            /* asserted at build time            */
#define OOB      0xFFFFFFF0u         /* start address beyond memory       */

#define PUT32(b,o,v) \
    {(b)[(o)]=(uint8_t)((v)>>24);(b)[(o)+1]=(uint8_t)((v)>>16); \
     (b)[(o)+2]=(uint8_t)((v)>>8);(b)[(o)+3]=(uint8_t)(v);}
#define GET32(b,o) \
    (((uint32_t)(b)[(o)]<<24)|((uint32_t)(b)[(o)+1]<<16)| \
     ((uint32_t)(b)[(o)+2]<<8)|(uint32_t)(b)[(o)+3])
#define PUT64(b,o,v) \
    {PUT32(b,o,(uint32_t)((uint64_t)(v)>>32)); PUT32(b,(o)+4,(uint32_t)(uint64_t)(v));}

/* Scratch (BSS, zeroed at instantiation). */
static uint8_t wb_[256];
static uint8_t rb_[256];
static uint8_t prep_[600];
static uint8_t fkey_[32];

/* Fixed inputs. */
static const uint8_t s1_[5]  = {0x22,0,0,0,0};                 /* {Flags=0}               */
static const uint8_t s2_[10] = {0x22,0,0,0,0, 0x24,0,0,0,1};   /* {Flags=0, Sequence=1}   */
static const uint8_t t2_[2]  = {0x22,0x00};                    /* UINT32 header, truncated */
static const char k_delay_[] = "DELAY";

#define WB  ((uint32_t)wb_)
#define RB  ((uint32_t)rb_)
#define S1  ((uint32_t)s1_)
#define S2  ((uint32_t)s2_)
#define T2  ((uint32_t)t2_)
#define BAD ((int64_t)0xDEADBEEFDEADBEEFULL)   /* negative enclosing number: invalid XFL */

#include "cases.gen.h"

int64_t cbak(uint32_t r) { accept(0, 0, 0); return 0; }

int64_t hook(uint32_t reserved)
{
    _g(1, 1);

    int64_t tt = otxn_type();
    if (tt != ttCRON && tt != ttINVOKE)
        accept(SBUF("floatsto: not a wake"), 0);

    uint8_t stats[16];
    stats[0]=stats[1]=stats[2]=stats[3]=0;
    stats[4]=stats[5]=stats[6]=stats[7]=0;
    stats[8]=stats[9]=stats[10]=stats[11]=0;
    stats[12]=stats[13]=stats[14]=stats[15]=0;
    state(SBUF(stats), (uint32_t)"STATS", 5);
    uint32_t runs = GET32(stats, 0) + 1;

    /* etxn_* / emit cases need a reservation; the Cron re-arm uses it too. */
    etxn_reserve(1);

    /* XFL operands, built through the API exactly as a Hook would. */
    int64_t ONE     = float_one();
    int64_t TWO     = float_set(0, 2);
    int64_t THREE   = float_set(0, 3);
    int64_t SIX     = float_set(0, 6);
    int64_t HUNDRED = float_set(2, 1);
    int64_t NONE    = float_negate(ONE);
    int64_t PI      = float_set(-15, 3141592653589793LL);

    uint8_t seed[32];
    if (ledger_nonce(SBUF(seed)) != 32)
        rollback(SBUF("floatsto: no nonce"), 1);
    int c = (int)(seed[0] & (CASE_COUNT - 1));

    int64_t actual = 0;
#include "cases.gen.inc"

    int64_t exp = EXPECTED[c];
    int correct = (actual == exp);

    if (correct)
    {
        PUT32(stats, 4, GET32(stats, 4) + 1);
    }
    else
    {
        PUT32(stats, 8, GET32(stats, 8) + 1);
        fkey_[0] = (uint8_t)c;
        fkey_[1] = 'F';
        uint8_t f[17];
        f[0] = (uint8_t)c;
        PUT64(f, 1, exp);
        PUT64(f, 9, actual);
        state_set(SBUF(f), (uint32_t)fkey_, 32);
    }

    PUT32(stats, 0, runs);
    state_set(SBUF(stats), (uint32_t)"STATS", 5);

    if (runs % REARM_EVERY == 0)
    {
        uint32_t delay = 10;
        uint8_t p[4];
        if (hook_param(SBUF(p), (uint32_t)k_delay_, 5) == 4)
            delay = GET32(p, 0);

        uint8_t cronbuf[3 + 3 * 6];
        cronbuf[0] = 0x12; cronbuf[1] = 0x00; cronbuf[2] = ttCRON_SET;
        cronbuf[3]  = 0x20; cronbuf[4]  = 93; PUT32(cronbuf,  5, 0);
        cronbuf[9]  = 0x20; cronbuf[10] = 94; PUT32(cronbuf, 11, 256);
        cronbuf[15] = 0x20; cronbuf[16] = 95; PUT32(cronbuf, 17, delay);
        int64_t cl = prepare(SBUF(prep_), (uint32_t)cronbuf, sizeof(cronbuf));
        uint8_t h[32];
        if (cl > 0) emit(SBUF(h), (uint32_t)prep_, cl);
    }

    if (!correct)
        accept(SBUF("floatsto: FINDING recorded"), c);
    accept(SBUF("floatsto: case ok"), c);
    return 0;
}
