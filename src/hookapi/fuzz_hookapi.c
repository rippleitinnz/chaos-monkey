/**
 * Chaos Monkey, harness C: Hook API boundary testing.
 *
 * The test cases live in src/hookapi/cases.mjs (single source of truth) and
 * are compiled in via the generated cases.gen.h / cases.gen.inc. Every
 * expected value is stated on the function's own page of the Hook API docs
 * and confirmed against xahaud release 0f3258d — see cases.mjs for the rule.
 *
 * On every wake (ttCRON or ttINVOKE) the Hook:
 *   1. writes the fixture state (key FK, 32 bytes) and keeps the return code,
 *   2. draws 32 bytes (ledger_nonce) and selects case = seed[0] & 63,
 *   3. makes exactly one host call with arguments whose result is known,
 *   4. records any mismatch as a finding, counts the run, re-arms Cron
 *      every REARM_EVERY runs.
 *
 * Hook state (namespace sha256("chaos-fuzzer-hookapi")):
 *   "STATS" (5-byte key)  runs(4) correct(4) findings(4) unused(4), big-endian
 *   FK (0xA5 x 32)        fixture value, 32 bytes, rewritten every run
 *   [c, 'F', 0 x 30]      finding for case c: c(1) expected(8) actual(8), BE
 *
 * Memory model: linear memory is exactly MEM_SIZE bytes. The build asserts
 * this against the compiled module (tools/check-wasm-memory.mjs), so the
 * OOB/EDGE pointers below can never silently become valid addresses again.
 *
 * No loops anywhere: the only guard is _g(1,1) at entry.
 */

#include "hook/hookapi.h"

#define REARM_EVERY 200

#define MEM_SIZE 0x20000u            /* asserted at build time            */
#define OOB      0xFFFFFFF0u         /* start address beyond memory       */
#define EDGE     (MEM_SIZE - 16u)    /* 32-byte access overruns by 16     */

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
static const uint8_t fk_[32] = {
    0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,
    0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5};
static const uint8_t mk_[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
static const uint8_t z20_[20] = {0};
static const char rzero_[] = "rrrrrrrrrrrrrrrrrrrrrhoLvTp";   /* account zero, 27 chars  */
static const char rbad_[]  = "rrrrrrrrrrrrrrrrrrrrrhoLvTq";   /* same, bad checksum      */
static const uint8_t s1_[5]  = {0x22,0,0,0,0};                 /* {Flags=0}               */
static const uint8_t s2_[10] = {0x22,0,0,0,0, 0x24,0,0,0,1};   /* {Flags=0, Sequence=1}   */
static const uint8_t f1_[5]  = {0x24,0,0,0,1};                 /* Sequence=1              */
static const char k_delay_[] = "DELAY";
static const char k_nope_[]  = "NOPE";

#define WB      ((uint32_t)wb_)
#define RB      ((uint32_t)rb_)
#define PREP    ((uint32_t)prep_)
#define FK      ((uint32_t)fk_)
#define MK      ((uint32_t)mk_)
#define Z20     ((uint32_t)z20_)
#define RZERO   ((uint32_t)rzero_)
#define RBAD    ((uint32_t)rbad_)
#define S1      ((uint32_t)s1_)
#define S2      ((uint32_t)s2_)
#define F1      ((uint32_t)f1_)
#define K_DELAY ((uint32_t)k_delay_)
#define K_NOPE  ((uint32_t)k_nope_)

#include "cases.gen.h"

int64_t cbak(uint32_t r) { accept(0, 0, 0); return 0; }

int64_t hook(uint32_t reserved)
{
    _g(1, 1);

    int64_t tt = otxn_type();
    if (tt != ttCRON && tt != ttINVOKE)
        accept(SBUF("hookapi: not a wake"), 0);

    uint8_t stats[16];
    stats[0]=stats[1]=stats[2]=stats[3]=0;
    stats[4]=stats[5]=stats[6]=stats[7]=0;
    stats[8]=stats[9]=stats[10]=stats[11]=0;
    stats[12]=stats[13]=stats[14]=stats[15]=0;
    state(SBUF(stats), (uint32_t)"STATS", 5);
    uint32_t runs = GET32(stats, 0) + 1;

    /* etxn_details needs a reservation; the Cron re-arm uses it too. */
    etxn_reserve(1);

    /* Fixture: gives the state() cases a known 32-byte value from run 1. */
    int64_t FIXSET = state_set(RB, 32, FK, 32);

    uint8_t seed[32];
    if (ledger_nonce(SBUF(seed)) != 32)
        rollback(SBUF("hookapi: no nonce"), 1);
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
        if (hook_param(SBUF(p), K_DELAY, 5) == 4)
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
        accept(SBUF("hookapi: FINDING recorded"), c);
    accept(SBUF("hookapi: case ok"), c);
    return 0;
}
