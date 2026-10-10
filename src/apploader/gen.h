/**
 * AppLoader test-case generator (shared by the Hook and the native harness).
 *
 * gen() turns 32 random bytes into one AppLoader document whose verdict is
 * known by construction from the rules documented in AppLoader.h:
 *
 *   - every case carries a random mix of features the spec says must PASS
 *     (BOM, leading whitespace, mixed-case tags, <html/>, whitespace before
 *     '>' in </html>, trailing whitespace, multi-byte UTF-8, C1 controls,
 *     noncharacters other than U+FFFE/U+FFFF, FF/CR in the body, exactly
 *     maxAppLoaderLength bytes);
 *   - at most ONE fault the spec says must FAIL is injected, so a mismatch
 *     points at a single rule.
 *
 * Returns the injected fault id (0 = none, the document must be accepted).
 * The output buffer needs 8 bytes of slack past GEN_MAX_LEN.
 *
 * Written for the Hook guard budget (65535 worst-case instructions): every
 * loop appears once, tag strings go through one segment writer, and padding
 * is written eight bytes per iteration.
 *
 * Fault classes 22-25 added in v2:
 *   22 F_BODY_C0      : other forbidden C0 control in body (SOH..US minus whitespace/VT/NUL/DEL)
 *   23 F_OPENER_C0    : forbidden C0 control other than VT before the opener
 *   24 F_CLOSE_NO_GT  : </html without closing > (truncated close tag)
 *   25 F_MULTI_CLOSE  : multiple </html> tags; must PASS. AppLoader.h: "the last such
 *                       end tag followed by nothing but ASCII whitespace".
 *
 * v3 (spec-only rule): the former class 25, "<!doctype svg> must pass", was removed.
 * AppLoader.h requires the document to open with "an HTML doctype or an <html start
 * tag"; <!doctype svg> is not an HTML doctype, and PWALoader_test does not pin it.
 * The validator accepts it only because it checks the "<!doctype" + whitespace
 * prefix, so the case tested code behaviour, not the spec. See docs/hookapi-doc-gaps.md.
 * Every remaining class is stated in AppLoader.h or pinned in PWALoader_test.
 * The fault table for reports lives in faults.mjs; tools/check-faults.mjs keeps it
 * in step with this file.
 */

#ifndef CHAOS_GEN_H
#define CHAOS_GEN_H

#ifndef GUARD
#define GUARD(n) 1
#endif

#define GI static inline __attribute__((always_inline))

#define GEN_MAX_LEN 4097
#define GEN_LIMIT 4096 /* maxAppLoaderLength */

/* Fault ids. Keep in sync with the report page. */
#define F_NONE 0
#define F_DOUBLE_BOM 1
#define F_VT_LEAD 2
#define F_DOCTYPE_NO_WS 3
#define F_HTMLX_OPENER 4
#define F_NO_HTML_ELEMENT 5
#define F_MISSING_CLOSE 6
#define F_CLOSE_SLASH 7
#define F_CLOSE_HTMLX 8
#define F_TRAILING_GARBAGE 9
#define F_TRUNCATED_END 10
#define F_TOO_LONG 11
#define F_BODY_FFFE 12
#define F_BODY_FFFF 13
#define F_BODY_OVERLONG2 14
#define F_BODY_OVERLONG3 15
#define F_BODY_SURROGATE 16
#define F_BODY_ABOVE_MAX 17
#define F_BODY_LONE_CONT 18
#define F_BODY_NUL 19
#define F_BODY_DEL 20
#define F_BODY_VT 21
#define F_BODY_C0 22    /* other forbidden C0 (SOH/STX/ETX/etc.) in body      */
#define F_OPENER_C0 23  /* forbidden C0 (not VT/NUL/DEL) before opener        */
#define F_CLOSE_NO_GT 24 /* </html with no closing >                          */
#define F_MULTI_CLOSE 25   /* multiple </html> tags; must PASS (last wins)    */
#define F_COUNT 26

/* Body items: first byte = length. 0..11 must pass; 12..22 are the body
   faults, indexed by their fault id (F_BODY_FFFE == 12 .. F_BODY_C0 == 22).
   F_OPENER_C0..F_MULTI_CLOSE (23-25) are not body-item faults; pad to keep
   the table index scheme consistent (the extra entries are never selected). */
static const unsigned char ITEMS[26][5] = {
    {1, 'a', 0, 0, 0},
    {1, 'Z', 0, 0, 0},
    {1, ' ', 0, 0, 0},
    {1, '\n', 0, 0, 0},
    {1, 0x0C, 0, 0, 0},             /* FF is HTML whitespace  */
    {1, '\r', 0, 0, 0},
    {2, 0xC3, 0xA9, 0, 0},          /* e-acute                */
    {3, 0xE2, 0x82, 0xAC, 0},       /* euro sign              */
    {4, 0xF0, 0x9F, 0x98, 0x80},    /* emoji                  */
    {2, 0xC2, 0x85, 0, 0},          /* C1 control U+0085      */
    {3, 0xEF, 0xB7, 0x90, 0},       /* noncharacter U+FDD0    */
    {4, 0xF0, 0x9F, 0xBF, 0xBE},    /* noncharacter U+1FFFE   */
    {3, 0xEF, 0xBF, 0xBE, 0},       /* U+FFFE                 */
    {3, 0xEF, 0xBF, 0xBF, 0},       /* U+FFFF                 */
    {2, 0xC0, 0xAF, 0, 0},          /* overlong '/'           */
    {3, 0xE0, 0x80, 0xAF, 0},       /* overlong 3-byte '/'    */
    {3, 0xED, 0xA0, 0x80, 0},       /* surrogate U+D800       */
    {4, 0xF4, 0x90, 0x80, 0x80},    /* above U+10FFFF         */
    {1, 0x80, 0, 0, 0},             /* lone continuation byte */
    {1, 0x00, 0, 0, 0},             /* NUL                    */
    {1, 0x7F, 0, 0, 0},             /* DEL                    */
    {1, 0x0B, 0, 0, 0},             /* VT                     */
    {1, 0x01, 0, 0, 0},             /* SOH — other C0 control */
    /* padding entries for F_OPENER_C0..F_MULTI_CLOSE (23-25); never used */
    {1, 'a', 0, 0, 0},
    {1, 'a', 0, 0, 0},
    {1, 'a', 0, 0, 0},
};

static const unsigned char WS[5] = {0x09, 0x0A, 0x0C, 0x0D, 0x20};

/* Tag strings, lowercase; writers flip letter case from a mask. */
#define S_DOCTYPE 0     /* "<!doctype"        */
#define S_DOCTYPE_C 1   /* "<!doctype>"       */
#define S_HTMLGT 2      /* "html>"            */
#define S_HTML 3        /* "<html>"           */
#define S_HTML_LANG 4   /* "<html lang=en>"   */
#define S_HTML_SELF 5   /* "<html/>"          */
#define S_HTMLX 6       /* "<htmlx>"          */
#define S_HTML_DIR 7    /* "<html\tdir=ltr>"  */
#define S_CLOSE 8          /* "</html"              */
#define S_CLOSE_SLASH 9    /* "</html/>"            */
#define S_CLOSE_X 10       /* "</htmlx>"            */
static const char* const STR[11] = {"<!doctype", "<!doctype>", "html>",
                                    "<html>", "<html lang=en>", "<html/>",
                                    "<htmlx>", "<html\tdir=ltr>", "</html",
                                    "</html/>", "</htmlx>"};
static const unsigned char STRLEN[11] = {9, 10, 5, 6, 14, 7, 7, 14, 6, 8, 8};

/* Returns 1 if the fault class means the document should pass */
GI int fault_is_pass(int f)
{
    return f == F_NONE || f == F_MULTI_CLOSE;
}

GI int gen(const unsigned char* r, unsigned char* o, int* len)
{
    int p = 0;
    int fault = (r[0] & 1) ? (1 + (r[1] % (F_COUNT - 1))) : F_NONE;
    unsigned int mask = (unsigned int)r[2] | ((unsigned int)r[3] << 8);

    /* ---- head: BOM (double BOM is a fault) + leading whitespace ---- */
    if (fault == F_DOUBLE_BOM || (r[4] & 1))
    {
        o[p++] = 0xEF; o[p++] = 0xBB; o[p++] = 0xBF;
    }
    if (fault == F_DOUBLE_BOM)
    {
        o[p++] = 0xEF; o[p++] = 0xBB; o[p++] = 0xBF;
    }
    {
        int n = (r[4] >> 1) % 4;
        for (int i = 0; GUARD(3), i < n; ++i)
            o[p++] = WS[(r[5] >> i) % 5];
    }
    if (fault == F_VT_LEAD)
        o[p++] = 0x0B;
    if (fault == F_OPENER_C0)
        o[p++] = 0x01; /* SOH — forbidden C0, not VT/NUL/DEL */

    /* ---- opener: up to 3 segments, written by one flat loop ---- */
    int seg[3];
    int nseg = 0;
    int ws_after_first = -1; /* whitespace byte written after segment 0 */
    int vhtml = (r[7] >> 4) % 3;
    if (fault == F_DOCTYPE_NO_WS)
    {
        seg[nseg++] = S_DOCTYPE_C;
        seg[nseg++] = S_HTML;
    }
    else if (fault == F_HTMLX_OPENER)
        seg[nseg++] = S_HTMLX;
    else if ((r[6] & 3) != 0 || fault == F_NO_HTML_ELEMENT)
    {
        seg[nseg++] = S_DOCTYPE;
        ws_after_first = WS[r[7] % 5];
        seg[nseg++] = S_HTMLGT;
        seg[nseg++] = fault == F_NO_HTML_ELEMENT ? S_HTMLX
            : vhtml == 0                         ? S_HTML
            : vhtml == 1                         ? S_HTML_LANG
                                                 : S_HTML_SELF;
    }
    else
        seg[nseg++] = vhtml == 0 ? S_HTML
            : vhtml == 1         ? S_HTML_DIR
                                 : S_HTML_SELF;

    {
        int si = 0, ci = 0;
        for (int k = 0; GUARD(30), si < nseg; ++k)
        {
            unsigned char c = (unsigned char)STR[seg[si]][ci];
            if (c >= 'a' && c <= 'z' && ((mask >> (k & 15)) & 1))
                c = (unsigned char)(c - 32);
            o[p++] = c;
            if (++ci == STRLEN[seg[si]])
            {
                if (si == 0 && ws_after_first >= 0)
                    o[p++] = (unsigned char)ws_after_first;
                ++si;
                ci = 0;
            }
        }
    }

    /* ---- body: pass items, then the body fault (if any) ---- */
    int items = 1 + r[8] % 24;
    int body_fault = (fault >= F_BODY_FFFE && fault <= F_BODY_C0);
    int total = items + (body_fault ? 1 : 0);
    int fault_slot = r[9] % total; /* where the fault item goes */
    for (int i = 0; GUARD(25), i < total; ++i)
    {
        int idx = (body_fault && i == fault_slot)
            ? fault
            : r[10 + (i % 16)] % 12;
        o[p] = ITEMS[idx][1];
        o[p + 1] = ITEMS[idx][2];
        o[p + 2] = ITEMS[idx][3];
        o[p + 3] = ITEMS[idx][4];
        p += ITEMS[idx][0];
    }

    /* ---- closing section sizes, for exact-length padding ---- */
    int close_ws = r[26] % 3;

    /* F_MULTI_CLOSE: emit a decoy </html> then some body content, then the
       real </html> — last match wins, nothing follows, so it must pass.
       Decoy is 7 bytes ("</html>"), body content is 1 byte ('x'), real
       close is written in the close section below. */
    if (fault == F_MULTI_CLOSE)
    {
        /* write a decoy close */
        o[p++] = '<'; o[p++] = '/'; o[p++] = 'h';
        o[p++] = 't'; o[p++] = 'm'; o[p++] = 'l'; o[p++] = '>';
        o[p++] = 'x'; /* content between closes */
    }

    int close_seg = fault == F_CLOSE_SLASH  ? S_CLOSE_SLASH
        : fault == F_CLOSE_HTMLX            ? S_CLOSE_X
        : fault == F_MISSING_CLOSE          ? -1
        : fault == F_CLOSE_NO_GT            ? S_CLOSE   /* written without > */
                                            : S_CLOSE;  /* normal */
    /* For F_CLOSE_NO_GT: we write </html but no WS or >, so length is 6 */
    int close_len = close_seg < 0                         ? 0
        : (fault == F_CLOSE_NO_GT)                        ? 6
        : (close_seg == S_CLOSE || fault == F_MULTI_CLOSE)? 7 + close_ws
                                                          : 8;
    int trail_ws = r[27] % 4;
    int tail_len = trail_ws + (fault == F_TRAILING_GARBAGE ? 1 : 0) +
        (fault == F_TRUNCATED_END ? 2 : 0);

    int target = fault == F_TOO_LONG ? GEN_LIMIT + 1
        : (r[28] & 7) == 0           ? GEN_LIMIT
                                     : 0;
    if (target)
    {
        /* p already includes any bytes written by F_MULTI_CLOSE decoy above */
        int pad = target - p - close_len - tail_len;
        /* eight bytes per iteration; overrun is overwritten by what follows
           or lies beyond the document */
        for (int i = 0; GUARD(GEN_MAX_LEN / 8 + 1), i < pad; i += 8)
        {
            o[p + i] = 'a'; o[p + i + 1] = 'a'; o[p + i + 2] = 'a';
            o[p + i + 3] = 'a'; o[p + i + 4] = 'a'; o[p + i + 5] = 'a';
            o[p + i + 6] = 'a'; o[p + i + 7] = 'a';
        }
        p += pad;
    }

    /* ---- close + trailer ---- */
    if (close_seg >= 0)
    {
        int n = STRLEN[close_seg];
        for (int i = 0; GUARD(8), i < n; ++i)
        {
            unsigned char c = (unsigned char)STR[close_seg][i];
            if (c >= 'a' && c <= 'z' && ((mask >> ((i + 5) & 15)) & 1))
                c = (unsigned char)(c - 32);
            o[p++] = c;
        }
        if (close_seg == S_CLOSE && fault != F_CLOSE_NO_GT)
        {
            for (int i = 0; GUARD(2), i < close_ws; ++i)
                o[p++] = WS[(r[29] >> i) % 5];
            o[p++] = '>';
        }
        /* F_CLOSE_NO_GT: </html written above, no > appended — truncated tag */
    }

    for (int i = 0; GUARD(3), i < trail_ws; ++i)
        o[p++] = WS[(r[30] >> i) % 5];
    if (fault == F_TRAILING_GARBAGE)
        o[p++] = 'x';
    if (fault == F_TRUNCATED_END)
    {
        o[p++] = 0xE2;
        o[p++] = 0x82;
    }

    *len = p;
    return fault;
}

#endif
