// Native harness: runs gen() against the real ripple::appLoader::validate()
// from the pwabootloader branch. Every case whose verdict disagrees with the
// one the generator expects is printed. Used to prove the generator is
// correct before the Hook runs it on-ledger.
#include <xrpl/protocol/AppLoader.h>
#include <cstdio>
#include <cstdlib>
#include <random>

extern "C" {
#include "gen.h"
}

// Names come from src/apploader/faults.mjs via tools/check-faults.mjs.
static const char* FAULT_NAMES[F_COUNT] = {
#include "apploader_fault_names.inc"
};

int main(int argc, char** argv)
{
    long n = argc > 1 ? atol(argv[1]) : 200000;
    std::mt19937_64 rng(argc > 2 ? atol(argv[2]) : 1);
    static unsigned char doc[GEN_MAX_LEN + 64];
    long mism[F_COUNT] = {0}, seen[F_COUNT] = {0};
    long printed = 0;

    for (long c = 0; c < n; ++c)
    {
        unsigned char r[32];
        for (auto& b : r)
            b = (unsigned char)rng();
        int len = 0;
        int fault = gen(r, doc, &len);
        auto res = ripple::appLoader::validate(doc, (std::size_t)len);
        bool pass = res == ripple::appLoader::Result::ok;
        bool expect_pass = (bool)fault_is_pass(fault);
        seen[fault]++;
        if (pass != expect_pass)
        {
            mism[fault]++;
            if (printed++ < 12)
            {
                printf("MISMATCH fault=%s expected=%s got=%s len=%d doc=",
                       FAULT_NAMES[fault], expect_pass ? "pass" : "fail",
                       ripple::appLoader::to_string(res), len);
                for (int i = 0; i < len && i < 120; ++i)
                    printf(doc[i] >= 0x20 && doc[i] < 0x7F ? "%c" : "\\x%02X",
                           doc[i]);
                printf("\n");
            }
        }
    }
    printf("\n%-32s %10s %10s\n", "fault", "cases", "mismatch");
    for (int f = 0; f < F_COUNT; ++f)
        printf("%-32s %10ld %10ld\n", FAULT_NAMES[f], seen[f], mism[f]);
    return 0;
}
