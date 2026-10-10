// Run xahaud release float code (extracted verbatim into build/xfl_release.h)
// on Harness D's float inputs, through wrappers identical to applyHook.cpp's.
//   make check-float XAHAUD_SRC=../xahaud   (a checkout of release 0f3258d)
#include "xfl_release.h"
#include <cstdio>
#include <cstring>
using namespace hook;
// rippled's Throw<> calls LogThrow (logging only) before throwing; no log here.
namespace ripple { void LogThrow(std::string const&) {} }
// R accepts both a plain value and a hook_return_code, as the host ABI does.
struct R { int64_t v; R(int64_t x) : v(x) {} R(hook_api::hook_return_code c) : v((int64_t)c) {} };
#define WRAP(expr) { auto res_ = (expr); if (!res_) return R(res_.error()); return R((int64_t)res_.value()); }
static R W_set(int32_t e, int64_t m)          { WRAP(float_set(e, m)); }
static R W_one()                              { return R((int64_t)float_one()); }
static R W_neg(int64_t a)                     { RETURN_IF_INVALID_FLOAT(a); return R((int64_t)float_negate(a)); }
static R W_sum(int64_t a, int64_t b)          { RETURN_IF_INVALID_FLOAT(a); RETURN_IF_INVALID_FLOAT(b); WRAP(float_sum(a, b)); }
static R W_mul(int64_t a, int64_t b)          { RETURN_IF_INVALID_FLOAT(a); RETURN_IF_INVALID_FLOAT(b); WRAP(float_multiply(a, b)); }
static R W_div(int64_t a, int64_t b)          { RETURN_IF_INVALID_FLOAT(a); RETURN_IF_INVALID_FLOAT(b); WRAP(float_divide(a, b)); }
static R W_inv(int64_t a)                     { RETURN_IF_INVALID_FLOAT(a); WRAP(float_invert(a)); }
static R W_cmp(int64_t a, int64_t b, uint32_t m) { RETURN_IF_INVALID_FLOAT(a); RETURN_IF_INVALID_FLOAT(b); WRAP(float_compare(a, b, m)); }
static R W_int(int64_t a, uint32_t d, uint32_t ab) { RETURN_IF_INVALID_FLOAT(a); WRAP(float_int(a, d, ab)); }
static R W_man(int64_t a)                     { RETURN_IF_INVALID_FLOAT(a); WRAP(float_mantissa(a)); }
static R W_sign(int64_t a)                    { RETURN_IF_INVALID_FLOAT(a); return R((int64_t)float_sign(a)); }
static R W_log(int64_t a)                     { RETURN_IF_INVALID_FLOAT(a); WRAP(float_log(a)); }
static R W_root(int64_t a, uint32_t n)        { RETURN_IF_INVALID_FLOAT(a); WRAP(float_root(a, n)); }
static R W_mulr(int64_t a, uint32_t r, uint32_t n, uint32_t d) { RETURN_IF_INVALID_FLOAT(a); WRAP(float_mulratio(a, r, n, d)); }

int main(int argc, char** argv)
{
    // Operands built through the API itself, as the Hook does.
    const int64_t ONE = W_one().v, TWO = W_set(0, 2).v, THREE = W_set(0, 3).v, SIX = W_set(0, 6).v,
                  HUNDRED = W_set(2, 1).v, NONE = W_neg(ONE).v, PI = W_set(-15, 3141592653589793LL).v,
                  BAD = (int64_t)0xDEADBEEFDEADBEEFULL;
    struct { const char* id; int64_t v; } R[] = {
#define X(id, e) { id, (e).v },
#include "native_floatsto_cases.inc"
#undef X
    };
    for (auto& r : R) std::printf("%s %lld\n", r.id, (long long)r.v);
    return 0;
}
