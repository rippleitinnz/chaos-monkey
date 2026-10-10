# Hook API: documentation gaps and doc/code divergences

Found while rebuilding Chaos Monkey harnesses A, C and D (October 2026). Each item was
checked against the docs source (`Xahau/xahau-web`,
`src/content/docs/docs/hooks/functions/`) and xahaud release 2026.9.29
(`0f3258d`, `src/xrpld/app/hook/detail/applyHook.cpp` and `HookAPI.cpp`).

Harnesses C and D only test behaviour the docs state. Divergences are tested
at the spec value and show up as expected findings; everything else below is
not tested. These are candidates for a docs PR, or questions for the maintainers.

## Doc and code disagree

| Function | Docs | Release code |
|---|---|---|
| `etxn_details` | Writes 105 bytes without `cbak`, 127 bytes with it | Requires and writes **116 / 138** bytes. Harness C case `ed.ok` tests the spec value, so it is expected to report this as a finding. |
| `util_accid` | TOO_BIG when `read_len` is "longer than an r-address can be" (max 35) | TOO_BIG only when `read_len > 49`. Lengths 36–49 return INVALID_ARGUMENT. |
| `util_accid` | Return described as "the length of the output r-address" | Returns 20, the Account ID length. This looks like a copy/paste from `util_raddr`. |
| `sto_validate` | Returns 1 (valid), 0 (invalid) or OUT_OF_BOUNDS | Returns **TOO_SMALL** for buffers under 2 bytes. Harness D cases `sv.len0` and `sv.len1` test the spec value 0. This is the only real fix in the open `float_set`/`sto_validate` PR. |
| `otxn_generation` | "the generation of the originating transaction or `1` if no generation field is present" | Returns **0** when there's no `sfEmitDetails`. `etxn_generation` (= otxn + 1) is still 1, which is what the emission spec requires. Harness D case `og.none`. |

## Example values in the docs are wrong

- **`sfEmitNonce` example.** The `otxn_field`, `slot_subfield` and `slot_subarray` pages say `sfEmitNonce` (type 5, field 11) is `0x050BU`. By the docs' own formula (type in the high 16 bits) it is `0x5000B`. Harness C's original `otxn_field` cases used this mistaken encoding (`0x1200`, `0x6800`).
- **`slot_subarray` `array_id`.** It is described as an "sf code". The code treats it as an array index.

## Behaviour that depends on an amendment

| Function | Without `fixFloatDivide` | With it |
|---|---|---|
| `float_divide`, `float_invert` | Exact quotients come out short: 6 ÷ 2 = 2.999999999999999, 1 ÷ 2 = 0.4999999999999990 | Exact. Harness D cases `fd.three` and `fi.half` test the exact spec value, so findings there mean the amendment is not active on that network. Proven by `make check-float`, which runs the release code with the switch off and on. |

## Error names

- **`OVERFLOW` vs `XFL_OVERFLOW`.** The `float_sum`, `float_multiply` and `float_mulratio` pages document an `OVERFLOW` error. No such code exists: `error.h` and the node use `XFL_OVERFLOW` (-30). The `float_sto` page uses the right name.

## `float_set` parameter range vs adjustment

- **The exponent parameter range.** The page gives it as `-96` to `80`, but then says the mantissa is adjusted to 16 digits first. So `float_set(81, 1)` is legal: it is 1 x 10^81, which adjusts to 10^15 x 10^66. Only an exponent that is out of range *after* adjustment gives INVALID_FLOAT, which is what the code does.
- **EXPONENT_OVERSIZED and EXPONENT_UNDERSIZED.** These are not documented for `float_set`. The current INVALID_FLOAT behaviour is the documented one. (The open PR's `float_set` change was based on a mistaken test case and should be dropped.)

## AppLoader (`featurePWALoader`, pwabootloader `98636ac`)

- **`<!doctype svg>` is accepted.** `AppLoader.h` says a document must open with "an HTML doctype or an `<html` start tag". The validator only checks for `<!doctype` followed by whitespace, so any doctype name passes. `PWALoader_test` doesn't pin this either way. Is a non-HTML doctype meant to be accepted? Harness A no longer tests it.

## Behaviour the docs do not cover

- **TOO_SMALL on `hook_account`, `ledger_nonce` and `ledger_last_hash`.** The code returns it when the buffer is under 20/32 bytes; each page lists only OUT_OF_BOUNDS.
- **`slot()` on an empty slot.** The code returns DOESNT_EXIST; the page lists only OUT_OF_BOUNDS and TOO_SMALL.
- **Slot number 0.** It is not described anywhere. The code returns DOESNT_EXIST from `slot`/`slot_clear` (it is never filled); `new_slot = 0` means "allocate" in `slot_subfield` and `slot_subarray`.
- **`state()` TOO_SMALL beyond what's documented.** The page documents TOO_SMALL only for an output buffer too small for the stored value. The code also returns it for `kread_len == 0`, and for `write_len == 0` with a non-null `write_ptr`, before any lookup.
- **`otxn_field` with `field_id = 0`.** It returns DOESNT_EXIST, not INVALID_FIELD: `SField::getField(0)` resolves to the internal `sfGeneric` placeholder, which is registered under code 0. It is unclear whether this is intended.
- **TOO_SMALL on `etxn_nonce` (write_len < 32) and on `emit` (write_len < 32).** The code returns it; neither page lists it.
- **`float_root` with `n < 2`, and `float_log` of zero.** Both return INVALID_ARGUMENT, which is not documented.
- **MEM_OVERLAP.** It appears in `error.h`, and `sto_emplace`/`sto_erase` return it for overlapping buffers. Neither page lists it, and no other function checks for overlap.
- **`sto_emplace` TOO_BIG.** The limits (source > 16 KiB, field > 4096 bytes) are not stated.
- **`sto_emplace` PARSE_ERROR.** The paths depend on amendments `fix20260929` and `fixHookAPI20251128`, which the docs don't mention.
