// Chaos Monkey, harness A — fault classes, for reports (status, dashboard).
//
// Index = fault id as returned by gen() and as the Hook's return code.
// `pass` = the document must be ACCEPTED. tools/check-faults.mjs fails the
// build if this table and src/apploader/gen.h (F_* ids, F_COUNT,
// fault_is_pass) ever disagree.
//
// Every class is stated in AppLoader.h's doc comment or pinned in
// PWALoader_test (pwabootloader branch).

export const FAULTS = [
  { id: "F_NONE",             short: "clean",       name: "clean document",                pass: true  },
  { id: "F_DOUBLE_BOM",       short: "2xBOM",       name: "double BOM",                    pass: false },
  { id: "F_VT_LEAD",          short: "VT lead",     name: "VT before opener",              pass: false },
  { id: "F_DOCTYPE_NO_WS",    short: "doctype",     name: "<!doctype> without whitespace", pass: false },
  { id: "F_HTMLX_OPENER",     short: "htmlx",       name: "<htmlx> opener",                pass: false },
  { id: "F_NO_HTML_ELEMENT",  short: "no html",     name: "no <html> element",             pass: false },
  { id: "F_MISSING_CLOSE",    short: "no /html",    name: "missing </html>",               pass: false },
  { id: "F_CLOSE_SLASH",      short: "/html/",      name: "</html/>",                      pass: false },
  { id: "F_CLOSE_HTMLX",      short: "/htmlx",      name: "</htmlx>",                      pass: false },
  { id: "F_TRAILING_GARBAGE", short: "junk",        name: "trailing garbage",              pass: false },
  { id: "F_TRUNCATED_END",    short: "cut UTF8",    name: "truncated UTF-8 at end",        pass: false },
  { id: "F_TOO_LONG",         short: "4097B",       name: "4097 bytes",                    pass: false },
  { id: "F_BODY_FFFE",        short: "FFFE",        name: "U+FFFE",                        pass: false },
  { id: "F_BODY_FFFF",        short: "FFFF",        name: "U+FFFF",                        pass: false },
  { id: "F_BODY_OVERLONG2",   short: "overlong2",   name: "overlong 2-byte",               pass: false },
  { id: "F_BODY_OVERLONG3",   short: "overlong3",   name: "overlong 3-byte",               pass: false },
  { id: "F_BODY_SURROGATE",   short: "surrogate",   name: "surrogate",                     pass: false },
  { id: "F_BODY_ABOVE_MAX",   short: ">10FFFF",     name: "above U+10FFFF",                pass: false },
  { id: "F_BODY_LONE_CONT",   short: "lone cont",   name: "lone continuation",             pass: false },
  { id: "F_BODY_NUL",         short: "NUL",         name: "NUL in body",                   pass: false },
  { id: "F_BODY_DEL",         short: "DEL",         name: "DEL in body",                   pass: false },
  { id: "F_BODY_VT",          short: "VT body",     name: "VT in body",                    pass: false },
  { id: "F_BODY_C0",          short: "C0 body",     name: "other C0 control in body",      pass: false },
  { id: "F_OPENER_C0",        short: "C0 lead",     name: "C0 control before opener",      pass: false },
  { id: "F_CLOSE_NO_GT",      short: "/html no>",   name: "</html without >",              pass: false },
  { id: "F_MULTI_CLOSE",      short: "multi✓",      name: "multiple </html> (last wins)",  pass: true  },
];
