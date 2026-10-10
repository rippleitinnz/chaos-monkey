# Chaos Monkey build
#
#   make            build both harness Hooks and guard-check them
#   make hookapi    harness C only: regenerate from cases.mjs, build, check
#   make floatsto   harness D only: same
#   make check-float  run xahaud's release float code natively on harness D's
#                   float cases (needs XAHAUD_SRC at release 0f3258d)
#   make check      run the generator against the real AppLoader validator
#                   (needs XAHAUD_SRC pointing at a xahaud checkout of the
#                   pwabootloader branch, plus boost and xxhash headers)
#   make tools      fetch and build hook-cleaner and guard_checker into tools/
#   make clean

CLANG        ?= clang
CXX          ?= g++
TOOLS        ?= tools
HOOK_CLEANER ?= $(TOOLS)/hook-cleaner-c/hook-cleaner
GUARD_CHECK  ?= $(TOOLS)/guard-checker/guard_checker
XAHAUD_SRC   ?= ../xahaud
CASES        ?= 500000

WASM_FLAGS_A = --target=wasm32 -nostdlib -fno-builtin -O2 -Iinclude -Isrc/apploader \
               -Wl,--no-entry -Wl,--allow-undefined -Wl,--export=hook -Wl,--export=cbak

WASM_FLAGS_C = --target=wasm32 -nostdlib -fno-builtin -O2 -Iinclude -Isrc/hookapi \
               -Wl,--no-entry -Wl,--allow-undefined -Wl,--export=hook -Wl,--export=cbak

WASM_FLAGS_D = --target=wasm32 -nostdlib -fno-builtin -O2 -Iinclude -Isrc/floatsto \
               -Wl,--no-entry -Wl,--allow-undefined -Wl,--export=hook -Wl,--export=cbak

all: dist/fuzz_apploader.wasm hookapi floatsto

# Harness A: src/apploader/faults.mjs (reports) must agree with gen.h (Hook).
build/apploader_fault_names.inc: src/apploader/faults.mjs src/apploader/gen.h tools/check-faults.mjs
	node tools/check-faults.mjs

dist/fuzz_apploader.wasm: src/apploader/fuzz_apploader.c src/apploader/gen.h build/apploader_fault_names.inc
	@mkdir -p build dist
	$(CLANG) $(WASM_FLAGS_A) -o build/fuzz_apploader.raw.wasm $<
	$(HOOK_CLEANER) build/fuzz_apploader.raw.wasm $@ > /dev/null
	$(GUARD_CHECK) $@ > build/fuzz_apploader.guard.txt 2>&1 || { tail -5 build/fuzz_apploader.guard.txt; rm -f $@; exit 1; }
	@grep -q "Hook validation successful" build/fuzz_apploader.guard.txt || { tail -5 build/fuzz_apploader.guard.txt; rm -f $@; exit 1; }
	@tail -2 build/fuzz_apploader.guard.txt

# Harnesses C and D: src/<h>/cases.mjs is the single source; tools/gen-cases.mjs
# derives the C dispatch, EXPECTED[] and the dashboard labels from it.
HOOKAPI_GEN = src/hookapi/cases.gen.h src/hookapi/cases.gen.inc dist/dashboard-hookapi.html

$(HOOKAPI_GEN) &: src/hookapi/cases.mjs tools/gen-cases.mjs dashboard-hookapi/dashboard-hookapi.html include/hook/error.h
	node tools/gen-cases.mjs hookapi

dist/fuzz_hookapi.wasm: src/hookapi/fuzz_hookapi.c src/hookapi/cases.gen.h src/hookapi/cases.gen.inc
	@mkdir -p build dist
	$(CLANG) $(WASM_FLAGS_C) -o build/fuzz_hookapi.raw.wasm $<
	$(HOOK_CLEANER) build/fuzz_hookapi.raw.wasm $@ > /dev/null
	node tools/check-wasm-memory.mjs $@ build/fuzz_hookapi.raw.wasm src/hookapi/fuzz_hookapi.c || { rm -f $@; exit 1; }
	$(GUARD_CHECK) $@ > build/fuzz_hookapi.guard.txt 2>&1 || { tail -5 build/fuzz_hookapi.guard.txt; rm -f $@; exit 1; }
	@grep -q "Hook validation successful" build/fuzz_hookapi.guard.txt || { tail -5 build/fuzz_hookapi.guard.txt; rm -f $@; exit 1; }
	@tail -2 build/fuzz_hookapi.guard.txt

hookapi: dist/fuzz_hookapi.wasm dist/dashboard-hookapi.html

FLOATSTO_GEN = src/floatsto/cases.gen.h src/floatsto/cases.gen.inc dist/dashboard-floatsto.html build/native_floatsto_cases.inc

$(FLOATSTO_GEN) &: src/floatsto/cases.mjs tools/gen-cases.mjs dashboard-floatsto/dashboard-floatsto.html include/hook/error.h
	node tools/gen-cases.mjs floatsto

dist/fuzz_floatsto.wasm: src/floatsto/fuzz_floatsto.c src/floatsto/cases.gen.h src/floatsto/cases.gen.inc
	@mkdir -p build dist
	$(CLANG) $(WASM_FLAGS_D) -o build/fuzz_floatsto.raw.wasm $<
	$(HOOK_CLEANER) build/fuzz_floatsto.raw.wasm $@ > /dev/null
	node tools/check-wasm-memory.mjs $@ build/fuzz_floatsto.raw.wasm src/floatsto/fuzz_floatsto.c || { rm -f $@; exit 1; }
	$(GUARD_CHECK) $@ > build/fuzz_floatsto.guard.txt 2>&1 || { tail -5 build/fuzz_floatsto.guard.txt; rm -f $@; exit 1; }
	@grep -q "Hook validation successful" build/fuzz_floatsto.guard.txt || { tail -5 build/fuzz_floatsto.guard.txt; rm -f $@; exit 1; }
	@tail -2 build/fuzz_floatsto.guard.txt

floatsto: dist/fuzz_floatsto.wasm dist/dashboard-floatsto.html

# Run the release float code natively on every float case, with the
# fixFloatDivide amendment off (0) and on (1). XAHAUD_SRC must be a checkout
# of the release being tested (0f3258d), with boost, boost_thread and xxhash.
check-float: build/native_float_0 build/native_float_1
	node test/compare_float.mjs build/native_float_0 build/native_float_1

build/xfl_release.h: test/extract_float.py
	@mkdir -p build
	python3 test/extract_float.py $(XAHAUD_SRC) > $@

build/native_float_%: test/native_float.cpp build/xfl_release.h build/native_floatsto_cases.inc
	$(CXX) -std=c++20 -O1 -DNATIVE_FIX_FLOAT_DIVIDE=$* -Ibuild -I$(XAHAUD_SRC)/include -I$(XAHAUD_SRC)/src $< \
	    $(XAHAUD_SRC)/src/libxrpl/protocol/IOUAmount.cpp $(XAHAUD_SRC)/src/libxrpl/basics/Number.cpp -lboost_thread -o $@

check: build/native_check
	./build/native_check $(CASES)

build/native_check: test/native_check.cpp src/apploader/gen.h build/apploader_fault_names.inc
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -I$(XAHAUD_SRC)/include -Isrc/apploader -Ibuild $< \
	    $(XAHAUD_SRC)/src/libxrpl/protocol/AppLoader.cpp \
	    $(XAHAUD_SRC)/src/libxrpl/basics/UTF8.cpp -o $@

tools:
	@mkdir -p $(TOOLS)
	cd $(TOOLS) && [ -d hook-cleaner-c ] || git clone --depth 1 https://github.com/RichardAH/hook-cleaner-c.git
	cd $(TOOLS) && [ -d guard-checker ] || git clone --depth 1 https://github.com/RichardAH/guard-checker.git
	cd $(TOOLS)/guard-checker && (git apply --check ../guard-checker-api.patch 2>/dev/null && git apply ../guard-checker-api.patch || true)
	$(MAKE) -C $(TOOLS)/hook-cleaner-c
	$(MAKE) -C $(TOOLS)/guard-checker

clean:
	rm -rf build

.PHONY: all check check-float tools clean hookapi floatsto apploader
