# Chaos Monkey build
#
#   make            build dist/fuzz_apploader.wasm and guard-check it
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

WASM_FLAGS = --target=wasm32 -nostdlib -fno-builtin -O2 -Iinclude -Isrc/apploader \
             -Wl,--no-entry -Wl,--allow-undefined -Wl,--export=hook -Wl,--export=cbak

all: dist/fuzz_apploader.wasm

dist/fuzz_apploader.wasm: src/apploader/fuzz_apploader.c src/apploader/gen.h
	@mkdir -p build dist
	$(CLANG) $(WASM_FLAGS) -o build/fuzz_apploader.raw.wasm $<
	$(HOOK_CLEANER) build/fuzz_apploader.raw.wasm $@ > /dev/null
	$(GUARD_CHECK) $@ 2>&1 | tail -2

check: build/native_check
	./build/native_check $(CASES)

build/native_check: test/native_check.cpp src/apploader/gen.h
	@mkdir -p build
	$(CXX) -std=c++20 -O2 -I$(XAHAUD_SRC)/include -Isrc/apploader $< \
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

.PHONY: all check tools clean
