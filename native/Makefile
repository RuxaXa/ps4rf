# PS4RF native build (P4/W2). Reproducible-by-default flags: no build id, no
# absolute source paths, no __DATE__/__TIME__ in the code. See README.md.
#
# Targets:
#   make             -> build/ps4rfd.elf (ET_DYN), build/ps4rfd.bin, build/ps4rf_parity
#   make check       -> run the offline parity harness against the golden catalogs
#   make self-test   -> run the agent skeleton against the in-process host stub
#   make repro       -> rebuild in two sub-trees and compare hashes (reproducibility proof)
#   make manifest    -> write build/toolchain-manifest.json from the real build
#   make clean

CC      ?= gcc
BUILD   := build
CORE_SRC := src/sha256.c src/chacha20poly1305.c src/jcs.c src/ps4rf_protocol.c

CFLAGS   := -std=c99 -O2 -Wall -Wextra -Werror -fPIC \
            -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L \
            -ffile-prefix-map=$(CURDIR)=. -fdebug-prefix-map=$(CURDIR)=.
LDFLAGS  := -pie -Wl,--build-id=none -Wl,-z,relro -Wl,-z,now
LDLIBS   := -lpthread

AGENT_SRC := src/ps4rfd_main.c
HARNESS_SRC := src/parity_harness.c

.PHONY: all check self-test repro manifest clean
all: $(BUILD)/ps4rfd.elf $(BUILD)/ps4rfd.bin $(BUILD)/ps4rf_parity

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/ps4rfd.elf: $(CORE_SRC) $(AGENT_SRC) src/ps4rf_protocol.h | $(BUILD)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(CORE_SRC) $(AGENT_SRC) $(LDLIBS)

$(BUILD)/ps4rfd.bin: $(BUILD)/ps4rfd.elf
	objcopy -O binary $< $@

$(BUILD)/ps4rf_parity: $(CORE_SRC) $(HARNESS_SRC) src/ps4rf_protocol.h | $(BUILD)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(CORE_SRC) $(HARNESS_SRC) $(LDLIBS)

check: $(BUILD)/ps4rf_parity
	./$(BUILD)/ps4rf_parity ../tests/fixtures/crypto/vectors-v1.json \
	                        ../tests/fixtures/parity/vectors-v1.json \
	                        ../tests/fixtures/parity/w2-negative-v1.json

self-test: $(BUILD)/ps4rfd.elf
	./$(BUILD)/ps4rfd.elf --self-test-loopback

repro: 
	$(MAKE) all BUILD=$(BUILD)/repro-a
	$(MAKE) all BUILD=$(BUILD)/repro-b
	@sha256sum $(BUILD)/repro-a/ps4rfd.elf $(BUILD)/repro-b/ps4rfd.elf \
	           $(BUILD)/repro-a/ps4rfd.bin $(BUILD)/repro-b/ps4rfd.bin \
	           $(BUILD)/repro-a/ps4rf_parity $(BUILD)/repro-b/ps4rf_parity \
	  | sed 's#$(BUILD)/repro-[ab]/##' | sort
	@cmp $(BUILD)/repro-a/ps4rfd.elf $(BUILD)/repro-b/ps4rfd.elf \
	  && cmp $(BUILD)/repro-a/ps4rfd.bin $(BUILD)/repro-b/ps4rfd.bin \
	  && cmp $(BUILD)/repro-a/ps4rf_parity $(BUILD)/repro-b/ps4rf_parity \
	  && echo "REPRO: byte-identical (agent ELF, agent BIN, harness)" \
	  || (echo "REPRO: MISMATCH" && exit 1)

manifest: $(BUILD)/ps4rfd.elf $(BUILD)/ps4rfd.bin $(BUILD)/ps4rf_parity
	python3 build_manifest.py

clean:
	rm -rf $(BUILD)
