CC     ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=c11 -D_GNU_SOURCE
LDLIBS := -lsodium

# --- vendored pakechat (CPace / Nostr / WebSocket) -------------------------
PAKE_DIR := third_party/pakechat
PAKE_MODS := cpace chat_crypto padding chat_session envelope ws_frame ws_handshake ws_client nostr_event
POBJ := $(addprefix .pobj/,$(addsuffix .o,$(PAKE_MODS)))
# pakechat sources self-#define _GNU_SOURCE, so compile them WITHOUT it.
PAKE_CFLAGS := -std=c11 -O2 -I$(PAKE_DIR) $(shell pkg-config --cflags libcjson 2>/dev/null)
PAKE_LIBS   := -lcjson -lsecp256k1 -lssl -lcrypto -lpthread

CORE := src/keys.c src/stun.c src/candidate.c src/net.c src/punch.c src/transport.c src/app.c
OBJ  := $(CORE:.c=.o)
TESTBIN := test_candidate test_punch test_transport test_app test_voice

OPUS_CFLAGS := $(shell pkg-config --cflags opus 2>/dev/null)
OPUS_LIBS   := $(shell pkg-config --libs opus 2>/dev/null)
PW_CFLAGS   := $(shell pkg-config --cflags libpipewire-0.3 2>/dev/null)
PW_LIBS     := $(shell pkg-config --libs libpipewire-0.3 2>/dev/null)

# Default: just the chat/file binary (no audio device needed).
# Unit tests are built on demand via `make test`.
all: telegloomy

# --- unit tests (libsodium only) ------------------------------------------
test_candidate: tests/test_candidate.c $(OBJ)
	$(CC) $(CFLAGS) -Isrc -o $@ $^ $(LDLIBS)
test_punch: tests/test_punch.c $(OBJ)
	$(CC) $(CFLAGS) -Isrc -o $@ $^ $(LDLIBS) -lpthread
test_transport: tests/test_transport.c $(OBJ)
	$(CC) $(CFLAGS) -Isrc -o $@ $^ $(LDLIBS) -lpthread
test_app: tests/test_app.c $(OBJ)
	$(CC) $(CFLAGS) -Isrc -o $@ $^ $(LDLIBS) -lpthread
test_voice: tests/test_voice.c src/voice.c $(OBJ)
	$(CC) $(CFLAGS) -Isrc -o $@ $^ $(LDLIBS) $(OPUS_CFLAGS) $(OPUS_LIBS) -lm -lpthread

test: $(TESTBIN)
	@for t in $(TESTBIN); do echo "--- $$t ---"; ./$$t || exit 1; done

# --- vendored pakechat objects (their own flags) --------------------------
.pobj/%.o: $(PAKE_DIR)/%.c
	@mkdir -p .pobj
	$(CC) $(PAKE_CFLAGS) -c -o $@ $<

# --- end-to-end binaries (self-contained; no PAKE= needed) ----------------
telegloomy: src/main.c src/signaling.c $(CORE) $(POBJ)
	$(CC) $(CFLAGS) -Isrc -I$(PAKE_DIR) -o $@ $^ $(LDLIBS) $(PAKE_LIBS)

# Separate binary, so `make` after `make telegloomy-voice` doesn't leave the
# voice build sitting where the plain one is expected.
telegloomy-voice: src/main.c src/signaling.c src/voice.c src/audio_pipewire.c $(CORE) $(POBJ)
	$(CC) $(CFLAGS) -DWITH_VOICE -Isrc -I$(PAKE_DIR) $(OPUS_CFLAGS) $(PW_CFLAGS) \
	   -o $@ $^ $(LDLIBS) $(PAKE_LIBS) $(OPUS_LIBS) $(PW_LIBS) -lm

%.o: %.c
	$(CC) $(CFLAGS) -Isrc -c -o $@ $<

clean:
	rm -f $(OBJ) $(TESTBIN) telegloomy telegloomy-voice fuzz/fuzzer
	rm -rf .pobj

.PHONY: all test clean fuzz asan tsan
# ---- security tooling ---------------------------------------------------
SAN_CORE  := src/keys.c src/stun.c src/candidate.c src/net.c src/punch.c src/transport.c
PAKE_CSRC := $(addprefix $(PAKE_DIR)/,$(addsuffix .c,$(PAKE_MODS)))
FUZZ_FLAGS := -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all -D_GNU_SOURCE

# Mutation-fuzz every attacker-facing parser under ASAN+UBSAN.
fuzz:
	gcc $(FUZZ_FLAGS) -Isrc -I$(PAKE_DIR) $(shell pkg-config --cflags libcjson) \
	  fuzz/fuzz.c $(SAN_CORE) $(PAKE_CSRC) -o fuzz/fuzzer \
	  -lsodium -lcjson -lsecp256k1 -lssl -lcrypto -lpthread
	ASAN_OPTIONS=detect_leaks=0 ./fuzz/fuzzer $(if $(N),$(N),500000)

# Unit tests under AddressSanitizer + UBSan.
asan:
	gcc $(FUZZ_FLAGS) -Isrc tests/test_app.c src/app.c $(SAN_CORE) -lsodium -lpthread -o /tmp/asan_app
	ASAN_OPTIONS=detect_leaks=0 /tmp/asan_app

# Concurrency check under ThreadSanitizer.
tsan:
	gcc -fsanitize=thread -g -D_GNU_SOURCE -Isrc tests/test_race.c $(SAN_CORE) src/voice.c \
	  -lsodium -lpthread $(shell pkg-config --cflags --libs opus) -lm -o /tmp/tsan_race
	/tmp/tsan_race

