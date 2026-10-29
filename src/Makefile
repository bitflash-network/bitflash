# Bitflash Linux build — ImGui + GLFW + OpenGL3
# Called by: make linux (root Makefile)

CXX ?= g++
CC  ?= gcc
FUZZ_CXX ?= clang++

# ML-KEM-1024 (mlkem-native, vendored under mlkem/). It is C99, not C++, and the
# parameter set is fixed at compile time, so it gets its own flags and its own
# rule. Its randomness never comes from itself: btfchan feeds the _derand entry
# points from libsodium, so none of its platform RNG code is compiled in.
MLKEMFLAGS = -std=c99 -O2 -Wall -Wextra -Imlkem -DMLK_CONFIG_PARAMETER_SET=1024

SECP_INC    ?= /usr/local/include
SECP_LIB    ?= /usr/local/lib
RANDOMX_DIR ?= $(HOME)/RandomX

# macOS (Apple silicon), the same tree with Homebrew's libraries: clang, the
# keg-only openssl@3 and berkeley-db@5 by their own prefixes, and Apple's
# OpenGL framework where Linux links libGL.
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
BREW_PREFIX ?= $(shell brew --prefix 2>/dev/null)
CXX = clang++
CC  = clang
PLATFORM_INC = -I$(BREW_PREFIX)/include -I$(BREW_PREFIX)/include/nlohmann \
               -I$(BREW_PREFIX)/opt/openssl@3/include -I$(BREW_PREFIX)/opt/berkeley-db@5/include \
               -I$(BREW_PREFIX)/opt/sqlite/include
PLATFORM_LIB = -L$(BREW_PREFIX)/lib -L$(BREW_PREFIX)/opt/openssl@3/lib \
               -L$(BREW_PREFIX)/opt/berkeley-db@5/lib -L$(BREW_PREFIX)/opt/sqlite/lib
GL_LIBS = -lglfw -framework OpenGL -framework Cocoa -framework IOKit
else
PLATFORM_INC =
PLATFORM_LIB =
GL_LIBS = -lglfw -lGL
endif

IMGUI_DIR = imgui

# -w used to sit here and suppressed every diagnostic in the build, including
# the one that mattered: `%I64d` is MSVC-only, glibc mis-parses it as the GNU
# `I` flag with a width of 64 and an `int` conversion, and the resulting vararg
# desynchronisation segfaulted the node while logging a received block (issue
# #5, deterministic at height 1062 -- the first block carrying a real
# transaction). GCC had been reporting it all along:
#
#   warning: format '%d' expects argument of type 'int',
#            but argument 4 has type 'int64_t'
#
# -w cannot be narrowed: it wins over any -W or -Werror= that follows it, so it
# has to go. The four -Wno- entries below are the categories this 2009-era tree
# genuinely produces (measured: 248 deprecated-declarations, 157 write-strings,
# 18 narrowing, 1 unused-result); silencing them by name instead of silencing
# everything keeps the build quiet while leaving format errors fatal.
WARNFLAGS = -Wformat -Werror=format \
            -Wno-deprecated-declarations -Wno-write-strings \
            -Wno-narrowing -Wno-unused-result

CXXFLAGS = -std=gnu++14 -O2 $(WARNFLAGS) -fpermissive -pthread \
           -DSECP256K1_STATIC -DBITFLASH_NODE_BUILD \
           -I$(SECP_INC) -I$(RANDOMX_DIR)/src \
           -I/usr/include/nlohmann \
           -I$(IMGUI_DIR) $(PLATFORM_INC)
FUZZ_CXXFLAGS = $(filter-out -O2,$(CXXFLAGS)) -O1 -g -fno-omit-frame-pointer \
                -fsanitize=fuzzer-no-link,address,undefined
FUZZ_LDFLAGS = -fsanitize=fuzzer,address,undefined

LIBS = -L$(SECP_LIB) -lsecp256k1 \
       -L$(RANDOMX_DIR)/build -lrandomx $(PLATFORM_LIB) \
       -lsodium -lssl -lcrypto -ldb_cxx -lsqlite3 -lpthread \
       $(GL_LIBS)

# Every header a .cpp here includes has to be listed, not just the interesting
# ones. sockcount.h was missing, and it declares a struct that lives in a
# function-local static shared across translation units: editing it rebuilt
# some objects and not others, and the linker said so in a warning easy to walk
# past -- "duplicate section ... has different size". That is one object
# indexing a struct by the old layout and another by the new one, in the same
# binary. Nothing crashed here, and nothing would say so if it had.
HEADERS = headers_core.h headers.h util.h main.h serialize.h uint256.h \
          key.h bignum.h script.h db.h base58.h net.h nostr.h \
          randomx_pow.h consensus.h btfaddr.h btfchan.h btfsock.h market.h \
          selftest.h walletcmd.h wallet_sqlite.h compat.h sockcount.h \
          btfchat.h btfchatmsg.h btfchatbox.h btfchatlog.h btfchatlink.h btfchatsock.h btfchatnode.h chatstore.h chatrelay.h btfchatnet.h swap.h btfchatwallet.h rpcclient.h btcswap.h btclight.h chatswap.h btfchatswap.h bip21.h qrcodegen.hpp invoice.h community.h chatdir.h sigcheck.h \
          proxy.h tor.h treasury.h gui_chat.h font_roboto.h

IMGUI_OBJS = obj/imgui.o obj/imgui_draw.o obj/imgui_tables.o \
             obj/imgui_widgets.o obj/imgui_impl_glfw.o obj/imgui_impl_opengl3.o

# Standalone foreign-chain PoW modules are always compiled without -fpermissive.
# `override`: a CXXFLAGS given on the command line must not drop these flags
# (the build broke, or the vendored code silently built with -fpermissive).
# sphlib's portable byte loads avoid unaligned accesses under UBSan.
LIGHT_POW_SOURCES = dgb_pow.cpp \
    rvn_kawpow.cpp \
    pow_vendor/dgb/KeccakP-800-reference.cpp \
    pow_vendor/dgb/cubehash.cpp \
    pow_vendor/dgb/echo.cpp \
    pow_vendor/dgb/luffa.cpp \
    pow_vendor/dgb/odocrypt.cpp \
    pow_vendor/dgb/shavite.cpp \
    pow_vendor/dgb/simd.cpp \
    pow_vendor/dgb/skein.cpp \
    pow_vendor/rvn/crypto/ethash/lib/ethash/ethash.cpp \
    pow_vendor/rvn/crypto/ethash/lib/ethash/progpow.cpp
LIGHT_POW_C_SOURCES = pow_vendor/rvn/crypto/ethash/lib/ethash/primes.c pow_vendor/rvn/crypto/ethash/lib/keccak/keccak.c pow_vendor/rvn/crypto/ethash/lib/keccak/keccakf1600.c pow_vendor/rvn/crypto/ethash/lib/keccak/keccakf800.c
LIGHT_POW_HEADERS = dgb_pow.h rvn_kawpow.h light_pow_common.h light_pow_internal.h \
    pow_vendor/dgb/aes_helper.cpp \
    pow_vendor/dgb/KeccakP-800-SnP.h \
    pow_vendor/dgb/brg_endian.h \
    pow_vendor/dgb/odocrypt.h \
    pow_vendor/dgb/sph_cubehash.h \
    pow_vendor/dgb/sph_echo.h \
    pow_vendor/dgb/sph_luffa.h \
    pow_vendor/dgb/sph_shavite.h \
    pow_vendor/dgb/sph_simd.h \
    pow_vendor/dgb/sph_skein.h \
    pow_vendor/dgb/sph_types.h \
    pow_vendor/rvn/crypto/ethash/include/ethash/ethash.h \
    pow_vendor/rvn/crypto/ethash/include/ethash/ethash.hpp \
    pow_vendor/rvn/crypto/ethash/include/ethash/hash_types.h \
    pow_vendor/rvn/crypto/ethash/include/ethash/hash_types.hpp \
    pow_vendor/rvn/crypto/ethash/include/ethash/keccak.h \
    pow_vendor/rvn/crypto/ethash/include/ethash/keccak.hpp \
    pow_vendor/rvn/crypto/ethash/include/ethash/progpow.hpp \
    pow_vendor/rvn/crypto/ethash/include/ethash/version.h \
    pow_vendor/rvn/crypto/ethash/lib/ethash/bit_manipulation.h \
    pow_vendor/rvn/crypto/ethash/lib/ethash/builtins.h \
    pow_vendor/rvn/crypto/ethash/lib/ethash/endianness.hpp \
    pow_vendor/rvn/crypto/ethash/lib/ethash/ethash-internal.hpp \
    pow_vendor/rvn/crypto/ethash/lib/ethash/kiss99.hpp \
    pow_vendor/rvn/crypto/ethash/lib/ethash/primes.h \
    pow_vendor/rvn/crypto/ethash/lib/support/attributes.h
LIGHT_POW_OBJS = $(foreach dir,obj obj-chat obj-node obj-chatterm obj-fuzz, \
    $(patsubst %.cpp,$(dir)/%.o,$(LIGHT_POW_SOURCES)) \
    $(patsubst %.c,$(dir)/%.o,$(LIGHT_POW_C_SOURCES)))

NODE_OBJS = obj/util.o obj/script.o obj/db.o obj/net.o obj/main.o \
            obj/market.o obj/sha.o obj/nostr.o obj/randomx_pow.o \
            obj/btfaddr.o obj/btfchan.o obj/rpc.o \
            obj/selftest.o obj/bip32.o obj/walletcmd.o obj/wallet_sqlite.o \
            obj/proxy.o obj/tor.o obj/jsonrpc.o obj/treasury.o \
            obj/mlkem.o \
            obj/btfchat.o obj/btfchatmsg.o obj/btfchatbox.o obj/btfchatlog.o \
            obj/btfchatlink.o obj/btfchatsock.o obj/btfchatnode.o \
            obj/chatstore.o obj/chatrelay.o obj/btfchatnet.o obj/swap.o obj/btfchatwallet.o obj/rpcclient.o obj/btcswap.o obj/btclight.o obj/chatswap.o obj/btfchatswap.o obj/bip21.o obj/qrcodegen.o obj/invoice.o \
            obj/community.o obj/chatdir.o obj/sigcheck.o \
            $(patsubst %.cpp,obj/%.o,$(LIGHT_POW_SOURCES)) $(patsubst %.c,obj/%.o,$(LIGHT_POW_C_SOURCES))

GUI_OBJS = obj/gui.o obj/main_gui.o

all: bitflash

$(LIGHT_POW_OBJS): override CXXFLAGS := $(filter-out -fpermissive,$(CXXFLAGS)) -Ipow_vendor/rvn -DSPH_UNALIGNED=0 -fno-strict-aliasing
$(LIGHT_POW_OBJS): override FUZZ_CXXFLAGS := $(filter-out -fpermissive,$(FUZZ_CXXFLAGS)) -Ipow_vendor/rvn -DSPH_UNALIGNED=0 -fno-strict-aliasing
$(LIGHT_POW_OBJS): $(LIGHT_POW_HEADERS)
obj/selftest.o obj-chat/selftest.o obj-node/selftest.o obj-chatterm/selftest.o obj-fuzz/selftest.o: dgb_pow.h rvn_kawpow.h light_pow_common.h test_light_pow.h test_light_pow_vectors.h


# Keep upstream Keccak translation units in C, as their declarations require.
LIGHT_POW_CFLAGS = -std=c99 -O2 -Ipow_vendor/rvn -fno-strict-aliasing
obj/%.o: %.c $(LIGHT_POW_HEADERS)
	@mkdir -p $(dir $@)
	$(CC) -c $(LIGHT_POW_CFLAGS) -o $@ $<
obj-chat/%.o: %.c $(LIGHT_POW_HEADERS)
	@mkdir -p $(dir $@)
	$(CC) -c $(LIGHT_POW_CFLAGS) -o $@ $<
obj-node/%.o: %.c $(LIGHT_POW_HEADERS)
	@mkdir -p $(dir $@)
	$(CC) -c $(LIGHT_POW_CFLAGS) -o $@ $<
obj-chatterm/%.o: %.c $(LIGHT_POW_HEADERS)
	@mkdir -p $(dir $@)
	$(CC) -c $(LIGHT_POW_CFLAGS) -o $@ $<
obj-fuzz/%.o: %.c $(LIGHT_POW_HEADERS)
	@mkdir -p $(dir $@)
	$(FUZZ_CXX) -c -x c $(filter-out -std=gnu++14 -fpermissive,$(FUZZ_CXXFLAGS)) -std=c99 -Ipow_vendor/rvn -o $@ $<

obj/%.o: %.cpp $(HEADERS)
	@mkdir -p $(dir $@)
	$(CXX) -c $(CXXFLAGS) -o $@ $<

obj/sha.o: sha.cpp sha.h
	@mkdir -p $(dir $@)
	$(CXX) -c $(CXXFLAGS) -O3 -o $@ $<

obj/mlkem.o: mlkem/mlkem_native.c
	@mkdir -p $(dir $@)
	$(CC) -c $(MLKEMFLAGS) -o $@ $<

obj/imgui.o:              $(IMGUI_DIR)/imgui.cpp
	@mkdir -p $(dir $@)
	$(CXX) -c $(CXXFLAGS) -o $@ $<

obj/imgui_draw.o:         $(IMGUI_DIR)/imgui_draw.cpp
	@mkdir -p $(dir $@)
	$(CXX) -c $(CXXFLAGS) -o $@ $<

obj/imgui_tables.o:       $(IMGUI_DIR)/imgui_tables.cpp
	@mkdir -p $(dir $@)
	$(CXX) -c $(CXXFLAGS) -o $@ $<

obj/imgui_widgets.o:      $(IMGUI_DIR)/imgui_widgets.cpp
	@mkdir -p $(dir $@)
	$(CXX) -c $(CXXFLAGS) -o $@ $<

obj/imgui_impl_glfw.o:    $(IMGUI_DIR)/imgui_impl_glfw.cpp
	@mkdir -p $(dir $@)
	$(CXX) -c $(CXXFLAGS) -o $@ $<

obj/imgui_impl_opengl3.o: $(IMGUI_DIR)/imgui_impl_opengl3.cpp
	@mkdir -p $(dir $@)
	$(CXX) -c $(CXXFLAGS) -o $@ $<

bitflash: $(IMGUI_OBJS) $(NODE_OBJS) $(GUI_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)
	@echo "Built: bitflash"


# ---- btfchat ---------------------------------------------------------------
#
# See the long note in makefile.mingw: same modules, separate process, separate
# data directory (~/.bitflash-chat), separate wallet, separate onion. gui.o is
# deliberately absent.

CHATFLAGS = $(CXXFLAGS) -DBITFLASH_CHAT_APP

CHAT_OBJS = $(patsubst obj/%,obj-chat/%,$(NODE_OBJS)) \
            obj-chat/gui_chat.o obj-chat/chat_terminal.o obj-chat/main_gui.o \
            $(IMGUI_OBJS)

obj-chat/%.o: %.cpp $(HEADERS)
	@mkdir -p $(dir $@)
	$(CXX) -c $(CHATFLAGS) -o $@ $<

obj-chat/sha.o: sha.cpp sha.h
	@mkdir -p $(dir $@)
	$(CXX) -c $(CHATFLAGS) -O3 -o $@ $<

obj-chat/mlkem.o: mlkem/mlkem_native.c
	@mkdir -p $(dir $@)
	$(CC) -c $(MLKEMFLAGS) -o $@ $<

btfchat: $(CHAT_OBJS)
	$(CXX) $(CHATFLAGS) -o $@ $^ $(LIBS)
	@echo "Built: btfchat"

# btfchat with no window at all (chat_terminal.cpp): no ImGui, GLFW or
# OpenGL, so it starts where there is no screen -- a server over ssh, or the
# macOS package, which is terminal only by design.
CHATTERM_OBJS = $(patsubst obj/%,obj-chatterm/%,$(NODE_OBJS)) \
                obj-chatterm/chat_terminal.o obj-chatterm/main_gui.o obj-chatterm/headless.o

obj-chatterm/%.o: %.cpp $(HEADERS)
	@mkdir -p $(dir $@)
	$(CXX) -c $(CHATFLAGS) -DBITFLASH_NO_GUI -o $@ $<

obj-chatterm/sha.o: sha.cpp sha.h
	@mkdir -p $(dir $@)
	$(CXX) -c $(CHATFLAGS) -DBITFLASH_NO_GUI -O3 -o $@ $<

obj-chatterm/mlkem.o: mlkem/mlkem_native.c
	@mkdir -p $(dir $@)
	$(CC) -c $(MLKEMFLAGS) -o $@ $<

btfchat-terminal: $(CHATTERM_OBJS)
	$(CXX) $(CHATFLAGS) -DBITFLASH_NO_GUI -o $@ $^ $(NODE_LIBS)
	@echo "Built: btfchat-terminal (no window, no libGL needed)"

# ---- headless node ---------------------------------------------------------
#
# Same node, built without ImGui, GLFW or OpenGL. Linking the GUI made the
# binary require libGL at load time even when started with -nogui, because the
# dynamic loader resolves everything before main() runs -- so on a clean server,
# which is where a node most naturally lives, it failed to start with an error
# about shared libraries and no hint that it would otherwise work.
#
# Objects go to obj-node/ because main_gui.cpp is compiled twice, with and
# without -DBITFLASH_NO_GUI, and the two must not overwrite each other.

NODE_LIBS = -L$(SECP_LIB) -lsecp256k1 \
            -L$(RANDOMX_DIR)/build -lrandomx $(PLATFORM_LIB) \
            -lsodium -lssl -lcrypto -ldb_cxx -lsqlite3 -lpthread

NODE_ONLY_OBJS = $(patsubst obj/%,obj-node/%,$(NODE_OBJS)) \
                 obj-node/main_gui.o obj-node/headless.o

FUZZ_BASE_OBJS = $(patsubst obj/%,obj-fuzz/%,$(NODE_OBJS))
FUZZ_NET_MESSAGE_OBJS = $(FUZZ_BASE_OBJS) obj-fuzz/fuzz_net_message.o
FUZZ_SCRIPT_OBJS = $(FUZZ_BASE_OBJS) obj-fuzz/fuzz_script.o

obj-node/%.o: %.cpp $(HEADERS)
	@mkdir -p $(dir $@)
	$(CXX) -c $(CXXFLAGS) -DBITFLASH_NO_GUI -o $@ $<

obj-node/sha.o: sha.cpp sha.h
	@mkdir -p $(dir $@)
	$(CXX) -c $(CXXFLAGS) -DBITFLASH_NO_GUI -O3 -o $@ $<

# ML-KEM is C, not C++, so the obj-node/%.o rule above cannot build it. It
# needs its own line in every object directory -- obj-node and obj-fuzz were
# missing it, so the headless node had never been built with the chat in it.
obj-node/mlkem.o: mlkem/mlkem_native.c
	@mkdir -p $(dir $@)
	$(CC) -c $(MLKEMFLAGS) -o $@ $<

obj-fuzz/mlkem.o: mlkem/mlkem_native.c
	@mkdir -p $(dir $@)
	$(CC) -c $(MLKEMFLAGS) -o $@ $<

bitflash-node: $(NODE_ONLY_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(NODE_LIBS)
	@echo "Built: bitflash-node (headless, no libGL needed)"

obj-fuzz/%.o: %.cpp $(HEADERS)
	@mkdir -p $(dir $@)
	$(FUZZ_CXX) -c $(FUZZ_CXXFLAGS) -DBITFLASH_FUZZ -o $@ $<

obj-fuzz/sha.o: sha.cpp sha.h
	@mkdir -p $(dir $@)
	$(FUZZ_CXX) -c $(FUZZ_CXXFLAGS) -DBITFLASH_FUZZ -O1 -o $@ $<

obj-fuzz/fuzz_net_message.o: fuzz_net_message.cpp $(HEADERS)
	@mkdir -p $(dir $@)
	$(FUZZ_CXX) -c $(FUZZ_CXXFLAGS) -DBITFLASH_FUZZ -o $@ $<

obj-fuzz/fuzz_script.o: fuzz_script.cpp $(HEADERS)
	@mkdir -p $(dir $@)
	$(FUZZ_CXX) -c $(FUZZ_CXXFLAGS) -DBITFLASH_FUZZ -o $@ $<

fuzz-net-message: $(FUZZ_NET_MESSAGE_OBJS)
	$(FUZZ_CXX) $(filter-out -fsanitize=fuzzer-no-link%,$(FUZZ_CXXFLAGS)) \
	  $(FUZZ_LDFLAGS) -o $@ $^ $(NODE_LIBS)
	@echo "Built: fuzz-net-message"

fuzz-script: $(FUZZ_SCRIPT_OBJS)
	$(FUZZ_CXX) $(filter-out -fsanitize=fuzzer-no-link%,$(FUZZ_CXXFLAGS)) \
	  $(FUZZ_LDFLAGS) -o $@ $^ $(NODE_LIBS)
	@echo "Built: fuzz-script"

obj-fuzz/fuzz_sigcheck.o: fuzz_sigcheck.cpp $(HEADERS)
	@mkdir -p $(dir $@)
	$(FUZZ_CXX) -c $(FUZZ_CXXFLAGS) -DBITFLASH_FUZZ -o $@ $<

fuzz-sigcheck: $(FUZZ_BASE_OBJS) obj-fuzz/fuzz_sigcheck.o
	$(FUZZ_CXX) $(filter-out -fsanitize=fuzzer-no-link%,$(FUZZ_CXXFLAGS)) \
	  $(FUZZ_LDFLAGS) -o $@ $^ $(NODE_LIBS)
	@echo "Built: fuzz-sigcheck"

# OpenSSL and libsecp256k1 on the same mutated signatures; a disagreement aborts.
fuzz-sigcheck-smoke: fuzz-sigcheck
	@mkdir -p ../work/fuzz-corpus/sigcheck
	@printf '\000\000\001\001' > ../work/fuzz-corpus/sigcheck/flip-sig
	@printf '\030\001\040\001' > ../work/fuzz-corpus/sigcheck/flip-key
	./fuzz-sigcheck -runs=20000 ../work/fuzz-corpus/sigcheck

fuzz-net-message-smoke: fuzz-net-message
	@mkdir -p ../work/fuzz-corpus/net-message
	@printf '\277\040\134\375ping\000\000\000\000\000\000\000\000\000\000\000\000' > ../work/fuzz-corpus/net-message/ping-header
	@printf '\277\040\134\375version\000\000\000\000\000\000\000\000\000' > ../work/fuzz-corpus/net-message/version-header
	./fuzz-net-message -runs=128 ../work/fuzz-corpus/net-message

fuzz-script-smoke: fuzz-script
	@mkdir -p ../work/fuzz-corpus/script
	@printf '\000\121' > ../work/fuzz-corpus/script/op-true
	@printf '\001\166\251\024\001\002\003\004\005\006\007\010\011\012\013\014\015\016\017\020\021\022\023\024\210\254' > ../work/fuzz-corpus/script/p2pkh-shape
	@printf '\000\115\377\377' > ../work/fuzz-corpus/script/truncated-pushdata2
	./fuzz-script -runs=128 ../work/fuzz-corpus/script

clean:
	rm -rf obj obj-node obj-fuzz test_light_pow test-light-pow-sanitize fuzz-light-pow bitflash bitflash-node fuzz-net-message fuzz-script fuzz-sigcheck test_bip32 test_btfaddr test_btfchan

test_bip32: test_bip32.cpp bip32.cpp bip32.h bip39_english.h
	$(CXX) $(CXXFLAGS) -o $@ test_bip32.cpp bip32.cpp $(PLATFORM_LIB) -lssl -lcrypto

# The .btf address tests existed as a file you had to compile by hand, which is
# the same as not having them: they did not run here and they did not run in CI.
test_btfaddr: test_btfaddr.cpp btfaddr.cpp btfaddr.h
	$(CXX) $(CXXFLAGS) -o $@ test_btfaddr.cpp btfaddr.cpp $(LIBS)

# The encrypted channel every .btf connection runs through. Same story as the
# address tests: the file was here, nothing ran it.
test_btfchan: test_btfchan.cpp btfchan.cpp btfchan.h obj/mlkem.o
	$(CXX) $(CXXFLAGS) -o $@ test_btfchan.cpp btfchan.cpp obj/mlkem.o $(PLATFORM_LIB) -lsodium

# See the note in makefile.mingw: bip32 for the phrase, btfaddr for the address,
# no ML-KEM object.
test_btfchat: test_btfchat.cpp btfchat.cpp btfchat.h bip32.cpp btfaddr.cpp
	$(CXX) $(CXXFLAGS) -o $@ test_btfchat.cpp btfchat.cpp bip32.cpp btfaddr.cpp $(LIBS)

# The frame layer: signing, the group admin proof, the replay guard.
test_btfchatmsg: test_btfchatmsg.cpp btfchatmsg.cpp chatswap.cpp btfchatmsg.h btfchat.cpp btfchat.h bip32.cpp btfaddr.cpp
	$(CXX) $(CXXFLAGS) -o $@ test_btfchatmsg.cpp btfchatmsg.cpp chatswap.cpp btfchat.cpp bip32.cpp btfaddr.cpp $(LIBS)

# See the note in makefile.mingw.
test_btfchatbox: test_btfchatbox.cpp btfchatbox.cpp btfchatbox.h btfchatmsg.cpp chatswap.cpp btfchat.cpp btfchan.cpp obj/mlkem.o bip32.cpp btfaddr.cpp
	$(CXX) $(CXXFLAGS) -o $@ test_btfchatbox.cpp btfchatbox.cpp btfchatmsg.cpp chatswap.cpp btfchat.cpp btfchan.cpp obj/mlkem.o bip32.cpp btfaddr.cpp $(LIBS)

# The sealed history.
test_btfchatlog: test_btfchatlog.cpp btfchatlog.cpp btfchatlog.h btfchatmsg.cpp chatswap.cpp btfchat.cpp bip32.cpp btfaddr.cpp
	$(CXX) $(CXXFLAGS) -o $@ test_btfchatlog.cpp btfchatlog.cpp btfchatmsg.cpp chatswap.cpp btfchat.cpp bip32.cpp btfaddr.cpp $(LIBS)

# See the note in makefile.mingw.
test_btfchatlink: test_btfchatlink.cpp btfchatlink.cpp btfchatlink.h btfchatlog.cpp btfchatmsg.cpp chatswap.cpp btfchat.cpp btfchan.cpp obj/mlkem.o bip32.cpp btfaddr.cpp
	$(CXX) $(CXXFLAGS) -o $@ test_btfchatlink.cpp btfchatlink.cpp btfchatlog.cpp btfchatmsg.cpp chatswap.cpp btfchat.cpp btfchan.cpp obj/mlkem.o bip32.cpp btfaddr.cpp $(LIBS)

# See the note in makefile.mingw.
test_chatstore: test_chatstore.cpp chatstore.cpp chatstore.h btfchatbox.cpp btfchatmsg.cpp chatswap.cpp btfchat.cpp btfchan.cpp obj/mlkem.o bip32.cpp btfaddr.cpp
	$(CXX) $(CXXFLAGS) -o $@ test_chatstore.cpp chatstore.cpp btfchatbox.cpp btfchatmsg.cpp chatswap.cpp btfchat.cpp btfchan.cpp obj/mlkem.o bip32.cpp btfaddr.cpp $(LIBS)

# See the note in makefile.mingw.
test_community: test_community.cpp community.cpp community.h
	$(CXX) $(CXXFLAGS) -o $@ test_community.cpp community.cpp $(PLATFORM_LIB) -lsodium

test_chatswap: test_chatswap.cpp chatswap.cpp chatswap.h
	$(CXX) $(CXXFLAGS) -o $@ test_chatswap.cpp chatswap.cpp

test_bip21: test_bip21.cpp bip21.cpp bip21.h qrcodegen.cpp qrcodegen.hpp
	$(CXX) $(CXXFLAGS) -o $@ test_bip21.cpp bip21.cpp qrcodegen.cpp

# Standalone proof verification avoids unrelated wallet dependencies on native
# and sanitizer hosts. The fixtures/assertions are shared with RunSelfTest.
LIGHT_POW_TEST_OBJS = $(patsubst %.cpp,obj/%.o,$(LIGHT_POW_SOURCES)) $(patsubst %.c,obj/%.o,$(LIGHT_POW_C_SOURCES))
LIGHT_POW_SAN_OBJS = $(patsubst obj/%,obj-fuzz/%,$(LIGHT_POW_TEST_OBJS))
obj/test_light_pow.o: test_light_pow.cpp test_light_pow.h test_light_pow_vectors.h $(LIGHT_POW_HEADERS)
	@mkdir -p $(dir $@)
	$(CXX) -c $(filter-out -fpermissive,$(CXXFLAGS)) -o $@ $<
test_light_pow: obj/test_light_pow.o $(LIGHT_POW_TEST_OBJS)
	$(CXX) $(filter-out -fpermissive,$(CXXFLAGS)) -o $@ $^ $(PLATFORM_LIB) -lcrypto
obj-fuzz/test_light_pow.o obj-fuzz/fuzz_light_pow.o: FUZZ_CXXFLAGS := $(filter-out -fpermissive,$(FUZZ_CXXFLAGS))
obj-fuzz/test_light_pow.o: test_light_pow.cpp test_light_pow.h test_light_pow_vectors.h $(LIGHT_POW_HEADERS)
obj-fuzz/fuzz_light_pow.o: fuzz_light_pow.cpp $(LIGHT_POW_HEADERS)
test-light-pow-sanitize: obj-fuzz/test_light_pow.o $(LIGHT_POW_SAN_OBJS)
	$(FUZZ_CXX) $(filter-out -fpermissive,$(FUZZ_CXXFLAGS)) -o $@ $^ $(PLATFORM_LIB) -lcrypto
fuzz-light-pow: obj-fuzz/fuzz_light_pow.o $(LIGHT_POW_SAN_OBJS)
	$(FUZZ_CXX) $(filter-out -fpermissive -fsanitize=fuzzer-no-link%,$(FUZZ_CXXFLAGS)) $(FUZZ_LDFLAGS) -o $@ $^ $(PLATFORM_LIB) -lcrypto


tests: btfchat test_bip32 test_btfchan test_btfaddr test_btfchat test_btfchatmsg test_btfchatbox test_btfchatlog test_btfchatlink test_chatstore test_community test_chatswap test_bip21 bitflash-node
	./test_bip32
	./test_btfchan
	./test_btfaddr
	./test_btfchat
	./test_btfchatmsg
	./test_btfchatbox
	./test_btfchatlog
	./test_btfchatlink
	./test_chatstore
	./test_community
	./test_chatswap
	./test_bip21
	./bitflash-node -selftest=wallet-keypool
	./bitflash-node -selftest=wallet-hd
	./bitflash-node -selftest=wallet-format
	./bitflash-node -selftest=wallet-sqlite
	./bitflash-node -selftest=wallet-sqlite-migration
	./bitflash-node -selftest=wallet-crypto
	./bitflash-node -selftest=wallet-encrypt
	./bitflash-node -selftest=net-message
	./bitflash-node -selftest=network-params
	./bitflash-node -selftest=consensus-limits
	./bitflash-node -selftest=pool-stratum
	./bitflash-node -selftest=parse-money
	./bitflash-node -selftest=debug-log-buffer
	./bitflash-node -selftest=pow-v2
	./bitflash-node -selftest=dgb-pow
	./bitflash-node -selftest=rvn-kawpow
	./bitflash-node -selftest=sigpipe
	./bitflash-node -selftest=script-eval
	./bitflash-node -selftest=rules-v2
	./bitflash-node -selftest=rules-v3
	./bitflash-node -selftest=rules-v4
	./bitflash-node -selftest=sigcheck
	./bitflash-node -selftest=btc-swap
	./bitflash-node -selftest=btc-light
	./bitflash-node -selftest=swap-wait-payment
	./bitflash-node -selftest=fee-policy
	./bitflash-node -selftest=invoice
	./bitflash-node -selftest=net-hardening
	./bitflash-node -selftest=multisig
	./bitflash-node -selftest=socks5-proxy
	./bitflash-node -selftest=managed-tor
	./bitflash-node -selftest=treasury
	./bitflash-node -selftest=chat-link
	./bitflash-node -selftest=chat-identity
	./bitflash-node -selftest=chat-relay
	./bitflash-node -selftest=chat-wallet

.PHONY: tests fuzz-net-message-smoke fuzz-script-smoke fuzz-sigcheck-smoke
