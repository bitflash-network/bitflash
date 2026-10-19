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
           -I$(IMGUI_DIR)
FUZZ_CXXFLAGS = $(filter-out -O2,$(CXXFLAGS)) -O1 -g -fno-omit-frame-pointer \
                -fsanitize=fuzzer-no-link,address,undefined
FUZZ_LDFLAGS = -fsanitize=fuzzer,address,undefined

LIBS = -L$(SECP_LIB) -lsecp256k1 \
       -L$(RANDOMX_DIR)/build -lrandomx \
       -lsodium -lssl -lcrypto -ldb_cxx -lsqlite3 -lpthread \
       -lglfw -lGL

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
          btfchat.h btfchatmsg.h btfchatbox.h btfchatlog.h btfchatlink.h btfchatsock.h btfchatnode.h chatstore.h chatrelay.h btfchatnet.h swap.h btfchatwallet.h \
          proxy.h tor.h treasury.h gui_chat.h font_roboto.h

IMGUI_OBJS = obj/imgui.o obj/imgui_draw.o obj/imgui_tables.o \
             obj/imgui_widgets.o obj/imgui_impl_glfw.o obj/imgui_impl_opengl3.o

NODE_OBJS = obj/util.o obj/script.o obj/db.o obj/net.o obj/main.o \
            obj/market.o obj/sha.o obj/nostr.o obj/randomx_pow.o \
            obj/btfaddr.o obj/btfchan.o obj/rpc.o \
            obj/selftest.o obj/bip32.o obj/walletcmd.o obj/wallet_sqlite.o \
            obj/proxy.o obj/tor.o obj/jsonrpc.o obj/treasury.o \
            obj/mlkem.o \
            obj/btfchat.o obj/btfchatmsg.o obj/btfchatbox.o obj/btfchatlog.o \
            obj/btfchatlink.o obj/btfchatsock.o obj/btfchatnode.o \
            obj/chatstore.o obj/chatrelay.o obj/btfchatnet.o obj/swap.o obj/btfchatwallet.o

GUI_OBJS = obj/gui.o obj/main_gui.o

all: bitflash

obj/%.o: %.cpp $(HEADERS)
	@mkdir -p obj
	$(CXX) -c $(CXXFLAGS) -o $@ $<

obj/sha.o: sha.cpp sha.h
	@mkdir -p obj
	$(CXX) -c $(CXXFLAGS) -O3 -o $@ $<

obj/mlkem.o: mlkem/mlkem_native.c
	@mkdir -p obj
	$(CC) -c $(MLKEMFLAGS) -o $@ $<

obj/imgui.o:              $(IMGUI_DIR)/imgui.cpp
	@mkdir -p obj
	$(CXX) -c $(CXXFLAGS) -o $@ $<

obj/imgui_draw.o:         $(IMGUI_DIR)/imgui_draw.cpp
	@mkdir -p obj
	$(CXX) -c $(CXXFLAGS) -o $@ $<

obj/imgui_tables.o:       $(IMGUI_DIR)/imgui_tables.cpp
	@mkdir -p obj
	$(CXX) -c $(CXXFLAGS) -o $@ $<

obj/imgui_widgets.o:      $(IMGUI_DIR)/imgui_widgets.cpp
	@mkdir -p obj
	$(CXX) -c $(CXXFLAGS) -o $@ $<

obj/imgui_impl_glfw.o:    $(IMGUI_DIR)/imgui_impl_glfw.cpp
	@mkdir -p obj
	$(CXX) -c $(CXXFLAGS) -o $@ $<

obj/imgui_impl_opengl3.o: $(IMGUI_DIR)/imgui_impl_opengl3.cpp
	@mkdir -p obj
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
            obj-chat/gui_chat.o obj-chat/main_gui.o \
            $(IMGUI_OBJS)

obj-chat/%.o: %.cpp $(HEADERS)
	@mkdir -p obj-chat
	$(CXX) -c $(CHATFLAGS) -o $@ $<

obj-chat/sha.o: sha.cpp sha.h
	@mkdir -p obj-chat
	$(CXX) -c $(CHATFLAGS) -O3 -o $@ $<

obj-chat/mlkem.o: mlkem/mlkem_native.c
	@mkdir -p obj-chat
	$(CC) -c $(MLKEMFLAGS) -o $@ $<

btfchat: $(CHAT_OBJS)
	$(CXX) $(CHATFLAGS) -o $@ $^ $(LIBS)
	@echo "Built: btfchat"

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
            -L$(RANDOMX_DIR)/build -lrandomx \
            -lsodium -lssl -lcrypto -ldb_cxx -lsqlite3 -lpthread

NODE_ONLY_OBJS = $(patsubst obj/%,obj-node/%,$(NODE_OBJS)) \
                 obj-node/main_gui.o obj-node/headless.o

FUZZ_BASE_OBJS = $(patsubst obj/%,obj-fuzz/%,$(NODE_OBJS))
FUZZ_NET_MESSAGE_OBJS = $(FUZZ_BASE_OBJS) obj-fuzz/fuzz_net_message.o
FUZZ_SCRIPT_OBJS = $(FUZZ_BASE_OBJS) obj-fuzz/fuzz_script.o

obj-node/%.o: %.cpp $(HEADERS)
	@mkdir -p obj-node
	$(CXX) -c $(CXXFLAGS) -DBITFLASH_NO_GUI -o $@ $<

obj-node/sha.o: sha.cpp sha.h
	@mkdir -p obj-node
	$(CXX) -c $(CXXFLAGS) -DBITFLASH_NO_GUI -O3 -o $@ $<

# ML-KEM is C, not C++, so the obj-node/%.o rule above cannot build it. It
# needs its own line in every object directory -- obj-node and obj-fuzz were
# missing it, so the headless node had never been built with the chat in it.
obj-node/mlkem.o: mlkem/mlkem_native.c
	@mkdir -p obj-node
	$(CC) -c $(MLKEMFLAGS) -o $@ $<

obj-fuzz/mlkem.o: mlkem/mlkem_native.c
	@mkdir -p obj-fuzz
	$(CC) -c $(MLKEMFLAGS) -o $@ $<

bitflash-node: $(NODE_ONLY_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(NODE_LIBS)
	@echo "Built: bitflash-node (headless, no libGL needed)"

obj-fuzz/%.o: %.cpp $(HEADERS)
	@mkdir -p obj-fuzz
	$(FUZZ_CXX) -c $(FUZZ_CXXFLAGS) -DBITFLASH_FUZZ -o $@ $<

obj-fuzz/sha.o: sha.cpp sha.h
	@mkdir -p obj-fuzz
	$(FUZZ_CXX) -c $(FUZZ_CXXFLAGS) -DBITFLASH_FUZZ -O1 -o $@ $<

obj-fuzz/fuzz_net_message.o: fuzz_net_message.cpp $(HEADERS)
	@mkdir -p obj-fuzz
	$(FUZZ_CXX) -c $(FUZZ_CXXFLAGS) -DBITFLASH_FUZZ -o $@ $<

obj-fuzz/fuzz_script.o: fuzz_script.cpp $(HEADERS)
	@mkdir -p obj-fuzz
	$(FUZZ_CXX) -c $(FUZZ_CXXFLAGS) -DBITFLASH_FUZZ -o $@ $<

fuzz-net-message: $(FUZZ_NET_MESSAGE_OBJS)
	$(FUZZ_CXX) $(filter-out -fsanitize=fuzzer-no-link%,$(FUZZ_CXXFLAGS)) \
	  $(FUZZ_LDFLAGS) -o $@ $^ $(NODE_LIBS)
	@echo "Built: fuzz-net-message"

fuzz-script: $(FUZZ_SCRIPT_OBJS)
	$(FUZZ_CXX) $(filter-out -fsanitize=fuzzer-no-link%,$(FUZZ_CXXFLAGS)) \
	  $(FUZZ_LDFLAGS) -o $@ $^ $(NODE_LIBS)
	@echo "Built: fuzz-script"

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
	rm -rf obj obj-node obj-fuzz bitflash bitflash-node fuzz-net-message fuzz-script test_bip32 test_btfaddr test_btfchan

test_bip32: test_bip32.cpp bip32.cpp bip32.h bip39_english.h
	$(CXX) $(CXXFLAGS) -o $@ test_bip32.cpp bip32.cpp -lssl -lcrypto

# The .btf address tests existed as a file you had to compile by hand, which is
# the same as not having them: they did not run here and they did not run in CI.
test_btfaddr: test_btfaddr.cpp btfaddr.cpp btfaddr.h
	$(CXX) $(CXXFLAGS) -o $@ test_btfaddr.cpp btfaddr.cpp $(LIBS)

# The encrypted channel every .btf connection runs through. Same story as the
# address tests: the file was here, nothing ran it.
test_btfchan: test_btfchan.cpp btfchan.cpp btfchan.h obj/mlkem.o
	$(CXX) $(CXXFLAGS) -o $@ test_btfchan.cpp btfchan.cpp obj/mlkem.o -lsodium

# See the note in makefile.mingw: bip32 for the phrase, btfaddr for the address,
# no ML-KEM object.
test_btfchat: test_btfchat.cpp btfchat.cpp btfchat.h bip32.cpp btfaddr.cpp
	$(CXX) $(CXXFLAGS) -o $@ test_btfchat.cpp btfchat.cpp bip32.cpp btfaddr.cpp $(LIBS)

# The frame layer: signing, the group admin proof, the replay guard.
test_btfchatmsg: test_btfchatmsg.cpp btfchatmsg.cpp btfchatmsg.h btfchat.cpp btfchat.h bip32.cpp btfaddr.cpp
	$(CXX) $(CXXFLAGS) -o $@ test_btfchatmsg.cpp btfchatmsg.cpp btfchat.cpp bip32.cpp btfaddr.cpp $(LIBS)

# See the note in makefile.mingw.
test_btfchatbox: test_btfchatbox.cpp btfchatbox.cpp btfchatbox.h btfchatmsg.cpp btfchat.cpp btfchan.cpp obj/mlkem.o bip32.cpp btfaddr.cpp
	$(CXX) $(CXXFLAGS) -o $@ test_btfchatbox.cpp btfchatbox.cpp btfchatmsg.cpp btfchat.cpp btfchan.cpp obj/mlkem.o bip32.cpp btfaddr.cpp $(LIBS)

# The sealed history.
test_btfchatlog: test_btfchatlog.cpp btfchatlog.cpp btfchatlog.h btfchatmsg.cpp btfchat.cpp bip32.cpp btfaddr.cpp
	$(CXX) $(CXXFLAGS) -o $@ test_btfchatlog.cpp btfchatlog.cpp btfchatmsg.cpp btfchat.cpp bip32.cpp btfaddr.cpp $(LIBS)

# See the note in makefile.mingw.
test_btfchatlink: test_btfchatlink.cpp btfchatlink.cpp btfchatlink.h btfchatlog.cpp btfchatmsg.cpp btfchat.cpp btfchan.cpp obj/mlkem.o bip32.cpp btfaddr.cpp
	$(CXX) $(CXXFLAGS) -o $@ test_btfchatlink.cpp btfchatlink.cpp btfchatlog.cpp btfchatmsg.cpp btfchat.cpp btfchan.cpp obj/mlkem.o bip32.cpp btfaddr.cpp $(LIBS)

# See the note in makefile.mingw.
test_chatstore: test_chatstore.cpp chatstore.cpp chatstore.h btfchatbox.cpp btfchatmsg.cpp btfchat.cpp btfchan.cpp obj/mlkem.o bip32.cpp btfaddr.cpp
	$(CXX) $(CXXFLAGS) -o $@ test_chatstore.cpp chatstore.cpp btfchatbox.cpp btfchatmsg.cpp btfchat.cpp btfchan.cpp obj/mlkem.o bip32.cpp btfaddr.cpp $(LIBS)

tests: btfchat test_bip32 test_btfchan test_btfaddr test_btfchat test_btfchatmsg test_btfchatbox test_btfchatlog test_btfchatlink test_chatstore bitflash-node
	./test_bip32
	./test_btfchan
	./test_btfaddr
	./test_btfchat
	./test_btfchatmsg
	./test_btfchatbox
	./test_btfchatlog
	./test_btfchatlink
	./test_chatstore
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
	./bitflash-node -selftest=sigpipe
	./bitflash-node -selftest=script-eval
	./bitflash-node -selftest=rules-v2
	./bitflash-node -selftest=rules-v3
	./bitflash-node -selftest=net-hardening
	./bitflash-node -selftest=multisig
	./bitflash-node -selftest=socks5-proxy
	./bitflash-node -selftest=managed-tor
	./bitflash-node -selftest=treasury
	./bitflash-node -selftest=chat-link
	./bitflash-node -selftest=chat-identity
	./bitflash-node -selftest=chat-relay
	./bitflash-node -selftest=chat-wallet

.PHONY: tests fuzz-net-message-smoke fuzz-script-smoke
