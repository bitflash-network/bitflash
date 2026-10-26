# Bitflash — top-level build
#
#   make linux    build Bitflash-*-x86_64.AppImage
#   make appimage-tor build the AppImage with managed Tor + transports bundled
#   make windows  build Bitflash-*-windows.zip (from MSYS2 UCRT64)
#   make windows-tor build Bitflash-*-windows-with-tor.zip
#   make tests    build and run standalone unit tests
#   make checksums create SHA256SUMS for release assets
#   make verify-release TAG=v1.2.13
#   make clean    remove build artifacts

ROOT    := $(shell pwd)
NPROC   := $(shell nproc 2>/dev/null || echo 2)

# Reproducible packages: every file in an archive or AppImage carries the
# commit's time, not the build's, so two builds of one commit can match.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 0)
export SOURCE_DATE_EPOCH

# The AppImage tools, pinned. They used to come from the "continuous" release
# with no hash: whoever could change that page chose what went into every
# AppImage, and no two builds were made with the same tool.
APPIMAGETOOL        := /tmp/appimagetool-1.9.1
APPIMAGETOOL_URL    := https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-x86_64.AppImage
APPIMAGETOOL_SHA256 := ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0
APPIMAGE_RUNTIME        := /tmp/appimage-runtime-20251108
APPIMAGE_RUNTIME_URL    := https://github.com/AppImage/type2-runtime/releases/download/20251108/runtime-x86_64
APPIMAGE_RUNTIME_SHA256 := 2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d
SUDO    := $(shell [ "$$(id -u)" = "0" ] && echo "" || echo "sudo")
VERSION := 1.2.31

SECP256K1_REPO   := https://github.com/bitcoin-core/secp256k1
SECP256K1_COMMIT := 7fecac74aed8e1fd9078380d67dd04663705c989
RANDOMX_REPO     := https://github.com/tevador/RandomX
RANDOMX_COMMIT   := 1e9d4b2df63fa6edf46b06789486e23c0fcaa55a

# ---- Linux ----------------------------------------------------------------

linux: deps-linux
	$(MAKE) -C src -f Makefile -j$(NPROC)
	strip src/bitflash
	$(MAKE) -f Makefile appimage
	$(MAKE) -f Makefile linux-node
	$(MAKE) -f Makefile btfchat-appimage

# Headless node, no ImGui/GLFW/OpenGL. The GUI build needs libGL present at load
# time even when started with -nogui -- the dynamic loader resolves everything
# before main() runs, so the flag comes far too late. On a clean server, which is
# where a node most naturally lives, that is a hard failure. This binary has no
# such dependency and needs no FUSE either, so it drops onto a VPS and runs.
linux-node: deps-linux
	$(MAKE) -C src -f Makefile bitflash-node -j$(NPROC)
	strip src/bitflash-node
	cp src/bitflash-node bitflash-node-$(VERSION)-x86_64
	@echo "Built: bitflash-node-$(VERSION)-x86_64"

deps-linux: deps-apt deps-secp256k1 deps-randomx

deps-apt:
	@if command -v apt-get >/dev/null 2>&1; then \
	  $(SUDO) apt-get install -y build-essential cmake git pkg-config autoconf \
	    libtool libssl-dev libdb5.3++-dev libsodium-dev nlohmann-json3-dev \
	    libboost-system-dev libglfw3-dev libgl-dev libsqlite3-dev \
	    python3-pil clang; \
	else \
	  echo "Not an apt system — install: g++ cmake git autoconf libtool"; \
	  echo "  libssl libdb++ libsodium nlohmann-json boost glfw3 opengl sqlite3 python3-pil"; \
	fi

deps-secp256k1:
	@if [ ! -f /usr/local/lib/libsecp256k1.a ]; then \
	  echo "==> building libsecp256k1"; \
	  rm -rf $(ROOT)/secp256k1-build; \
	  git init -q $(ROOT)/secp256k1-build; \
	  cd $(ROOT)/secp256k1-build && \
	  git remote add origin $(SECP256K1_REPO) && \
	  git fetch -q --depth 1 origin $(SECP256K1_COMMIT) && \
	  git checkout -q --detach FETCH_HEAD && \
	  test "$$(git rev-parse HEAD)" = "$(SECP256K1_COMMIT)" && \
	  echo "==> libsecp256k1 pinned at $(SECP256K1_COMMIT)" && \
	  cd $(ROOT)/secp256k1-build && ./autogen.sh && \
	  ./configure --enable-module-schnorrsig --enable-module-extrakeys \
	    --disable-shared --with-pic --disable-benchmark --disable-tests && \
	  make -j$(NPROC) && $(SUDO) make install && $(SUDO) ldconfig; \
	  echo "==> libsecp256k1 done"; \
	else \
	  echo "==> libsecp256k1 already installed"; \
	fi

deps-randomx:
	@if [ ! -f $(HOME)/RandomX/build/librandomx.a ]; then \
	  echo "==> building RandomX"; \
	  rm -rf $(HOME)/RandomX; \
	  git init -q $(HOME)/RandomX; \
	  cd $(HOME)/RandomX && \
	  git remote add origin $(RANDOMX_REPO) && \
	  git fetch -q --depth 1 origin $(RANDOMX_COMMIT) && \
	  git checkout -q --detach FETCH_HEAD && \
	  test "$$(git rev-parse HEAD)" = "$(RANDOMX_COMMIT)" && \
	  echo "==> RandomX pinned at $(RANDOMX_COMMIT)" && \
	  mkdir -p $(HOME)/RandomX/build; \
	  cd $(HOME)/RandomX/build && cmake .. -DCMAKE_BUILD_TYPE=Release && \
	  make -j$(NPROC) randomx; \
	  echo "==> RandomX done"; \
	else \
	  echo "==> RandomX already built"; \
	fi

# The GUI binary the AppImage packs. A plain file prerequisite here once let
# `make appimage-tor` pack whatever src/bitflash happened to be lying around;
# it packed a stale one for six releases. Always rebuild through src/Makefile.
gui:
	$(MAKE) -C src -f Makefile bitflash -j$(NPROC)
	strip src/bitflash

# Fetch the pinned AppImage tool and runtime, and refuse them unless their
# hashes are the ones above.
appimage-tools:
	@for pair in "$(APPIMAGETOOL)|$(APPIMAGETOOL_URL)|$(APPIMAGETOOL_SHA256)" \
	             "$(APPIMAGE_RUNTIME)|$(APPIMAGE_RUNTIME_URL)|$(APPIMAGE_RUNTIME_SHA256)"; do \
	  f=$${pair%%|*}; rest=$${pair#*|}; url=$${rest%%|*}; want=$${rest#*|}; \
	  if [ ! -f "$$f" ] || [ "$$(sha256sum "$$f" | cut -d' ' -f1)" != "$$want" ]; then \
	    wget -q "$$url" -O "$$f.part" || exit 1; \
	    got=$$(sha256sum "$$f.part" | cut -d' ' -f1); \
	    if [ "$$got" != "$$want" ]; then echo "hash mismatch for $$url: $$got" >&2; rm -f "$$f.part"; exit 1; fi; \
	    mv "$$f.part" "$$f"; \
	  fi; \
	done; chmod +x $(APPIMAGETOOL)

# Every file in an AppDir gets the commit's time before it is packed.
define appimage_pack
	@find $(1) -exec touch -h -d @$(SOURCE_DATE_EPOCH) {} +
	@ARCH=x86_64 $(APPIMAGETOOL) --no-appstream --runtime-file $(APPIMAGE_RUNTIME) $(1) $(2) 2>&1 | grep -E "^Built|^Error" || true
endef

appimage: gui appimage-tools
	@echo "==> building AppImage"
	@rm -rf /tmp/bitflash.AppDir
	@mkdir -p /tmp/bitflash.AppDir/usr/bin \
	          /tmp/bitflash.AppDir/usr/lib \
	          /tmp/bitflash.AppDir/usr/share/applications \
	          /tmp/bitflash.AppDir/usr/share/icons/hicolor/256x256/apps
	@cp src/bitflash /tmp/bitflash.AppDir/usr/bin/bitflash
	@printf '#!/bin/sh\nHERE="$$(dirname "$$(readlink -f "$$0")")"\nexport LD_LIBRARY_PATH="$$HERE/usr/lib:$$LD_LIBRARY_PATH"\nexec "$$HERE/usr/bin/bitflash" "$$@"\n' \
	  > /tmp/bitflash.AppDir/AppRun && chmod +x /tmp/bitflash.AppDir/AppRun
	@printf '[Desktop Entry]\nName=Bitflash\nExec=bitflash\nIcon=bitflash\nType=Application\nCategories=Finance;\n' \
	  > /tmp/bitflash.AppDir/bitflash.desktop
	@cp /tmp/bitflash.AppDir/bitflash.desktop \
	    /tmp/bitflash.AppDir/usr/share/applications/
	@python3 -c "\
from PIL import Image; \
ico = Image.open('src/rc/bitcoin.ico'); \
img = ico.convert('RGBA'); \
img.save('/tmp/bitflash.AppDir/bitflash.png'); \
import shutil; shutil.copy('/tmp/bitflash.AppDir/bitflash.png', \
'/tmp/bitflash.AppDir/usr/share/icons/hicolor/256x256/apps/bitflash.png')"
	@for lib in libsodium.so.23 libdb_cxx-5.3.so libsqlite3.so.0 libglfw.so.3; do \
	  path=$$(ldconfig -p | grep " $$lib " | awk '{print $$NF}' | head -1); \
	  [ -z "$$path" ] && path=$$(find /usr/lib /lib -name "$$lib" 2>/dev/null | head -1); \
	  [ -n "$$path" ] && cp -L "$$path" /tmp/bitflash.AppDir/usr/lib/ && echo "  bundled $$lib" || echo "  missing $$lib"; \
	done
	@if [ -n "$(WITH_TOR)" ]; then \
	  echo "==> bundling Tor into the AppImage"; \
	  ./scripts/bundle-tor-linux.sh /tmp/bitflash.AppDir/usr/bin; \
	fi
	$(call appimage_pack,/tmp/bitflash.AppDir,$(ROOT)/Bitflash-$(VERSION)-x86_64.AppImage)
	@echo "Built: Bitflash-$(VERSION)-x86_64.AppImage"

# Release AppImage: same as `appimage` but with managed Tor and the obfs4 /
# snowflake pluggable transports bundled in, so it reaches Tor with no system
# Tor install. This is the artifact that ships.
appimage-tor: gui
	$(MAKE) -f Makefile appimage WITH_TOR=1


# ---- btfchat (Linux) -------------------------------------------------------
#
# A separate AppImage, not a second binary inside the miner's. Its own icon and
# its own desktop entry, because it is its own program: separate process,
# separate data directory (~/.bitflash-chat), separate wallet, separate onion
# address, no chain and no peer-to-peer node.
btfchat-linux: deps-linux
	$(MAKE) -C src -f Makefile btfchat -j$(NPROC)
	strip src/btfchat
	@echo "Built: src/btfchat"

btfchat-appimage: btfchat-linux appimage-tools
	@echo "==> building the btfchat AppImage"
	@rm -rf /tmp/btfchat.AppDir
	@mkdir -p /tmp/btfchat.AppDir/usr/bin \
	          /tmp/btfchat.AppDir/usr/lib \
	          /tmp/btfchat.AppDir/usr/share/applications \
	          /tmp/btfchat.AppDir/usr/share/icons/hicolor/256x256/apps
	@cp src/btfchat /tmp/btfchat.AppDir/usr/bin/btfchat
	@printf '#!/bin/sh\nHERE="$$(dirname "$$(readlink -f "$$0")")"\nexport LD_LIBRARY_PATH="$$HERE/usr/lib:$$LD_LIBRARY_PATH"\nexec "$$HERE/usr/bin/btfchat" "$$@"\n' \
	  > /tmp/btfchat.AppDir/AppRun && chmod +x /tmp/btfchat.AppDir/AppRun
	@printf '[Desktop Entry]\nName=btfchat\nExec=btfchat\nIcon=btfchat\nType=Application\nCategories=Network;InstantMessaging;\n' \
	  > /tmp/btfchat.AppDir/btfchat.desktop
	@cp /tmp/btfchat.AppDir/btfchat.desktop /tmp/btfchat.AppDir/usr/share/applications/
	@python3 -c "\
from PIL import Image; \
ico = Image.open('src/rc/bitcoin.ico'); \
img = ico.convert('RGBA'); \
img.save('/tmp/btfchat.AppDir/btfchat.png'); \
import shutil; shutil.copy('/tmp/btfchat.AppDir/btfchat.png', \
'/tmp/btfchat.AppDir/usr/share/icons/hicolor/256x256/apps/btfchat.png')"
	@for lib in libsodium.so.23 libdb_cxx-5.3.so libsqlite3.so.0 libglfw.so.3; do \
	  path=$$(ldconfig -p | grep " $$lib " | awk '{print $$NF}' | head -1); \
	  [ -z "$$path" ] && path=$$(find /usr/lib /lib -name "$$lib" 2>/dev/null | head -1); \
	  [ -n "$$path" ] && cp -L "$$path" /tmp/btfchat.AppDir/usr/lib/ && echo "  bundled $$lib" || echo "  missing $$lib"; \
	done
	@if [ -n "$(WITH_TOR)" ]; then \
	  echo "==> bundling Tor into the btfchat AppImage"; \
	  ./scripts/bundle-tor-linux.sh /tmp/btfchat.AppDir/usr/bin; \
	fi
	$(call appimage_pack,/tmp/btfchat.AppDir,$(ROOT)/BtfChat-$(VERSION)-x86_64.AppImage)
	@echo "Built: BtfChat-$(VERSION)-x86_64.AppImage"

# The shipping one: managed Tor and the pluggable transports bundled in. btfchat
# without Tor is not a degraded chat, it is no chat at all -- it refuses to dial
# anything but an onion -- so the release artifact always carries it.
btfchat-appimage-tor: btfchat-linux
	$(MAKE) -f Makefile btfchat-appimage WITH_TOR=1

# ---- Windows (MSYS2 UCRT64) -----------------------------------------------

deps-windows:
	pacman -S --noconfirm --needed \
	  mingw-w64-ucrt-x86_64-gcc \
	  mingw-w64-ucrt-x86_64-make \
	  mingw-w64-ucrt-x86_64-glfw \
	  mingw-w64-ucrt-x86_64-openssl \
	  mingw-w64-ucrt-x86_64-db \
	  mingw-w64-ucrt-x86_64-sqlite3 \
	  mingw-w64-ucrt-x86_64-libsodium \
	  mingw-w64-ucrt-x86_64-nlohmann-json \
	  mingw-w64-ucrt-x86_64-boost \
	  mingw-w64-ucrt-x86_64-cmake \
	  autoconf automake libtool
	@if [ ! -f deps/lib/libsecp256k1.a ]; then \
	  rm -rf secp256k1-build; \
	  git init -q secp256k1-build; \
	  cd secp256k1-build && \
	  git remote add origin $(SECP256K1_REPO) && \
	  git fetch -q --depth 1 origin $(SECP256K1_COMMIT) && \
	  git checkout -q --detach FETCH_HEAD && \
	  test "$$(git rev-parse HEAD)" = "$(SECP256K1_COMMIT)" && \
	  echo "==> secp256k1 pinned at $(SECP256K1_COMMIT)" && \
	  cd $(ROOT)/secp256k1-build && ./autogen.sh && \
	  ./configure --prefix=$(ROOT)/deps \
	    --enable-module-schnorrsig --enable-module-extrakeys \
	    --disable-shared --with-pic --disable-benchmark --disable-tests && \
	  make install; \
	  echo "==> secp256k1 done"; \
	else \
	  echo "==> secp256k1 already built"; \
	fi
	@if [ ! -f RandomX/build/librandomx.a ]; then \
	  rm -rf RandomX; \
	  git init -q RandomX; \
	  cd RandomX && \
	  git remote add origin $(RANDOMX_REPO) && \
	  git fetch -q --depth 1 origin $(RANDOMX_COMMIT) && \
	  git checkout -q --detach FETCH_HEAD && \
	  test "$$(git rev-parse HEAD)" = "$(RANDOMX_COMMIT)" && \
	  echo "==> RandomX pinned at $(RANDOMX_COMMIT)" && \
	  mkdir -p $(ROOT)/RandomX/build; \
	  cd $(ROOT)/RandomX/build && cmake .. -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release && \
	  make randomx; \
	  echo "==> RandomX done"; \
	else \
	  echo "==> RandomX already built"; \
	fi

windows: deps-windows
	cd src && make -f makefile.mingw
	cd src && make -f makefile.mingw btfchat.exe
	@rm -rf Bitflash-$(VERSION)-windows
	@mkdir -p Bitflash-$(VERSION)-windows
	@cp src/bitflash.exe Bitflash-$(VERSION)-windows/Bitflash.exe
	@cp src/btfchat.exe Bitflash-$(VERSION)-windows/BtfChat.exe
	@ldd src/bitflash.exe | grep ucrt64 | awk '{print $$3}' | \
	  xargs -I{} cp {} Bitflash-$(VERSION)-windows/ 2>/dev/null || true
	@ldd src/btfchat.exe | grep ucrt64 | awk '{print $$3}' | \
	  xargs -I{} cp {} Bitflash-$(VERSION)-windows/ 2>/dev/null || true
	@zip -r Bitflash-$(VERSION)-windows.zip Bitflash-$(VERSION)-windows/
	@echo "Built: Bitflash-$(VERSION)-windows.zip"

windows-tor: windows
	./scripts/package-windows-tor.sh

# ---- Clean ----------------------------------------------------------------

clean:
	$(MAKE) -C src -f Makefile clean 2>/dev/null || true
	cd src && make -f makefile.mingw clean 2>/dev/null || true
	rm -f Bitflash-*.AppImage Bitflash-*.zip
	rm -rf Bitflash-*-windows

tests:
	$(MAKE) -C src -f Makefile tests

fuzz-net-message-smoke: deps-linux
	$(MAKE) -C src -f Makefile fuzz-net-message-smoke

fuzz-script-smoke: deps-linux
	$(MAKE) -C src -f Makefile fuzz-script-smoke

fuzz-sigcheck-smoke: deps-linux
	$(MAKE) -C src -f Makefile fuzz-sigcheck-smoke

checksums:
	./scripts/make-release-checksums.sh

sign-checksums:
	./scripts/make-release-checksums.sh --sign $(if $(KEY),--local-user $(KEY),)

verify-release:
	./scripts/verify-release.sh $(if $(TAG),$(TAG),latest)

.PHONY: linux windows windows-tor clean gui appimage appimage-tor appimage-tools \
        tests fuzz-net-message-smoke fuzz-script-smoke fuzz-sigcheck-smoke checksums sign-checksums verify-release \
        deps-linux deps-windows deps-apt deps-secp256k1 deps-randomx
