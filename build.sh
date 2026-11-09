#!/usr/bin/env bash
# Build Bitflash on MSYS2 UCRT64. Usage: bash build.sh [target]
cd "$(dirname "$0")/src" || exit 1
mkdir -p obj
exec mingw32-make -f makefile.mingw "${@:-all}"
