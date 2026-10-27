#!/bin/sh
# Build with mingw-w64 or llvm-mingw: CC=x86_64-w64-mingw32-clang ./build.sh
set -e
cd "$(dirname "$0")"
${CC:-x86_64-w64-mingw32-gcc} -O1 -o ntflag.exe ntflag.c
