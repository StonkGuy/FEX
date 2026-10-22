#!/bin/sh
# Build with llvm-mingw or mingw-w64: CC=x86_64-w64-mingw32-clang ./build.sh
set -e
cd "$(dirname "$0")"
${CC:-x86_64-w64-mingw32-gcc} -O1 -o ntcontinue.exe ntcontinue.c
