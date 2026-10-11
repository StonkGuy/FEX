#!/bin/sh
# Builds the static x86-64 test binary on a Linux x86-64 host (needs glibc: pthreads, malloc).
#   ./build.sh [output]
# Unlike the freestanding tests (segv-regs, alt-nested) this one links glibc: the point is to
# exercise fork()/pthread_create() through a real libc, which is exactly how the live hang fired.
# Build on the x86 reference box (or any x86-64 Linux), then copy the binary into the guest to run
# under FEX:
#   gcc -static -O2 -pthread fork_deadlock_test.c -o fork_deadlock_test
set -e
OUT=${1:-fork_deadlock_test}
HERE=$(cd "$(dirname "$0")" && pwd)
command -v gcc >/dev/null || { echo "build.sh needs gcc on an x86-64 Linux host (see header)" >&2; exit 2; }
gcc -static -O2 -pthread "$HERE/fork_deadlock_test.c" -o "$OUT"
echo "built $OUT"
