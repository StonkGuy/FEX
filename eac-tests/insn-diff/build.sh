#!/bin/sh
# Builds the static x86-64 insn_diff binary (needs an x86-64 gcc with static glibc, i.e. run it on x86-64 Linux).
#   ./build.sh [output] [sequences]
set -e
HERE=$(cd "$(dirname "$0")" && pwd); OUT=${1:-$PWD/insn_diff}; WORK=$(mktemp -d)
(cd "$WORK" && python3 "$HERE/gen.py" "${2:-600}")
${CC:-gcc} -O2 -static -I"$WORK" -o "$OUT" "$HERE/harness.c" "$WORK/forms.S"
cp "$WORK/forms.json" "$(dirname "$OUT")/forms.json"
rm -rf "$WORK"
