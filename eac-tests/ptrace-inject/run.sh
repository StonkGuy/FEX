#!/bin/sh
# Runs the synthetic ptrace injection test. On an x86-64 Linux machine this is the reference behaviour; on arm64 run it
# where x86-64 binaries execute through FEX (e.g. inside the muvm VM) with a FEX that has the patches.
#   ./run.sh [path/to/ptrace_inject_test]
BIN=${1:-./ptrace_inject_test}
timeout 60 "$BIN"
