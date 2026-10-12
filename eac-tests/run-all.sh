#!/bin/sh
# Builds and runs every eac-tests program and prints one line per run.
#   ./run-all.sh [runner...]
# Without arguments the x86-64 binaries are executed directly: on a real x86-64 Linux that is the native reference run,
# on an Arm64 Linux with FEX registered through binfmt_misc it runs them under FEX. A runner can be given explicitly,
# e.g. `./run-all.sh FEXInterpreter`. Needs clang with the x86-64 target (ld.lld optional) and python3.
# Environment: NATIVE=1 for the reference run on x86-64 Linux (every test then expects PASS), CC (default clang), OUT (build directory, default ./build), TIMEOUT (seconds per run, default 60).
# Exit status: 0 when every run gives its expected result, 1 otherwise.
HERE=$(cd "$(dirname "$0")" && pwd)
CC=${CC:-clang}; OUT=${OUT:-$HERE/build}; TIMEOUT=${TIMEOUT:-60}
mkdir -p "$OUT"; bad=0

# name  binary  expected  env
# pop-fault needs the withdrawn patch 0021 and is expected to FAIL on this branch (it passes natively).
TESTS='
ptrace-inject       ptrace_inject_test          PASS -
signal-mask         signal_mask_test            PASS -
signal-regs         signal_regs_test            PASS -
seccomp-trap        seccomp_trap_test           PASS FEX_NEEDSSECCOMP=1
seccomp-trap-noexec seccomp_trap_noexec_test    PASS FEX_NEEDSSECCOMP=1
seccomp-trap-blocked seccomp_trap_blocked_test  PASS FEX_NEEDSSECCOMP=1
signal-race         seccomp_signal_race_test    PASS FEX_NEEDSSECCOMP=1
cpuid-fault         cpuid_fault_test            PASS -
proc-status         proc_status_test            PASS -
proc-maps           proc_maps_test              PASS -
smc-remote-write    smc_remote_write_test       PASS -
smc-same-page       smc_same_page_test          PASS -
smc-same-page       smc_same_page_test          PASS FEX_SMCHOTPAGEFAULTS=0
munmap-4g           munmap_4g_test              PASS -
ptrace-dregs        ptrace_dregs_test           PASS -
ptrace-regsets      ptrace_regsets_test         PASS -
restart-syscall     restart_syscall_test        PASS -
signal-frame        signal_frame_test           PASS -
signal-frame        signal_frame_test           PASS FEX_HOSTFEATURES=disableavx
sigreturn-eflags    sigreturn_eflags_test       PASS -
maps-probe          maps_probe_test             PASS -
tf-iret             tf_iret_test                PASS -
pop-fault           pop_fault_test              FAIL -
'

echo "$TESTS" | while read -r name bin expect envs; do
  [ -n "$name" ] || continue
  if [ ! -x "$OUT/$bin" ]; then
    (cd "$OUT" && sh "$HERE/$name/build.sh" "$CC" "$bin" >/dev/null 2>"$OUT/$bin.build.log") ||
      { printf '%-20s %-30s BUILD-FAILED (see %s)\n' "$name" "" "$OUT/$bin.build.log"; echo bad > "$OUT/.bad"; continue; }
  fi
  [ "$envs" = - ] && envs=
  [ "${NATIVE:-0}" = 1 ] && expect=PASS
  log="$OUT/$name${envs:+.$(echo "$envs" | tr '=' '_')}.log"
  (cd "$OUT" && env $envs timeout "$TIMEOUT" "$@" "./$bin" >"$log" 2>&1)
  rc=$?
  got=$(grep -o 'RESULT: [A-Z]*' "$log" | tail -1 | cut -d' ' -f2)
  [ -n "$got" ] || got="NONE(exit $rc)"
  if [ "$got" = "$expect" ]; then verdict=ok; else verdict=UNEXPECTED; echo bad > "$OUT/.bad"; fi
  printf '%-20s %-30s %-14s expected %-5s %s\n' "$name" "$envs" "$got" "$expect" "$verdict"
done

[ -f "$OUT/.bad" ] && { rm -f "$OUT/.bad"; bad=1; }
exit $bad
