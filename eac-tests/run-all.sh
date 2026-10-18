#!/bin/sh
# Builds and runs every eac-tests program and prints one line per run.
#   ./run-all.sh [runner...]
# Without arguments the x86-64 binaries are executed directly: on a real x86-64 Linux that is the native reference run,
# on an Arm64 Linux with FEX registered through binfmt_misc it runs them under FEX. A runner can be given explicitly,
# e.g. `./run-all.sh FEXInterpreter`. Needs clang with the x86-64 target (ld.lld optional) and python3.
# Environment: NATIVE=1 for the reference run on x86-64 Linux (every test then expects PASS), CC (default clang), OUT (build directory, default ./build), TIMEOUT (seconds per run, default 60).
# A run that exceeds TIMEOUT is killed and reported as TIMEOUT; a test that could not exercise its feature prints
# RESULT: SKIP with the reason. SKIP is accepted only in the NATIVE=1 run (the host may lack the feature, e.g. CPUID
# faulting on AMD or in a VM) and is listed with its reason; under FEX a SKIP means the feature is missing and fails.
# Exit status: 0 when every run gives its expected result, 1 otherwise.
HERE=$(cd "$(dirname "$0")" && pwd)
CC=${CC:-clang}; OUT=${OUT:-$HERE/build}; TIMEOUT=${TIMEOUT:-60}
mkdir -p "$OUT"; bad=0

# name  binary  expected  env
# smc-hot-page with FEX_SMCHOTPAGEFAULTS=0 is the negative control: every store faults, so it FAILs under FEX.
# pop-fault needs the withdrawn patch 0021 and is expected to FAIL on this branch (it passes natively).
TESTS='
ptrace-inject       ptrace_inject_test          PASS -
signal-mask         signal_mask_test            PASS -
signal-regs         signal_regs_test            PASS -
seccomp-trap        seccomp_trap_test           PASS FEX_NEEDSSECCOMP=1
seccomp-trap-noexec seccomp_trap_noexec_test    PASS FEX_NEEDSSECCOMP=1
seccomp-trap-blocked seccomp_trap_blocked_test  PASS FEX_NEEDSSECCOMP=1
signal-race         seccomp_signal_race_test    PASS FEX_NEEDSSECCOMP=1
fdexec-argv         fdexec_argv_test            PASS -
execve-seccomp      execve_seccomp_test         PASS FEX_NEEDSSECCOMP=1
cpuid-fault         cpuid_fault_test            PASS -
proc-status         proc_status_test            PASS -
proc-maps           proc_maps_test              PASS -
sigtrace-unlink     sigtrace_unlink_test        PASS -
smc-remote-write    smc_remote_write_test       PASS -
smc-same-page       smc_same_page_test          PASS -
smc-same-page       smc_same_page_test          PASS FEX_SMCHOTPAGEFAULTS=0
munmap-4g           munmap_4g_test              PASS -
smc-hot-page        smc_hot_page_test           PASS -
smc-hot-page        smc_hot_page_test           FAIL FEX_SMCHOTPAGEFAULTS=0
smc-kernel-write    smc_kernel_write_test       PASS -
ptrace-dregs        ptrace_dregs_test           PASS -
ptrace-regsets      ptrace_regsets_test         PASS -
ptrace-sigbus       ptrace_sigbus_test          PASS -
restart-syscall     restart_syscall_test        PASS -
signal-frame        signal_frame_test           PASS -
signal-frame        signal_frame_test           PASS FEX_HOSTFEATURES=disableavx
sigreturn-eflags    sigreturn_eflags_test       PASS -
maps-probe          maps_probe_test             PASS -
tf-iret             tf_iret_test                PASS -
syscall-efault      syscall_efault_test         PASS FEX_NEEDSSECCOMP=1
sigreturn-syscallinfo sigreturn_syscallinfo_test PASS -
sigsys-redirect     sigsys_redirect_test        PASS FEX_NEEDSSECCOMP=1
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
  (cd "$OUT" && env $envs timeout -k 5 "$TIMEOUT" "$@" "./$bin" >"$log" 2>&1)
  rc=$?
  got=$(grep -o 'RESULT: [A-Z]*' "$log" | tail -1 | cut -d' ' -f2)
  if [ -z "$got" ]; then
    case $rc in 124|137) got="TIMEOUT(${TIMEOUT}s)" ;; *) got="NONE(exit $rc)" ;; esac
  fi
  if [ "$got" = "$expect" ]; then verdict=ok
  elif [ "$got" = SKIP ] && [ "${NATIVE:-0}" = 1 ]; then verdict="skipped: $(grep -m1 '^SKIP:' "$log" | cut -c7-)"
  else verdict=UNEXPECTED; echo bad > "$OUT/.bad"; fi
  printf '%-20s %-30s %-14s expected %-5s %s\n' "$name" "$envs" "$got" "$expect" "$verdict"
done

[ -f "$OUT/.bad" ] && { rm -f "$OUT/.bad"; bad=1; }
exit $bad
