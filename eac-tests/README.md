# eac-tests

Regression tests for the fidelity patches on this branch (see [EAC-README.md](../EAC-README.md)). Each one is a small
freestanding x86-64 program (raw system calls, no libc) that checks one behaviour a genuine Easy Anti-Cheat title,
Wine/Proton or a debugger relies on, and prints `RESULT: PASS` or `RESULT: FAIL`.

**The expected result is what a real x86-64 Linux kernel does.** Every test runs unchanged on bare-metal x86-64 Linux;
that native run is the oracle, not FEX's own current behaviour. A test that cannot pass natively is the test's bug. A
remaining difference from native that no real program observes is a documented limit, not a defect.

## Building and running

Needs clang with the x86-64 target and python3. `ld.lld` is used when it works; otherwise
[tools/static-link.py](tools/static-link.py), a minimal linker for one freestanding object, links the binary, so the
tests also build on an Arm64 machine without an x86-64 linker.

```
eac-tests/run-all.sh                    # build everything into eac-tests/build/, run each test, one line per run
eac-tests/run-all.sh FEXInterpreter     # the same with an explicit runner instead of binfmt_misc
NATIVE=1 eac-tests/run-all.sh           # on a real x86-64 Linux: the reference run, every test expects PASS
```

`run-all.sh` exits 0 when every run gives its expected result. Per test:

```
eac-tests/<name>/build.sh [clang] [output]   # x86-64 binary: run it under FEX, and unchanged on x86-64 Linux
eac-tests/<name>/build.sh native [output]    # where supported: built with the host's cc for the host's own arch
./<binary>                                   # exit status = number of failed checks
```

## The tests

| test | checks | patch |
|---|---|---|
| `ptrace-inject` | The whole `ptrace` conversation of a launcher injecting into a child (35 checks). Under stock FEX it hangs after `PASS: fork`. `run.sh` runs it with a 60 s timeout. | 0001 |
| `signal-mask` | The Linux signal-mask rule around guest handlers. | 0007, 0008 |
| `signal-regs` | A handler's register changes survive across a syscall. | 0008 |
| `seccomp-trap` | Wine's `SECCOMP_RET_TRAP`/SIGSYS path: `si_code`/`si_syscall`/`si_arch`/`si_call_addr`, the six arguments in the ucontext, a RAX written by the handler resumes the caller; 1000 repetitions. Run with `FEX_NEEDSSECCOMP=1`. | 0010 |
| `seccomp-trap-noexec` | A trapped syscall is never executed (a trapped `uname()` leaves its buffer untouched). Run with `FEX_NEEDSSECCOMP=1`. | 0010 |
| `seccomp-trap-blocked` | A trapped syscall is never executed, and a blocked or ignored SIGSYS is forced like Linux does (`force_sig_seccomp`): the process dies from SIGSYS. Run with `FEX_NEEDSSECCOMP=1`. | 0036 |
| `signal-race` | A thread looping trapped syscalls while another hammers it with SIGUSR1 can still be stopped (the shape of Wine's `NtGetContextThread`). Run with `FEX_NEEDSSECCOMP=1`. | 0010, 0022 |
| `fdexec-argv` | `fexecve()` (`execveat(fd, "", AT_EMPTY_PATH)`), the same with an `FD_CLOEXEC` fd, `execve("/proc/self/fd/N")` and a path `execve` pass argv (including argv[0]) and envp unchanged. Run with and without FEX's binfmt_misc registration. | 0039 |
| `cpuid-fault` | `arch_prctl(ARCH_SET_CPUID/ARCH_GET_CPUID)`: a CPUID faults as SIGSEGV/`SI_KERNEL` while disabled. Re-execs itself with `FEX_ENABLECPUIDFAULTING=1`. A host CPU without `cpuid_fault` reports SKIP natively. | 0011 |
| `munmap-4g` | x86-64 munmap across 4 GiB, with holes, at the 4 GiB boundary, MAP_32BIT reuse, overflowing lengths. | #5847 |
| `ptrace-dregs` | Debug registers through `PTRACE_PEEKUSER`/`POKEUSER`, with the kernel's validation and error codes. | 0012 |
| `proc-status` | `Seccomp:` and `TracerPid:` in `/proc/self/status`. Re-execs itself with `FEX_NEEDSSECCOMP=1`. | 0013 |
| `ptrace-regsets` | `PTRACE_GETREGSET`/`SETREGSET`: `NT_PRSTATUS`, `NT_X86_XSTATE`, `-EINVAL` for an unknown type. | 0014 |
| `restart-syscall` | `restart_syscall` returns `-EINTR` and the process survives. | 0015 |
| `signal-frame` | The signal frame against what Linux writes: TF single-step, CS/SS `0x33`/`0x2b`, the XSAVE fpstate trailer (run a second time with `FEX_HOSTFEATURES=disableavx` for the FXSAVE frame), `ud2` → `ILL_ILLOPN`, `uc_sigmask`, a frame that does not fit the stack. | 0016–0020 |
| `sigreturn-eflags` | `rt_sigreturn` applies EFLAGS a handler wrote (DF; TF starts single-stepping with exactly one SIGTRAP). | 0016 |
| `maps-probe` | Probes every inaccessible mapping listed in `/proc/self/maps` under a SIGSEGV handler: every probe returns, `si_addr` is the probed address. | 0023 |
| `tf-iret` | Where the single-step trap lands after `POPFQ`, an `IRETQ` loading TF, Wine's `popfq; iretq`, and across cached call/ret code. | 0025 |
| `proc-maps` | `/proc/self/maps` lists only x86-64 process mappings: everything below `TASK_SIZE_MAX` except `[vsyscall]`, every file-backed ELF mapping x86-64. | 0033 |
| `smc-remote-write` | A code page the guest made RWX (and executed from again) can be written by another process with `process_vm_writev` (Wine's `NtWriteVirtualMemory`), and the new code runs. | 0035 |
| `smc-same-page` | Code that rewrites instructions on its own page (ahead of and behind the writer, in and outside the executing block, 1 to 16 bytes, with and without a jump or CPUID in between, across a page boundary, with the stack on the page) runs the new code every time and never hangs; then the same while a second thread keeps translating code from that page. Run also with `FEX_SMCHOTPAGEFAULTS=0`. | 0037 |
| `syscall-efault` | 51 system-call cases given a pointer into a `PROT_NONE` page (or a structure running into one) return `-EFAULT` and the caller survives. Run with `FEX_NEEDSSECCOMP=1` (the seccomp case). | 3942 fix |
| `pop-fault` | A faulting `pop` to memory leaves RSP unchanged. Its patch (0021) is withdrawn, so it is **expected to fail** on this branch. | — |
| `bench` | Not a pass/fail test: micro-benchmarks for code-churn invalidation (`EXTRA="-DINVAL_MODE=1 -DINVAL_THREADS=190"`) and the self-modifying-code modes; `tso_probe.c` is an ordinary Arm64 program printing the TSO `prctl` state. | 0002, 0004 |

Expected results (same binaries on all three):

| test | native x86-64 | stock FEX-2610 | eac-2610 |
|---|---|---|---|
| `ptrace-inject` | PASS | hang (timeout) | PASS |
| `signal-mask`, `signal-regs`, `signal-race`, `cpuid-fault`, `proc-status`, `ptrace-regsets`, `ptrace-dregs`, `signal-frame`, `sigreturn-eflags`, `tf-iret` | PASS | FAIL | PASS |
| `proc-maps` | PASS (x86-64, kernel 6.19) | FAIL | PASS |
| `smc-remote-write` | PASS (x86-64, kernel 6.19) | FAIL | PASS |
| `smc-same-page` | PASS (x86-64, kernel 6.19) | not run (same code as eac-2610 before 0037, which fails the `+thread` cases) | PASS |
| `seccomp-trap`, `seccomp-trap-noexec` | PASS | SIGSEGV | PASS |
| `seccomp-trap-blocked` | PASS | not run | PASS (FAIL on `eac-2610.2`) |
| `fdexec-argv` | PASS | FAIL (FD cases without binfmt_misc, FD_CLOEXEC case with it) | PASS |
| `restart-syscall` | PASS | SIGILL | PASS |
| `maps-probe` | PASS | hang (timeout) | PASS |
| `pop-fault` | PASS | FAIL | FAIL (withdrawn 0021) |

Each test fails without the patch it names: the series was built one patch at a time and each test flips from FAIL to
PASS at its own patch.

## Adding a test

New behaviour on this branch ships with a test here: a freestanding program that prints `RESULT: PASS`/`FAIL`, passes
on a real x86-64 Linux kernel, fails without the change and passes with it. Add it to the list in `run-all.sh`.
