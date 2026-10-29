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

`run-all.sh` exits 0 when every run gives its expected result. A run over `TIMEOUT` seconds (default 60) is killed and
reported as `TIMEOUT`. A test that could not exercise its feature prints `RESULT: SKIP` and the reason; that is
accepted (and listed) only in the `NATIVE=1` run, under FEX it fails. Tests that re-exec themselves with a FEX option
build the new environment from the actual one, so any environment size works. CI
(`.github/workflows/eac-tests.yml`) runs the suite under FEX on an Arm64 runner and natively on an x86-64 runner, each
with the runner's environment and with an inflated one (400 variables of 1 KiB). Per test:

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
| `sigreturn-jit-regs` | After a handler's `rt_sigreturn` into code that makes no syscall, a SIGSEGV handler and a store to the code's own page see the current RSP, not the one from the last syscall. Run also with `FEX_SMCHOTPAGEFAULTS=0`. | 0041 |
| `seccomp-trap` | Wine's `SECCOMP_RET_TRAP`/SIGSYS path: `si_code`/`si_syscall`/`si_arch`/`si_call_addr`, the six arguments in the ucontext, a RAX written by the handler resumes the caller; 1000 repetitions. Run with `FEX_NEEDSSECCOMP=1`. | 0010 |
| `seccomp-trap-noexec` | A trapped syscall is never executed (a trapped `uname()` leaves its buffer untouched). Run with `FEX_NEEDSSECCOMP=1`. | 0010 |
| `seccomp-trap-blocked` | A trapped syscall is never executed, and a blocked or ignored SIGSYS is forced like Linux does (`force_sig_seccomp`): the process dies from SIGSYS. Run with `FEX_NEEDSSECCOMP=1`. | 0036 |
| `execve-seccomp` | With a seccomp filter installed, a path `execve` of an ELF and of a `#!` script and an `execveat` of an FD (with and without `FD_CLOEXEC`) start the new program with the filter, the inherited FDs and no FD_CLOEXEC FD. Run with `FEX_NEEDSSECCOMP=1`. | 0038 |
| `signal-race` | A thread looping trapped syscalls while another hammers it with SIGUSR1 can still be stopped (the shape of Wine's `NtGetContextThread`), and every trapped syscall delivers exactly one SIGSYS. Run with `FEX_NEEDSSECCOMP=1`. | 0010, 0022 |
| `fdexec-argv` | `fexecve()` (`execveat(fd, "", AT_EMPTY_PATH)`), the same with an `FD_CLOEXEC` fd, `execve("/proc/self/fd/N")` and a path `execve` pass argv (including argv[0]) and envp unchanged. Run with and without FEX's binfmt_misc registration. | 0039 |
| `cpuid-fault` | `arch_prctl(ARCH_SET_CPUID/ARCH_GET_CPUID)`: a CPUID faults as SIGSEGV/`SI_KERNEL` while disabled. Re-execs itself with `FEX_ENABLECPUIDFAULTING=1`. A host CPU without `cpuid_fault` reports SKIP natively. | 0011 |
| `munmap-4g` | x86-64 munmap across 4 GiB, with holes, at the 4 GiB boundary, MAP_32BIT reuse, overflowing lengths. | #5847 |
| `smc-kernel-write` | read, pread64, recvfrom (file, pipe, stream, datagram) into a page that holds translated code fill it as Linux does; mirrors, partial and EFAULT cases. | #5874 |
| `smc-hot-page` | A code page written all the time (data next to code, code rewritten in place, a memfd mirror) keeps running the right code; per loop, the SMC write faults stay within `FEX_SMCHOTPAGEFAULTS`. Run a second time with `FEX_SMCHOTPAGEFAULTS=0` as the negative control (expected FAIL). | 0002 |
| `ptrace-dregs` | Debug registers through `PTRACE_PEEKUSER`/`POKEUSER`, with the kernel's validation and error codes. | 0012 |
| `proc-status` | `Seccomp:` and `TracerPid:` in `/proc/self/status`. Re-execs itself with `FEX_NEEDSSECCOMP=1`. | 0013 |
| `sigtrace-unlink` | `FEX_SIGNALTRACE=1` ring `/dev/shm/fex-<pid>-sigtrace` exists while the process runs and is gone after a normal exit. Re-execs itself with the option. | 0007 |
| `ptrace-regsets` | `PTRACE_GETREGSET`/`SETREGSET`: `NT_PRSTATUS`, `NT_X86_XSTATE`, `-EINVAL` for an unknown type. | 0014 |
| `ptrace-sigbus` | A tracer sees no SIGBUS stop for unaligned atomics (FEX's own `BUS_ADRALN` on arm64), and still sees the tracee's real SIGBUS (`BUS_ADRERR`). | 0039 |
| `restart-syscall` | `restart_syscall` returns `-EINTR` and the process survives. | 0015 |
| `signal-frame` | The signal frame against what Linux writes: TF single-step, CS/SS `0x33`/`0x2b`, the XSAVE fpstate trailer (run a second time with `FEX_HOSTFEATURES=disableavx` for the FXSAVE frame), `ud2` → `ILL_ILLOPN`, `uc_sigmask`, a frame that does not fit the stack. | 0016–0020 |
| `sigreturn-eflags` | `rt_sigreturn` applies EFLAGS a handler wrote (DF; TF starts single-stepping with exactly one SIGTRAP). | 0016 |
| `maps-probe` | Probes every inaccessible mapping listed in `/proc/self/maps` under a SIGSEGV handler: every probe returns, `si_addr` is the probed address. | 0023 |
| `tf-iret` | Where the single-step trap lands after `POPFQ`, an `IRETQ` loading TF, Wine's `popfq; iretq`, and across cached call/ret code. | 0025 |
| `iret-nt` | EFLAGS.NT: `POPFQ`/`PUSHFQ`, R11 after a syscall, `IRETQ` with NT = 1 raises #GP at the `IRETQ` with its frame intact, `IRETQ` with NT = 0 loads NT from its frame, a signal context reports the live NT (Limit: FEX's `rt_sigreturn` applies NT a handler writes to the context, Linux keeps the interrupted NT; no consumer known). Wine side (exception `CONTEXT`, raw invalid syscall, child processes): `wine-ntflag/` (Windows PE, run under Wine). | #27 |
| `seg-load64` | `MOV` to FS and GS in 64-bit mode with 31 selectors each: null selectors load and clear the base, the user descriptors load with base 0, every other selector raises #GP with the selector as the error code; reads return the loaded selector. | #29 |
| `insn-straddle` | An instruction fetch fault at a page boundary: an instruction that starts on an executable page and ends on a PROT_NONE or PROT_READ page faults at the boundary with RIP at the instruction; a jump into the page faults at its target. | #30 |
| `decode-race` | A page that code only branches to is switched between PROT_NONE and executable while another thread calls that code: no thread faults and the process never stalls (FEX's decoder reads ahead into such a page; a fault there used to reach the program and leave the code-invalidation lock held). | #34 |
| `proc-maps` | `/proc/self/maps` lists only x86-64 process mappings: everything below `TASK_SIZE_MAX` except `[vsyscall]`, every file-backed ELF mapping x86-64. | 0033 |
| `smc-remote-write` | A code page the guest made RWX (and executed from again) can be written by another process with `process_vm_writev` (Wine's `NtWriteVirtualMemory`), and the new code runs. | 0035 |
| `smc-same-page` | Code that rewrites instructions on its own page (ahead of and behind the writer, in and outside the executing block, 1 to 16 bytes, with and without a jump or CPUID in between, across a page boundary, with the stack on the page) runs the new code every time and never hangs; then the same while a second thread keeps translating code from that page. Run also with `FEX_SMCHOTPAGEFAULTS=0`. | 0037 |
| `smc-restart-state` | A store to data on the page of the code that writes it (0x600 bytes away, outside the executing block) gives the instruction's result exactly once, with the flags and registers from before it: `adc`/`sbb`/`rcl`/`rcr` (CF in), `xadd`, `pop` to memory (RSP), `stos`/`movs` (RSI/RDI), `fstp` (x87 TOP), `cmpxchg`, `add` as the control. Run also with `FEX_SMCHOTPAGEFAULTS=0`. | #35 fix |
| `syscall-efault` | 51 system-call cases given a pointer into a `PROT_NONE` page (or a structure running into one) return `-EFAULT` and the caller survives. Run with `FEX_NEEDSSECCOMP=1` (the seccomp case). | 3942 fix |
| `sigreturn-syscallinfo` | Signal frames stay below the live stack after earlier handlers returned normally through `rt_sigreturn` (worker with a 12-deep patterned call chain, SIGUSR1 every 20 us, 100000 signals). | 5901 fix |
| `pop-fault` | A faulting `pop` to memory leaves RSP unchanged. Its patch (0021) is withdrawn, so it is **expected to fail** on this branch. | — |
| `insn-diff` | Not a pass/fail test: differential instruction test. `gen.py` generates ~1100 instruction forms (ALU/ADC/SBB, all shifts and rotates with every count class, MUL/DIV, bit scans and counts, BT* with memory bit offsets, BMI1/BMI2/ADX, CRC32, CMPXCHG/XADD/CMPXCHG16B, MOVBE/BSWAP, LAHF/SAHF/PUSHF/POPF, partial registers, SETcc/CMOVcc, string ops with DF=0/1, FS/GS-prefixed memory, x87 incl. FPREM/FXAM/transcendentals/BCD, SSE4.2 string compares, AES-NI, PCLMULQDQ, SHA-NI, SSE conversions/rounding/compares) plus random 2-8 instruction sequences; `harness.c` runs each with seeded random GPR/flag/x87/XMM/MXCSR/memory state and prints the result as a delta; `compare.py` diffs a native run against a FEX run and separates defined differences from architecturally undefined flags, x87/MXCSR status-only and transcendental-ulp differences. `build.sh` needs x86-64 gcc (static glibc). | — |
| `bench` | Not a pass/fail test: micro-benchmarks for code-churn invalidation (`EXTRA="-DINVAL_MODE=1 -DINVAL_THREADS=190"`) and the self-modifying-code modes; `tso_probe.c` is an ordinary Arm64 program printing the TSO `prctl` state. | 0002, 0004 |

Expected results (same binaries on all three):

| test | native x86-64 | stock FEX-2610 | eac-2610 |
|---|---|---|---|
| `ptrace-inject` | PASS | hang (timeout) | PASS |
| `ptrace-sigbus` | not run yet | not run | PASS (FAIL on `eac-2610` before 0039) |
| `cpuid-fault` | PASS with `cpuid_fault` (Intel bare metal); SKIP without it (AMD, most VMs incl. GitHub runners) | FAIL | PASS |
| `signal-mask`, `signal-regs`, `signal-race`, `proc-status`, `ptrace-regsets`, `ptrace-dregs`, `signal-frame`, `sigreturn-eflags`, `tf-iret` | PASS | FAIL | PASS |
| `proc-maps` | PASS (x86-64, kernel 6.19) | FAIL | PASS |
| `smc-remote-write` | PASS (x86-64, kernel 6.19) | FAIL | PASS |
| `smc-same-page` | PASS (x86-64, kernel 6.19) | not run (same code as eac-2610 before 0037, which fails the `+thread` cases) | PASS |
| `seccomp-trap`, `seccomp-trap-noexec` | PASS | SIGSEGV | PASS |
| `seccomp-trap-blocked` | PASS | not run | PASS (FAIL on `eac-2610.2`) |
| `fdexec-argv` | PASS | FAIL (FD cases without binfmt_misc, FD_CLOEXEC case with it) | PASS |
| `execve-seccomp` | PASS | FAIL (the `#!` case) | PASS |
| `restart-syscall` | PASS | SIGILL | PASS |
| `sigreturn-jit-regs` | PASS | not run | PASS (FAIL on `eac-2610` before 0041) |
| `maps-probe` | PASS | hang (timeout) | PASS |
| `seg-load64`, `insn-straddle` | PASS | FAIL | PASS |
| `decode-race` | PASS | not run | PASS (stalls in 2 of 3 runs on `eac-2610` before #34) |
| `pop-fault` | PASS | FAIL | FAIL (withdrawn 0021) |

Each test fails without the patch it names: the series was built one patch at a time and each test flips from FAIL to
PASS at its own patch.

## Adding a test

New behaviour on this branch ships with a test here: a freestanding program that prints `RESULT: PASS`/`FAIL`, passes
on a real x86-64 Linux kernel, fails without the change and passes with it. Add it to the list in `run-all.sh`.
