# FEX-Emu eac-2610

Branch `eac-2610` is **FEX-2610** ([`14c9268`](https://github.com/FEX-Emu/FEX/commit/14c92681f4d62cf84d901460e0358de09c8847a7))
**plus fidelity patches that let genuine Easy Anti-Cheat titles run under Proton on Arm64**: faithful `ptrace`,
signal, seccomp and `/proc` emulation where the anti-cheat launcher, Wine/Proton or a debugger observes it, and a few
performance and diagnostic changes found on the way. FEX's own [README.md](README.md) is unchanged.

Releases are tags on this branch: `eac-2610.1` is the first. The write-up — why each patch exists, how it was found,
results and limits — is in the proof of concept,
[StonkGuy/eac-arm64-emulation-poc](https://github.com/StonkGuy/eac-arm64-emulation-poc)
([docs/patches.md](https://github.com/StonkGuy/eac-arm64-emulation-poc/blob/master/docs/patches.md)). This is a
standalone fork; it is not affiliated with FEX-Emu.

## Commits

One commit per patch, in order, on top of FEX-2610. The numbers are the PoC's patch numbers (0021 was withdrawn;
0027–0032 are not part of this release).

| patch | commit | change |
|---|---|---|
| 0001 | `19647b2` | LinuxSyscalls: emulate x86-64 ptrace for tracees that also run under FEX |
| 0002 | `12f7c35` | SMC: stop write-protecting pages that keep faulting, verify their code in the JIT instead |
| 0003 | `5f468fc` | Stats: account guest code-range invalidations |
| 0004 | `bc317d4` | Skip the per-thread cache walk when an invalidated range holds no translated code |
| 0005 | `4ca1637` | Add an in-process sampling profiler (FEX_PROFILESAMPLEHZ) |
| 0006 | `57fa8a5` | SamplingProfiler: add an all-thread snapshot |
| 0007 | `00146a4` | Signals: run guest handlers with the Linux signal mask; optional signal trace |
| 0008 | `0267762` | Signals: do not leave InSyscallInfo set for a guest handler entered from a syscall handler |
| 0009 | `aac9dd7` | SamplingProfiler: record the futex word in all-thread snapshots |
| 0010 | `bcfbe93` | Seccomp: report SECCOMP_RET_TRAP at the instruction after the syscall |
| 0011 | `dd9cbc1` | arch_prctl: honour ARCH_SET_CPUID/ARCH_GET_CPUID |
| 0012 | `89775f9` | ptrace: store the hardware debug registers instead of discarding them |
| 0013 | `915aca6` | proc: report the emulated Seccomp: and TracerPid: in /proc/<pid>/status |
| 0014 | `13282e0` | ptrace: answer unknown GETREGSET/SETREGSET types with -EINVAL, and serve NT_X86_XSTATE |
| 0015 | `ee3ad7b` | syscalls: restart_syscall returns -EINTR instead of aborting the process |
| 0016 | `76e9252` | Signals: restore EFLAGS from the frame on rt_sigreturn even when RIP is unchanged |
| 0017 | `8cd4a09` | Signals: report the Linux 64-bit CS/SS selectors in the frame and to mov %cs/%ss |
| 0018 | `12dd3eb` | Signals: emit an XSAVE fpstate with the FP_XSTATE_MAGIC1/2 trailer on x86-64 |
| 0019 | `7b87d95` | Signals: validate the guest frame destination before writing it |
| 0020 | `0a9cd24` | Signals: write the interrupted mask into the frame's uc_sigmask |
| 0022 | `0cb56fd` | Signals: return to the guest's own host stack level when rt_sigreturn abandons a syscall handler |
| 0023 | `8fed995` | LinuxEmulation: deliver guest reads of the call/ret shadow-stack guard pages instead of spinning |
| 0024 | `3609f03` | SamplingProfiler: FEX_PROFILESAMPLEMINTHREADS and external SIGPROF snapshots |
| 0025 | `78adb13` | JIT: raise the single-step trap on the target of an IRETQ that loads TF, and never leave single-step mode through the lookup caches |
| 0026 | `2169934` | Signals: keep the signal alt stack while a thread exits on it |
| 0033 | `e8f2a2f` | proc: list only the emulated process's mappings in /proc/<pid>/maps |

Two more commits add [eac-tests/](eac-tests/) and this file; they touch nothing FEX builds.

## Options

New behaviour is either on by default where it is the Linux behaviour, or behind an option in FEX's own config
(`Config.json.in`), e.g. `FEX_PROFILESAMPLEHZ` (0005), `FEX_ENABLECPUIDFAULTING` (0011),
`FEX_SIGNALMASKFIX` (0007). Stock options this work relies on, such as `FEX_NEEDSSECCOMP` and
`FEX_TSOENABLED`, are unchanged.

## Building and testing

Build exactly like upstream FEX (for Steam's FEX compatibility tool, `-DBUILD_STEAM_SUPPORT=ON`). Then run the
regression tests under FEX, and on a real x86-64 Linux for the reference:

```
eac-tests/run-all.sh             # on the Arm64 host, FEX registered for x86-64
NATIVE=1 eac-tests/run-all.sh    # on x86-64 Linux: the expected results
```

See [eac-tests/README.md](eac-tests/README.md).

## Bugs, fixes and upstreaming

**Found a bug, or a place where the patched FEX still behaves differently from x86-64 Linux?** Please report it here as
an issue. If you have already fixed it in your own fork, please consider opening a pull request here too (with a test),
so everyone gets the fix and the test suite covers it.

This repository does not send patches to FEX-Emu or Proton itself and is not affiliated with them (steamac changes are
discussed with its maintainer directly). If you have reviewed a patch and think it is good enough for upstream, **you
are welcome to submit it there yourself**: keep its test with it, follow the upstream project's own process, and
mention where it came from. The same applies to the other patched components (libkrun, Mesa/KosmicKrisp,
virglrenderer, DXMT), unless that project's own rules say otherwise — DXMT, for example, does not accept AI-assisted
contributions.

## Maintenance and support

I will try to keep the patched components up to date with their upstream releases, re-running the regression tests on
every update, and to drop any patch once upstream covers its behaviour. For game-specific problems I will try to help
where I can, but I cannot guarantee that every game, or every fix, will work.

Each FEX release is handled the same way: rebase this branch onto it as `eac-<release>`, run `eac-tests` in the
guest and natively for the oracle, check a live VRChat session, drop every patch whose behaviour upstream now
provides, and tag the result.
