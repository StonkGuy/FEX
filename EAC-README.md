# FEX-Emu eac-2611

Branch `eac-2611` is **FEX-2611.1** ([`4f9c1f1`](https://github.com/FEX-Emu/FEX/commit/4f9c1f1e36443d22d7655477e34f51b95b685bf1))
**plus fidelity patches that let genuine Easy Anti-Cheat titles run under Proton on Arm64**: faithful `ptrace`,
signal, seccomp and `/proc` emulation where the anti-cheat launcher, Wine/Proton or a debugger observes it, and a few
performance and diagnostic changes found on the way. FEX's own [README.md](README.md) is unchanged.

Tested titles: VRChat is verified in game (EAC `301`, online session); Mini Royale's EAC launcher also reaches `301`.
Results differ from game to game — each title ships its own EAC build and checks — so an untested game may or may not
work.

**Like it? Help it along.** A star on the repository, an issue when something breaks (with your hardware and the
log), and pull requests are all welcome. If you keep a fork with a fix or an improvement, please open a pull request
against `eac-2611` too (with a test in `eac-tests/`): it gets reviewed, credited to you and shipped in the next tag.

Releases are tags on this branch (`eac-2611.1`); the earlier ones (`eac-2610.1` to `eac-2610.5`) are on branch `eac-2610`, on FEX-2610. Fixes merged after the latest tag ship in the next one. The write-up — why each patch exists, how it was found,
results and limits — is in the proof of concept,
[StonkGuy/eac-arm64-emulation-poc](https://github.com/StonkGuy/eac-arm64-emulation-poc)
([docs/patches.md](https://github.com/StonkGuy/eac-arm64-emulation-poc/blob/master/docs/patches.md)). This is a
standalone fork; it is not affiliated with FEX-Emu.

## Commits

One commit per patch, in order, on top of FEX-2611.1. The numbers are the PoC's patch numbers (0021 was withdrawn;
0027–0032, 0034 and 0040 are not part of this release). Since `eac-2610.2`, patches arrive through merged pull
requests, so the table is in commit order (`git log --no-merges --reverse`), not in number order.

| patch | commit | change |
|---|---|---|
| 0001 | `4863de9` | LinuxSyscalls: emulate x86-64 ptrace for tracees that also run under FEX |
| 0002 | `3543d3e` | SMC: stop write-protecting pages that keep faulting, verify their code in the JIT instead |
| 0003 | `09b1c8e` | Stats: account guest code-range invalidations |
| 0004 | `f22c6e7` | Skip the per-thread cache walk when an invalidated range holds no translated code |
| 0005 | `b409a79` | Add an in-process sampling profiler (FEX_PROFILESAMPLEHZ) |
| 0006 | `f935e81` | SamplingProfiler: add an all-thread snapshot |
| 0007 | `6a6142d` | Signals: run guest handlers with the Linux signal mask; optional signal trace |
| 0008 | `7bb5709` | Signals: do not leave InSyscallInfo set for a guest handler entered from a syscall handler |
| 0009 | `7e15d09` | SamplingProfiler: record the futex word in all-thread snapshots |
| 0010 | `2a30b4d` | Seccomp: report SECCOMP_RET_TRAP at the instruction after the syscall |
| 0011 | `0e5d20f` | arch_prctl: honour ARCH_SET_CPUID/ARCH_GET_CPUID |
| 0012 | `c704647` | ptrace: store the hardware debug registers instead of discarding them |
| 0013 | `a8c7048` | proc: report the emulated Seccomp: and TracerPid: in /proc/<pid>/status |
| 0014 | `8e6103b` | ptrace: answer unknown GETREGSET/SETREGSET types with -EINVAL, and serve NT_X86_XSTATE |
| 0015 | `510b8e5` | syscalls: restart_syscall returns -EINTR instead of aborting the process |
| 0016 | `8a5272d` | Signals: restore EFLAGS from the frame on rt_sigreturn even when RIP is unchanged |
| 0017 | `fd289af` | Signals: report the Linux 64-bit CS/SS selectors in the frame and to mov %cs/%ss |
| 0018 | `5218de2` | Signals: emit an XSAVE fpstate with the FP_XSTATE_MAGIC1/2 trailer on x86-64 |
| 0019 | `224b52d` | Signals: validate the guest frame destination before writing it |
| 0020 | `e9064cc` | Signals: write the interrupted mask into the frame's uc_sigmask |
| 0022 | `689f680` | Signals: return to the guest's own host stack level when rt_sigreturn abandons a syscall handler |
| 0023 | `fb58edf` | LinuxEmulation: deliver guest reads of the call/ret shadow-stack guard pages instead of spinning |
| 0024 | `223ccab` | SamplingProfiler: FEX_PROFILESAMPLEMINTHREADS and external SIGPROF snapshots |
| 0025 | `ff83240` | JIT: raise the single-step trap on the target of an IRETQ that loads TF, and never leave single-step mode through the lookup caches |
| 0026 | `fab7403` | Signals: keep the signal alt stack while a thread exits on it |
| 0033 | `13c7e36` | proc: list only the emulated process's mappings in /proc/<pid>/maps |
| 0035 | `9afe9bd` | SMC: code pages the guest makes writable stay writable for other processes (based on yungtry's patch 0028) |
| 0036 | `edd75d8` | Seccomp: never execute a trapped syscall, and force its SIGSYS like Linux |
| 0037 | `d9d6532` | SMC: write-protect a code page before publishing it as translated |
| 0041 | `70fd110` | Signals: put back the interrupted InSyscallInfo on every rt_sigreturn |
| 0042 | `048d8b6` | Syscalls: return EFAULT for bad user pointers in FEX's own handlers |
| 0043 | `6686fbb` | SignalTrace: unlink the /dev/shm ring on exit_group |
| 0044 | `579139a` | proc: check every I/O step of the synthesized /proc/<pid>/maps |
| 0045 | `fcea307` | LinuxSyscalls: make translated-code pages writable before a kernel write (#5874) |
| 0046 | `df5c698` | LinuxSyscalls: x86-64 munmap may cross 4 GiB (#5847) |
| 0047 | `f3481dc` | Ptrace: hide FEX's own SIGBUS alignment stops from the tracer |
| 0038 | `a15badb` | Syscalls: keep seccomp inheritance off the FEX_EXECVEFD path in execve |
| 0039 | `95ed879` | Syscalls: keep argv[0] for an FD execveat through the FEX loader |
| 0048 | `af4c4b8` | Seccomp: emulate Syscall User Dispatch |
| 0049 | `c66bf83` | Syscall User Dispatch: no designated initializer inside the syscall macro |
| 0050 | `7ac6be5` | FEXCore: keep the packed NZCV bytes out of reconstructed EFLAGS |
| 0051 | `76a104c` | Seccomp: only the trap's own SIGSYS resumes past the trapped syscall |
| 0052 | `1291646` | Seccomp: a Syscall User Dispatch SIGSYS also owns the trap's resume address |
| 0053 | `e9617e2` | Signals: reuse the host stack of abandoned seccomp/SUD trap frames |
| 0054 | `677c8ef` | FEXCore: IRET with RFLAGS.NT = 1 raises #GP |
| 0055 | `51c81db` | FEXCore: load FS and GS with MOV in 64-bit mode as Linux does |
| 0056 | `82751be` | DiskCache: a format version of the fork's own |
| 0060 | `a19786d` | Frontend: instructions longer than 15 bytes raise #GP(0) |
| 0065 | `297a6ae` | FEXCore: read guest code fault-safely while compiling |
| 0070 | `5aa38b0` | SMC: restart a faulting store only when it can reach the running block |
| 0071 | `e4dfb1c` | Signals: a seccomp/SUD trap frame never resumes the abandoned syscall handler on rt_sigreturn |

Not on `eac-2611`, because FEX-2611 provides them: 0059 and 0064 (fetch fault address of a split instruction:
upstream b65c96b75e, 511f58356e; their tests stay in `eac-tests/`), 0061 (XSETBV #GP: 61523a6db1), 0066 and 0067
(0F B8/BC/BD decode and its test: 68f4c5fbc4, 95a305bc4d). The disk-cache revisions 0057, 0062 and 0068 are folded
into 0056 (revision 1 on upstream version 43), and the InstCountCI updates 0058, 0063 and 0069 into one update
regenerated on this branch.

The other commits add [eac-tests/](eac-tests/), its CI workflow and this file; they touch nothing FEX builds.

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
so everyone gets the fix and the test suite covers it. FEX code changes go to [StonkGuy/FEX](https://github.com/StonkGuy/FEX) as a pull request against the current `eac-<release>` branch, with a test in its `eac-tests/`.

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

Each FEX release is handled the same way: rebase the patches onto it as branch `eac-<release>` of StonkGuy/FEX, run
`eac-tests` in the guest and natively for the oracle, check a live VRChat session, drop every patch whose behaviour
upstream now provides, and tag the result; the PoC and the steamac fork then pin the new tag.

