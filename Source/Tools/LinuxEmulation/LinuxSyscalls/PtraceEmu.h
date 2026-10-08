// SPDX-License-Identifier: MIT
/*
$info$
tags: LinuxSyscalls|PtraceEmu
desc: Guest-visible ptrace emulation for x86-64 tracees that are themselves running under FEX
$end_info$
*/
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <sys/types.h>

namespace FEXCore::Core {
struct CpuStateFrame;
}

/**
 * @file PtraceEmu.h
 *
 * Why this exists
 * ---------------
 * A debugger-style ptrace *tracer* (for example the Easy Anti-Cheat launcher that Proton runs, which
 * injects its client library into the game with ptrace) expects to see the x86-64 view of its tracee:
 * syscall entry/exit stops carrying x86-64 syscall numbers and registers, `struct user_regs_struct` in
 * x86-64 layout, PTRACE_EVENT_EXEC stops, `/proc/<pid>/exe` pointing at the guest binary and signal
 * delivery stops for guest `int3`.
 *
 * When tracer and tracee both run under FEX, the host kernel only sees FEX (aarch64) processes, so none
 * of that is true by default: host syscall stops report FEX's own host syscalls, host registers are
 * aarch64 registers and so on. FEX therefore *emulates* the x86-64 view:
 *
 *  - The tracee keeps a small `SharedState` block (registers, pending syscall, "dirty" mask ...).
 *  - The tracer's ptrace requests (PTRACE_SYSCALL, GETREGSET, SETREGSET, PEEKUSER, ...) are answered
 *    from that block, and writes the tracer makes are applied by the tracee when it resumes.
 *  - The tracee reports guest syscall boundaries by raising a host SIGSTOP on itself; the tracer's
 *    wait4() wrapper turns that host stop into a SIGTRAP|0x80 syscall stop (or into the guest signal
 *    stop that was requested).
 *
 * Limitations: only the main thread of a tracee is traced, PTRACE_ATTACH to an already running FEX
 * process is not emulated, and only the PTRACE_TRACEME / PTRACE_SYSCALL / PTRACE_CONT flow used by
 * launcher-style injectors is covered.
 */
namespace FEX::HLE::PtraceEmu {

/// Number of 64-bit slots in an x86-64 `struct user_regs_struct`.
constexpr unsigned NumUserRegs = 27;

/**
 * State block that lives inside the tracee and is read/written by the tracer.
 *
 * Tracer and tracee are always the same FEX binary, so the layout is private to FEX. The block is either
 * ordinary static storage of the tracee image (reachable by the tracer through ptrace PEEK/POKE once the
 * image's load address is known) or, for a PTRACE_TRACEME child before its exec, a file-backed shared page
 * that both sides map (the child is not dumpable, so the tracer cannot inspect its /proc/<pid>/maps).
 */
struct SharedState {
  static constexpr uint64_t MagicValue = 0xFE8E5E57CAFE0001ULL;

  volatile uint64_t Magic;
  volatile uint64_t SyscallStops; ///< Tracer resumed with PTRACE_SYSCALL: report syscall entry/exit stops
  volatile uint64_t Attached;     ///< This process is a ptrace tracee (PTRACE_TRACEME was called)
  volatile uint64_t Pending;      ///< Tracee is currently parked inside an emulated stop
  volatile uint64_t PendingIsEntry;
  volatile uint64_t PendingNr;
  volatile uint64_t PendingArgs[6];
  volatile uint64_t PendingRet;
  volatile uint64_t Regs[NumUserRegs]; ///< x86-64 user_regs_struct image at the stop
  volatile uint64_t DebugRegs[8];      ///< x86-64 DR0-DR7 shadow (DR4/DR5 do not exist; see PtraceEmu.cpp)
  volatile uint64_t DirtyMask;         ///< bit i set: the tracer wrote Regs[i]; apply it when resuming
  volatile uint64_t SignalNumber;      ///< Non-zero: the pending stop is a signal-delivery stop for this signal
  volatile uint64_t FlushAddr;         ///< The tracer wrote tracee memory: invalidate translated code here
  volatile uint64_t FlushLen;
  char ExePath[1024];                  ///< Guest path of the image the tracee is about to execve() (see RecordExecPath)
};

// ---------------------------------------------------------------------------------------------------
// Tracee side (the process that called PTRACE_TRACEME)
// ---------------------------------------------------------------------------------------------------

/// True while the tracer wants syscall stops and the calling thread is the tracee's main thread.
bool WantsSyscallStops();

/// Reports a syscall-entry stop. Returns the (possibly rewritten by the tracer) syscall number.
uint64_t SyscallEntryStop(FEXCore::Core::CpuStateFrame* Frame, uint64_t Nr, const uint64_t Args[6]);

/// Reports a syscall-exit stop. Returns the (possibly rewritten by the tracer) syscall result.
uint64_t SyscallExitStop(FEXCore::Core::CpuStateFrame* Frame, uint64_t Nr, const uint64_t Args[6], uint64_t Result);

/// A fork-like clone just returned 0 in the child: leave state shared with the parent.
void OnForkedChild(bool SharesAddressSpace);

/// Applies a pending "tracer wrote tracee memory" invalidation. Called when a syscall returns in a traced process, which
/// covers real (host) signal-delivery stops such as a guest kill(self, SIGSTOP), where no emulated stop happens.
void ApplyPendingFlush(FEXCore::Core::CpuStateFrame* Frame);

/// New RIP written by the tracer at the last syscall stop (0 if none). Consumed once.
uint64_t TakePendingRip();

/// Guest `int3` / SIGSEGV raised by the guest itself while traced: report it as a signal-delivery stop.
/// Returns true if the signal was consumed by the emulated stop (guest delivery must be skipped).
bool TryGuestSignalStop(FEXCore::Core::CpuStateFrame* Frame, int Signal);

/// execve() of a traced process: remember the guest path so the tracer can readlink /proc/<pid>/exe (which would
/// otherwise show the FEX binary). The path travels in the shared state page and is picked up at PTRACE_EVENT_EXEC.
void RecordExecPath(const std::string& GuestPath);

/// True if this process is a ptrace tracee.
bool IsAttached();

// ---------------------------------------------------------------------------------------------------
// Tracer side (the process that issues PTRACE_* requests)
// ---------------------------------------------------------------------------------------------------

/// Handles the ptrace requests whose x86-64 semantics FEX emulates. Returns true and fills *Result
/// (a guest-style return value, negative errno on failure) if the request was handled.
bool HandleRequest(int Request, pid_t Pid, void* Addr, void* Data, uint64_t* Result);

/// Post-processes a wait4() result. Returns true if the stop was FEX-internal (host SIGSEGV/SIGTRAP of a
/// tracee that FEX will handle itself) and the caller must wait again.
bool FixupWaitStatus(pid_t Pid, int* Status);

/// Guest path of the binary a traced FEX process exec()ed, if known (for readlink of /proc/<pid>/exe).
std::optional<std::string> TraceeExePath(pid_t Pid);

} // namespace FEX::HLE::PtraceEmu
