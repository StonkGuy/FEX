// SPDX-License-Identifier: MIT
/*
$info$
tags: LinuxSyscalls|PtraceEmu
desc: Guest-visible ptrace emulation for x86-64 tracees that are themselves running under FEX
$end_info$
*/

#include "LinuxSyscalls/PtraceEmu.h"
#include "LinuxSyscalls/Syscalls.h"

#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/X86Enums.h>

#include <elf.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <unordered_map>

namespace FEX::HLE::PtraceEmu {
namespace {
  // Layout of the x86-64 `struct user_regs_struct` (slot indices).
  enum UserReg : unsigned {
    R15, R14, R13, R12, Rbp, Rbx, R11, R10, R9, R8, Rax, Rcx, Rdx, Rsi, Rdi, OrigRax, Rip, Cs, Eflags, Rsp, Ss, FsBase, GsBase, Ds, Es, Fs, Gs,
  };
  static_assert(Gs + 1 == NumUserRegs);

  // The kernel's x86-64 `struct user` (arch/x86/include/asm/user_64.h) is 928 bytes: 27 register slots (216),
  // the i387/gdb bookkeeping area, then u_debugreg[8] at byte 848, error_code at 912 and fault_address at 920.
  // (glibc's struct user stops at 912 because it omits the last two fields, but it is the kernel's layout that
  // PTRACE_PEEKUSR/POKEUSR validate against.) Both requests reject a slot-unaligned offset and anything at or
  // past 928 with -EIO; only the register image and the DR range have handlers, and every other in-range offset
  // reads the initialised 0.
  constexpr uintptr_t UserDebugRegByteOffset = 848;
  constexpr uintptr_t UserDebugRegByteEnd = UserDebugRegByteOffset + 8 * sizeof(uint64_t); // 912
  constexpr uintptr_t UserStructSize = 928;

  // TASK_SIZE_MAX on x86-64 with 4-level paging, the boundary arch/x86/kernel/hw_breakpoint.c
  // arch_check_bp_in_kernelspace() tests a breakpoint address against.
  constexpr uint64_t UserTaskSizeMax = 0x00007ffffffff000ULL;

  // DR7 field encoding (arch/x86/include/uapi/asm/debugreg.h): the length is the high nibble, the type the low.
  // arch/x86/kernel/hw_breakpoint.c arch_bp_generic_fields() decodes these and rejects everything else; an
  // execute breakpoint must use the undefined length encoding (bits 7:6 set, low bits clear).
  bool DrFieldValid(uint64_t Field, uint64_t* AlignMask) {
    const uint64_t Len = Field & 0xC;
    switch (Field & 0x3) {
    case 0x0: // execute
      if (Len != 0x0) {
        return false;
      }
      *AlignMask = 0; // "len X": no alignment requirement
      return true;
    case 0x1: // write
    case 0x3: // read/write
      switch (Len) {
      case 0x0: *AlignMask = 0; return true; // len 1
      case 0x4: *AlignMask = 1; return true; // len 2
      case 0xC: *AlignMask = 3; return true; // len 4
      case 0x8: *AlignMask = 7; return true; // len 8
      default: return false;
      }
    default: // type 2 is reserved
      return false;
    }
  }

  constexpr unsigned DrEnableShift(unsigned N) { return N * 2; }
  constexpr unsigned DrFieldShift(unsigned N) { return 16 + N * 4; }

  // A DR0-DR3 address must be a user address below TASK_SIZE_MAX and meet the alignment implied by its length
  // (arch/x86/kernel/hw_breakpoint.c arch_check_bp_in_kernelspace() + hw_breakpoint_arch_parse()).
  bool DrAddressValid(uint64_t Addr, uint64_t AlignMask) {
    return Addr < UserTaskSizeMax && (Addr & AlignMask) == 0;
  }

  // arch/x86/kernel/ptrace.c ptrace_write_dr7(): a field with no enable bits and no already-registered breakpoint
  // is not validated at all; otherwise the kernel (re)registers the breakpoint, which validates the encoding
  // (arch_bp_generic_fields) and the address for the implied length. Any failure makes the whole write -EINVAL.
  // `Dr` is the shadow before the write; a slot the kernel never accepted holds 0.
  bool Dr7Valid(const uint64_t Dr[8], uint64_t NewDr7) {
    for (unsigned N = 0; N < 4; ++N) {
      const bool Enabled = (NewDr7 >> DrEnableShift(N)) & 0x3;
      const bool Registered = Dr[N] != 0;
      if (!Enabled && !Registered) {
        continue;
      }
      const uint64_t Field = (NewDr7 >> DrFieldShift(N)) & 0xF;
      uint64_t AlignMask = 0;
      if (!DrFieldValid(Field, &AlignMask) || !DrAddressValid(Dr[N], AlignMask)) {
        return false;
      }
    }
    return true;
  }

  constexpr uint16_t UserCodeSegment = 0x33;
  constexpr uint16_t UserStackSegment = 0x2b;
  constexpr uint64_t UserFlags = 0x246;
  constexpr uint64_t NoOverride = ~0ULL;

  // x86 request numbers that do not exist (or differ) in the host's <sys/ptrace.h>.
  constexpr int X86_PTRACE_GETREGS = 12;
  constexpr int X86_PTRACE_SETREGS = 13;
  constexpr int X86_PTRACE_EVENT_EXEC = 4;

  SharedState StaticState {SharedState::MagicValue};
  SharedState* Current = &StaticState;
  thread_local uint64_t PendingRip = 0;

  // A syscall entry whose exit stop never happened (rt_sigreturn, ...) is closed before the next entry.
  struct OpenSyscall {
    bool Open = false;
    uint64_t Nr {};
    uint64_t Args[6] {};
  } Previous;

  // ---------------------------------------------------------------------------------------------
  // Backing file of the shared state page of a PTRACE_TRACEME child. /dev/shm is tried first, /tmp is the fallback.
  // ---------------------------------------------------------------------------------------------
  constexpr const char* SidecarDirs[] = {"/dev/shm", "/tmp"};

  std::string SidecarPath(const char* Dir, const char* Kind, pid_t Pid) {
    return std::string(Dir) + "/fex-ptrace-" + Kind + "-" + std::to_string(Pid);
  }

  int OpenSidecar(const char* Kind, pid_t Pid, int Flags) {
    for (const char* Dir : SidecarDirs) {
      const int fd = ::open(SidecarPath(Dir, Kind, Pid).c_str(), Flags | O_CLOEXEC, 0600);
      if (fd >= 0) {
        return fd;
      }
    }
    return -1;
  }

  void RemoveSidecar(const char* Kind, pid_t Pid) {
    for (const char* Dir : SidecarDirs) {
      ::unlink(SidecarPath(Dir, Kind, Pid).c_str());
    }
  }

  bool IsMainThread() {
    return ::syscall(SYS_gettid) == ::getpid();
  }

  // True if a host tracer is attached to this process. If the tracer died without detaching we must not park
  // ourselves in a SIGSTOP that nobody will ever resume.
  bool HasHostTracer() {
    const int fd = ::open("/proc/self/status", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
      return true;
    }
    char Buf[2048];
    const ssize_t n = ::read(fd, Buf, sizeof(Buf) - 1);
    ::close(fd);
    if (n <= 0) {
      return true;
    }
    Buf[n] = 0;
    const char* Tag = strstr(Buf, "TracerPid:");
    return !Tag || atoi(Tag + sizeof("TracerPid:") - 1) != 0;
  }

  // ---------------------------------------------------------------------------------------------
  // Tracee side
  // ---------------------------------------------------------------------------------------------

  // Builds the x86-64 user_regs_struct image of the guest at a syscall boundary.
  void BuildRegs(const FEXCore::Core::CpuStateFrame* Frame, uint64_t Nr, bool Entry, uint64_t Ret, uint64_t* X) {
    using namespace FEXCore::X86State;
    const auto& S = Frame->State;
    X[R15] = S.gregs[REG_R15];
    X[R14] = S.gregs[REG_R14];
    X[R13] = S.gregs[REG_R13];
    X[R12] = S.gregs[REG_R12];
    X[Rbp] = S.gregs[REG_RBP];
    X[Rbx] = S.gregs[REG_RBX];
    X[R11] = UserFlags; // `syscall` leaves RFLAGS in r11
    X[R10] = S.gregs[REG_R10];
    X[R9] = S.gregs[REG_R9];
    X[R8] = S.gregs[REG_R8];
    X[Rax] = Entry ? static_cast<uint64_t>(-ENOSYS) : Ret;
    X[Rcx] = S.gregs[REG_RCX];
    X[Rdx] = S.gregs[REG_RDX];
    X[Rsi] = S.gregs[REG_RSI];
    X[Rdi] = S.gregs[REG_RDI];
    X[OrigRax] = Nr;
    X[Rip] = S.gregs[REG_RCX] ? S.gregs[REG_RCX] : S.rip; // `syscall` leaves the return address in rcx
    X[Cs] = UserCodeSegment;
    X[Eflags] = UserFlags;
    X[Rsp] = S.gregs[REG_RSP];
    X[Ss] = UserStackSegment;
    X[FsBase] = S.fs_cached;
    X[GsBase] = S.gs_cached;
    X[Ds] = X[Es] = X[Fs] = X[Gs] = 0;
  }

  // Parks the tracee until the tracer resumes it. The host SIGSTOP is what the tracer's wait4() observes.
  void Stop(uint64_t Nr, const uint64_t Args[6], bool Entry, uint64_t Ret, const uint64_t* Regs) {
    SharedState& S = *Current;
    if (!HasHostTracer()) {
      S.SyscallStops = 0;
      S.Attached = 0;
      return;
    }
    for (unsigned i = 0; i < NumUserRegs; ++i) {
      S.Regs[i] = Regs[i];
    }
    S.PendingNr = Nr;
    for (unsigned i = 0; i < 6; ++i) {
      S.PendingArgs[i] = Args[i];
    }
    S.PendingRet = Ret;
    S.PendingIsEntry = Entry ? 1 : 0;
    S.Pending = 1;
    ::syscall(SYS_tgkill, ::getpid(), ::syscall(SYS_gettid), SIGSTOP);
    S.Pending = 0;
  }

  // Applies what the tracer wrote while we were stopped. Returns the syscall result the tracer forced at an
  // exit stop (or NoOverride).
  uint64_t ApplyTracerWrites(FEXCore::Core::CpuStateFrame* Frame, bool Entry) {
    using namespace FEXCore::X86State;
    SharedState& S = *Current;

    if (S.FlushLen) {
      // The tracer poked guest memory through ptrace; FEX's translated code cache cannot see that.
      const uint64_t Addr = S.FlushAddr;
      const uint64_t Len = S.FlushLen;
      S.FlushLen = 0;
      FEX::HLE::_SyscallHandler->InvalidateGuestCodeRange(Frame->Thread, Addr, Len);
    }

    const uint64_t Dirty = S.DirtyMask;
    if (!Dirty) {
      return NoOverride;
    }

    // user_regs_struct slot -> FEX gpr index (r11 and rax are special cased)
    static constexpr int Map[15] = {REG_R15, REG_R14, REG_R13, REG_R12, REG_RBP, REG_RBX, -1, REG_R10, REG_R9, REG_R8, -1, REG_RCX, REG_RDX, REG_RSI, REG_RDI};
    auto& State = Frame->State;
    uint64_t Override = NoOverride;
    for (unsigned i = 0; i < NumUserRegs; ++i) {
      if (!(Dirty & (1ULL << i))) {
        continue;
      }
      const uint64_t V = S.Regs[i];
      if (i < 15) {
        if (Map[i] >= 0) {
          State.gregs[Map[i]] = V;
        }
      } else if (i == Rip) {
        PendingRip = V;
      } else if (i == Rsp) {
        State.gregs[REG_RSP] = V;
      } else if (i == FsBase) {
        State.fs_cached = V;
      } else if (i == GsBase) {
        State.gs_cached = V;
      }
      if (i == Rax && !Entry) {
        Override = V; // exit stop: the tracer forges the syscall result
      }
      // At an entry stop rax is the -ENOSYS placeholder: writing it (a GETREGS/SETREGS round trip does) selects
      // nothing. The syscall that runs is orig_rax, applied below.
      // cs/ss/eflags/ds/es/fs/gs and orig_rax (handled below) are accepted and ignored
    }
    if (Entry && (Dirty & (1ULL << OrigRax))) {
      State.gregs[REG_RAX] = S.Regs[OrigRax]; // on Linux orig_rax selects the syscall that runs
    }
    S.DirtyMask = 0;
    return Override;
  }

  // Maps the shared state block that a PTRACE_TRACEME child publishes for its tracer.
  void PublishSharedPage() {
    if (Current != &StaticState) {
      return;
    }
    const int fd = OpenSidecar("state", ::getpid(), O_RDWR | O_CREAT | O_TRUNC);
    if (fd < 0) {
      return;
    }
    if (::ftruncate(fd, 4096) == 0) {
      void* Page = ::mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
      if (Page != MAP_FAILED) {
        std::memcpy(Page, &StaticState, sizeof(SharedState));
        Current = static_cast<SharedState*>(Page);
      }
    }
    ::close(fd);
  }

  // ---------------------------------------------------------------------------------------------
  // Tracer side: access to the state block of another FEX process
  // ---------------------------------------------------------------------------------------------
  struct Remote {
    uint8_t* Mapped = nullptr;  // tracee published a shared page (PTRACE_TRACEME child before its exec)
    uintptr_t StaticAddr = 0;   // otherwise: address of the tracee image's static SharedState
    std::array<uint8_t, 512> FpRegs {}; // shadow of the tracee's x87/SSE state for NT_PRFPREG round trips
    bool FpValid = false;
  };
  std::mutex RemotesLock;
  std::unordered_map<pid_t, Remote> Remotes;
  std::unordered_map<pid_t, std::string> ExePaths; // guest exe path of tracees that already exec()ed

  uintptr_t FindFexImageBase(pid_t Pid) {
    static const std::string SelfExe = []() {
      char Buf[512];
      const ssize_t n = ::readlink("/proc/self/exe", Buf, sizeof(Buf) - 1);
      return n > 0 ? std::string(Buf, n) : std::string();
    }();
    if (SelfExe.empty()) {
      return 0;
    }
    const std::string Maps = Pid ? "/proc/" + std::to_string(Pid) + "/maps" : "/proc/self/maps";
    FILE* F = fopen(Maps.c_str(), "r");
    if (!F) {
      return 0;
    }
    char Line[1024];
    uintptr_t Lowest = 0;
    while (fgets(Line, sizeof(Line), F)) {
      if (!strstr(Line, SelfExe.c_str())) {
        continue;
      }
      unsigned long long Start = 0, End = 0, Offset = 0;
      if (sscanf(Line, "%llx-%llx %*s %llx", &Start, &End, &Offset) == 3 && Offset == 0 && (!Lowest || Start < Lowest)) {
        Lowest = Start;
      }
    }
    fclose(F);
    return Lowest;
  }

  // Finds (or establishes) how to reach the state block of `Pid`. Failures are not cached.
  Remote* Lookup(pid_t Pid) {
    auto It = Remotes.find(Pid);
    if (It != Remotes.end()) {
      return &It->second;
    }
    Remote R;
    const int fd = OpenSidecar("state", Pid, O_RDWR);
    if (fd >= 0) {
      void* Page = ::mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
      ::close(fd);
      if (Page != MAP_FAILED) {
        R.Mapped = static_cast<uint8_t*>(Page);
      }
    }
    if (!R.Mapped) {
      static const uintptr_t SelfBase = FindFexImageBase(0);
      const uintptr_t TraceeBase = FindFexImageBase(Pid);
      if (!SelfBase || !TraceeBase) {
        return nullptr;
      }
      R.StaticAddr = TraceeBase + (reinterpret_cast<uintptr_t>(&StaticState) - SelfBase);
    }
    return &Remotes.emplace(Pid, std::move(R)).first->second;
  }

  // Drops how `Pid`'s state block was reached (it exec()ed, was detached or exited). The recorded exe path is kept
  // until the process is gone, since a tracer may still readlink /proc/<pid>/exe after detaching.
  void Forget(pid_t Pid, bool Exited) {
    std::lock_guard lk(RemotesLock);
    auto It = Remotes.find(Pid);
    if (It != Remotes.end()) {
      if (It->second.Mapped) {
        ::munmap(It->second.Mapped, 4096);
      }
      Remotes.erase(It);
    }
    RemoveSidecar("state", Pid);
    if (Exited) {
      ExePaths.erase(Pid);
    }
  }

  // At PTRACE_EVENT_EXEC the old image (and with it the shared state page it published) is about to be dropped:
  // take the path of the new image out of that page.
  void CaptureExecPath(pid_t Pid) {
    std::lock_guard lk(RemotesLock);
    Remote* R = Lookup(Pid);
    if (R && R->Mapped) {
      auto* S = reinterpret_cast<SharedState*>(R->Mapped);
      if (S->Magic == SharedState::MagicValue && S->ExePath[0]) {
        ExePaths[Pid] = std::string(S->ExePath, strnlen(S->ExePath, sizeof(S->ExePath)));
      }
    }
  }

  uint64_t HostPtrace(int Request, pid_t Pid, void* Addr, void* Data) {
    const long R = ::syscall(SYS_ptrace, Request, Pid, Addr, Data);
    return R == -1 ? static_cast<uint64_t>(-errno) : static_cast<uint64_t>(R);
  }

  bool ReadWord(pid_t Pid, size_t Offset, uint64_t* Out) {
    std::lock_guard lk(RemotesLock);
    Remote* R = Lookup(Pid);
    if (!R) {
      return false;
    }
    if (R->Mapped) {
      *Out = *reinterpret_cast<volatile uint64_t*>(R->Mapped + Offset);
      return true;
    }
    return ::syscall(SYS_ptrace, PTRACE_PEEKDATA, Pid, R->StaticAddr + Offset, Out) == 0;
  }

  bool WriteWord(pid_t Pid, size_t Offset, uint64_t Value) {
    std::lock_guard lk(RemotesLock);
    Remote* R = Lookup(Pid);
    if (!R) {
      return false;
    }
    if (R->Mapped) {
      *reinterpret_cast<volatile uint64_t*>(R->Mapped + Offset) = Value;
      return true;
    }
    return ::syscall(SYS_ptrace, PTRACE_POKEDATA, Pid, R->StaticAddr + Offset, Value) == 0;
  }

  // True if `Pid` is a FEX process whose state block is reachable (the magic matches).
  bool IsFexTracee(pid_t Pid) {
    uint64_t Magic = 0;
    return ReadWord(Pid, offsetof(SharedState, Magic), &Magic) && Magic == SharedState::MagicValue;
  }

  bool ReadSlot(pid_t Pid, size_t Offset, uint64_t* Out) {
    return ReadWord(Pid, Offset, Out);
  }

  void MarkDirty(pid_t Pid, uint64_t Mask) {
    uint64_t Dirty = 0;
    ReadWord(Pid, offsetof(SharedState, DirtyMask), &Dirty);
    WriteWord(Pid, offsetof(SharedState, DirtyMask), Dirty | Mask);
  }

  constexpr size_t RegOffset(unsigned Index) {
    return offsetof(SharedState, Regs) + Index * sizeof(uint64_t);
  }

  // Reads DR<n>. There are no DR4/DR5 registers: ptrace_get_debugreg returns 0 for them.
  bool ReadDebugReg(pid_t Pid, unsigned N, uint64_t* Out) {
    if (N == 4 || N == 5) {
      *Out = 0;
      return true;
    }
    if (N > 7) {
      return false;
    }
    return ReadWord(Pid, offsetof(SharedState, DebugRegs) + N * sizeof(uint64_t), Out);
  }

  // Writes DR<n>, mirroring arch/x86/kernel/ptrace.c ptrace_set_debugreg(). Returns 0 on success or the negative
  // errno the kernel uses.
  int WriteDebugReg(pid_t Pid, unsigned N, uint64_t Value) {
    if (N == 4 || N == 5) {
      return -EIO; // "There are no DR4 or DR5 registers"
    }
    if (N <= 3) {
      // A slot that is not yet a breakpoint is registered with the kernel's default len-1 write shape, which
      // imposes no alignment, so only the address itself is checked. An already-registered slot was created the
      // same way (the length only changes through DR7), so the alignment requirement is still none.
      if (!DrAddressValid(Value, 0)) {
        return -EINVAL;
      }
      return WriteWord(Pid, offsetof(SharedState, DebugRegs) + N * sizeof(uint64_t), Value) ? 0 : -ESRCH;
    }
    if (N == 6) {
      // The kernel stores DR6 raw (virtual_dr6 ^ DR6_RESERVED) and reads it back XORed again, so it round-trips.
      return WriteWord(Pid, offsetof(SharedState, DebugRegs) + 6 * sizeof(uint64_t), Value) ? 0 : -ESRCH;
    }
    // N == 7: validate against the current shadow, then store the raw value as the kernel does.
    uint64_t Dr[8] {};
    for (unsigned I = 0; I < 8; ++I) {
      if (!ReadWord(Pid, offsetof(SharedState, DebugRegs) + I * sizeof(uint64_t), &Dr[I])) {
        return -ESRCH;
      }
    }
    if (!Dr7Valid(Dr, Value)) {
      return -EINVAL;
    }
    return WriteWord(Pid, offsetof(SharedState, DebugRegs) + 7 * sizeof(uint64_t), Value) ? 0 : -ESRCH;
  }

  Remote* FpState(pid_t Pid) {
    std::lock_guard lk(RemotesLock);
    Remote* R = Lookup(Pid);
    if (R && !R->FpValid) {
      // Power-on x87/SSE state: FCW=0x37f, MXCSR=0x1f80 and mask 0xffff
      const uint16_t Fcw = 0x37f;
      const uint32_t Mxcsr = 0x1f80, MxcsrMask = 0xffff;
      std::memcpy(&R->FpRegs[0], &Fcw, sizeof(Fcw));
      std::memcpy(&R->FpRegs[24], &Mxcsr, sizeof(Mxcsr));
      std::memcpy(&R->FpRegs[28], &MxcsrMask, sizeof(MxcsrMask));
      R->FpValid = true;
    }
    return R;
  }
} // namespace

// -----------------------------------------------------------------------------------------------------
// Tracee side
// -----------------------------------------------------------------------------------------------------

bool IsAttached() {
  return Current->Attached != 0;
}

bool WantsSyscallStops() {
  return Current->SyscallStops && IsMainThread();
}

uint64_t SyscallEntryStop(FEXCore::Core::CpuStateFrame* Frame, uint64_t Nr, const uint64_t Args[6]) {
  uint64_t Regs[NumUserRegs];
  if (Previous.Open) {
    BuildRegs(Frame, Previous.Nr, false, 0, Regs);
    Stop(Previous.Nr, Previous.Args, false, 0, Regs);
  }
  BuildRegs(Frame, Nr, true, 0, Regs);
  Stop(Nr, Args, true, 0, Regs);
  ApplyTracerWrites(Frame, true);

  // The tracer may have rewritten orig_rax: that is the syscall that must run.
  const uint64_t NewNr = Frame->State.gregs[FEXCore::X86State::REG_RAX];
  // If the tracer resumed with PTRACE_CONT instead of PTRACE_SYSCALL the exit of this syscall is never reported, so
  // it must not stay open: a later PTRACE_SYSCALL would start with a stale exit stop for it.
  Previous.Open = Current->SyscallStops != 0;
  Previous.Nr = NewNr;
  std::copy(Args, Args + 6, Previous.Args);
  return NewNr;
}

uint64_t SyscallExitStop(FEXCore::Core::CpuStateFrame* Frame, uint64_t Nr, const uint64_t Args[6], uint64_t Result) {
  uint64_t Regs[NumUserRegs];
  BuildRegs(Frame, Nr, false, Result, Regs);
  Stop(Nr, Args, false, Result, Regs);
  const uint64_t Override = ApplyTracerWrites(Frame, false);
  Previous.Open = false;
  return Override != NoOverride ? Override : Result;
}

void OnForkedChild(bool SharesAddressSpace) {
  if (SharesAddressSpace) {
    return; // a thread: the state block is shared with the (still traced) parent
  }
  // A forked child is not traced: leave the parent's shared page and drop the inherited flags.
  Current = &StaticState;
  StaticState.SyscallStops = 0;
  StaticState.Attached = 0;
  StaticState.Pending = 0;
  Previous.Open = false;
}

void ApplyPendingFlush(FEXCore::Core::CpuStateFrame* Frame) {
  SharedState& S = *Current;
  if (S.FlushLen) {
    const uint64_t Addr = S.FlushAddr;
    const uint64_t Len = S.FlushLen;
    S.FlushLen = 0;
    FEX::HLE::_SyscallHandler->InvalidateGuestCodeRange(Frame->Thread, Addr, Len);
  }
}

uint64_t TakePendingRip() {
  const uint64_t Rip = PendingRip;
  PendingRip = 0;
  return Rip;
}

bool TryGuestSignalStop(FEXCore::Core::CpuStateFrame* Frame, int Signal) {
  if (Signal != SIGTRAP && Signal != SIGSEGV) {
    return false;
  }
  if (!Frame->SynchronousFaultData.FaultToTopAndGeneratedException || !Current->Attached || !IsMainThread()) {
    return false;
  }

  uint64_t Regs[NumUserRegs];
  const uint64_t NoArgs[6] {};
  BuildRegs(Frame, ~0ULL, false, Frame->State.gregs[FEXCore::X86State::REG_RAX], Regs);
  Regs[Rip] = Frame->State.rip; // for int3 FEX already points at the next instruction, which matches Linux

  Current->SignalNumber = static_cast<uint64_t>(Signal);
  Stop(~0ULL, NoArgs, false, 0, Regs);
  Current->SignalNumber = 0;

  const uint64_t Override = ApplyTracerWrites(Frame, false);
  if (Override != NoOverride) {
    Frame->State.gregs[FEXCore::X86State::REG_RAX] = Override;
  }
  if (const uint64_t NewRip = TakePendingRip()) {
    Frame->State.rip = NewRip;
  }
  return true;
}

void RecordExecPath(const std::string& GuestPath) {
  if (!Current->Attached) {
    return;
  }
  const size_t Len = std::min(GuestPath.size(), sizeof(Current->ExePath) - 1);
  std::memcpy(Current->ExePath, GuestPath.data(), Len);
  Current->ExePath[Len] = 0;
}

// -----------------------------------------------------------------------------------------------------
// Tracer side
// -----------------------------------------------------------------------------------------------------

std::optional<std::string> TraceeExePath(pid_t Pid) {
  if (Pid <= 0 || Pid == ::getpid()) {
    return std::nullopt;
  }
  std::lock_guard lk(RemotesLock);
  auto It = ExePaths.find(Pid);
  return It != ExePaths.end() ? std::optional<std::string>(It->second) : std::nullopt;
}

bool FixupWaitStatus(pid_t Pid, int* Status) {
  if (!Status || Pid <= 0) {
    return false;
  }
  const int St = *Status;

  if (WIFEXITED(St) || WIFSIGNALED(St)) {
    Forget(Pid, true);
    return false;
  }
  if (!WIFSTOPPED(St)) {
    return false;
  }

  // SIGTRAP / SIGSEGV signal-delivery stops of a FEX tracee come from the host kernel: they are either a
  // guest int3 (FEX turns it into an emulated stop once the signal is re-injected) or an SMC write fault that
  // FEX handles internally. Neither must be visible to the tracer.
  if ((St >> 16) == 0 && (WSTOPSIG(St) == SIGTRAP || WSTOPSIG(St) == SIGSEGV) && IsFexTracee(Pid)) {
    HostPtrace(PTRACE_CONT, Pid, nullptr, reinterpret_cast<void*>(static_cast<uintptr_t>(WSTOPSIG(St))));
    return true;
  }

  if ((St >> 16) == 0 && WSTOPSIG(St) == SIGPROF && IsFexTracee(Pid)) {
    // FEX's own sampling profiler signal: never visible to the guest tracer.
    HostPtrace(PTRACE_CONT, Pid, nullptr, nullptr);
    return true;
  }

  if ((St >> 16) == X86_PTRACE_EVENT_EXEC) {
    // The tracee is now a fresh FEX image: keep the new image's path, drop the old image's state page.
    CaptureExecPath(Pid);
    Forget(Pid, false);
  }

  if (WSTOPSIG(St) == SIGSTOP) {
    uint64_t Pending = 0;
    if (ReadWord(Pid, offsetof(SharedState, Pending), &Pending) && Pending) {
      uint64_t Signal = 0;
      ReadWord(Pid, offsetof(SharedState, SignalNumber), &Signal);
      // Emulated syscall stop (SIGTRAP|0x80 because of PTRACE_O_TRACESYSGOOD) or the requested signal stop.
      *Status = (St & ~0xff00) | (static_cast<int>(Signal ? Signal : (SIGTRAP | 0x80)) << 8);
    }
  }
  return false;
}

bool HandleRequest(int Request, pid_t Pid, void* Addr, void* Data, uint64_t* Result) {
  switch (Request) {
  case PTRACE_TRACEME:
    *Result = HostPtrace(Request, Pid, Addr, Data);
    if (*Result == 0) {
      // Only a process that really became a tracee publishes its state: a failing PTRACE_TRACEME (already traced,
      // the common anti-debug probe) has no tracer that would ever remove the /dev/shm file again.
      PublishSharedPage();
      Current->Attached = 1;
    }
    return true;

  case PTRACE_KILL:
  case PTRACE_SEIZE:
  case PTRACE_INTERRUPT:
  case PTRACE_SETOPTIONS:
  case PTRACE_GETEVENTMSG:
  case PTRACE_SINGLESTEP:
  case PTRACE_GETSIGINFO: *Result = HostPtrace(Request, Pid, Addr, Data); return true;

  case PTRACE_POKETEXT:
  case PTRACE_POKEDATA: {
    *Result = HostPtrace(Request, Pid, Addr, Data);
    if (*Result == 0 && IsFexTracee(Pid)) {
      // Remember the touched range so the tracee invalidates its translated code when it resumes.
      const uint64_t Lo = reinterpret_cast<uint64_t>(Addr) & ~0xfffULL;
      const uint64_t Hi = Lo + 0x2000;
      uint64_t OldAddr = 0, OldLen = 0;
      ReadWord(Pid, offsetof(SharedState, FlushAddr), &OldAddr);
      ReadWord(Pid, offsetof(SharedState, FlushLen), &OldLen);
      uint64_t NewLo = Lo, NewHi = Hi;
      if (OldLen) {
        NewLo = std::min(OldAddr, Lo);
        NewHi = std::max(OldAddr + OldLen, Hi);
      }
      WriteWord(Pid, offsetof(SharedState, FlushAddr), NewLo);
      WriteWord(Pid, offsetof(SharedState, FlushLen), NewHi - NewLo);
    }
    return true;
  }

  case PTRACE_CONT:
  case PTRACE_SYSCALL: {
    // The host only knows PTRACE_CONT: the syscall stops are produced by the tracee itself.
    uint64_t Magic = 0;
    if (ReadWord(Pid, offsetof(SharedState, Magic), &Magic) && Magic == SharedState::MagicValue) {
      WriteWord(Pid, offsetof(SharedState, SyscallStops), Request == PTRACE_SYSCALL ? 1 : 0);
      WriteWord(Pid, offsetof(SharedState, Attached), 1);
    }
    *Result = HostPtrace(PTRACE_CONT, Pid, Addr, Data);
    return true;
  }

  case PTRACE_DETACH: {
    // The tracee must stop emulating stops once it is detached.
    if (IsFexTracee(Pid)) {
      WriteWord(Pid, offsetof(SharedState, SyscallStops), 0);
      WriteWord(Pid, offsetof(SharedState, Attached), 0);
    }
    *Result = HostPtrace(Request, Pid, Addr, Data);
    Forget(Pid, false);
    return true;
  }

  case PTRACE_PEEKUSER: {
    const uintptr_t Off = reinterpret_cast<uintptr_t>(Addr);
    // Mirror arch/x86/kernel/ptrace.c PTRACE_PEEKUSR: a slot-unaligned offset or one at/after sizeof(struct
    // user) is -EIO; the register image and the DR range are served; every other in-struct offset reads the
    // initialised 0.
    if ((Off % sizeof(uint64_t)) != 0 || Off >= UserStructSize) {
      *Result = static_cast<uint64_t>(-EIO);
      return true;
    }
    uint64_t V = 0;
    if (Off < NumUserRegs * sizeof(uint64_t)) {
      if (!ReadSlot(Pid, RegOffset(Off / 8), &V)) {
        *Result = static_cast<uint64_t>(-ESRCH);
        return true;
      }
    } else if (Off >= UserDebugRegByteOffset && Off < UserDebugRegByteEnd) {
      if (!ReadDebugReg(Pid, static_cast<unsigned>((Off - UserDebugRegByteOffset) / sizeof(uint64_t)), &V)) {
        *Result = static_cast<uint64_t>(-ESRCH);
        return true;
      }
    }
    *static_cast<uint64_t*>(Data) = V;
    *Result = 0;
    return true;
  }

  case PTRACE_POKEUSER: {
    const uintptr_t Off = reinterpret_cast<uintptr_t>(Addr);
    // Mirror arch/x86/kernel/ptrace.c PTRACE_POKEUSR: a slot-unaligned offset or one at/after sizeof(struct
    // user) is -EIO; the register image is written; the DR range goes through ptrace_set_debugreg (which stores
    // DR0-DR3/DR6/DR7, rejects DR4/DR5 with -EIO and validates DR0-DR3 and DR7 with -EINVAL); every other
    // in-struct offset has no handler and is -EIO.
    if ((Off % sizeof(uint64_t)) != 0 || Off >= UserStructSize) {
      *Result = static_cast<uint64_t>(-EIO);
      return true;
    }
    if (Off < NumUserRegs * sizeof(uint64_t)) {
      if (!WriteWord(Pid, RegOffset(Off / 8), reinterpret_cast<uint64_t>(Data))) {
        *Result = static_cast<uint64_t>(-ESRCH);
        return true;
      }
      MarkDirty(Pid, 1ULL << (Off / 8));
      *Result = 0;
      return true;
    }
    if (Off >= UserDebugRegByteOffset && Off < UserDebugRegByteEnd) {
      *Result = static_cast<uint64_t>(WriteDebugReg(Pid, static_cast<unsigned>((Off - UserDebugRegByteOffset) / sizeof(uint64_t)), reinterpret_cast<uint64_t>(Data)));
      return true;
    }
    *Result = static_cast<uint64_t>(-EIO);
    return true;
  }

  case X86_PTRACE_GETREGS: {
    for (unsigned i = 0; i < NumUserRegs; ++i) {
      uint64_t V = 0;
      if (!ReadSlot(Pid, RegOffset(i), &V)) {
        *Result = static_cast<uint64_t>(-ESRCH);
        return true;
      }
      static_cast<uint64_t*>(Data)[i] = V;
    }
    *Result = 0;
    return true;
  }

  case X86_PTRACE_SETREGS: {
    uint64_t Mask = 0;
    for (unsigned i = 0; i < NumUserRegs; ++i) {
      if (!WriteWord(Pid, RegOffset(i), static_cast<const uint64_t*>(Data)[i])) {
        *Result = static_cast<uint64_t>(-ESRCH);
        return true;
      }
      Mask |= 1ULL << i;
    }
    MarkDirty(Pid, Mask);
    *Result = 0;
    return true;
  }

  case PTRACE_GETREGSET:
  case PTRACE_SETREGSET: {
    const auto NtType = reinterpret_cast<uintptr_t>(Addr);
    auto* Iov = static_cast<struct iovec*>(Data);
    if (!Iov) {
      return false;
    }
    const bool Get = Request == PTRACE_GETREGSET;

    if (NtType == NT_PRSTATUS) {
      if (Get) {
        uint64_t Image[NumUserRegs];
        for (unsigned i = 0; i < NumUserRegs; ++i) {
          if (!ReadSlot(Pid, RegOffset(i), &Image[i])) {
            *Result = static_cast<uint64_t>(-ESRCH);
            return true;
          }
        }
        const size_t Len = std::min(Iov->iov_len, sizeof(Image));
        std::memcpy(Iov->iov_base, Image, Len);
        Iov->iov_len = Len;
      } else {
        const size_t Slots = std::min<size_t>(Iov->iov_len / sizeof(uint64_t), NumUserRegs);
        uint64_t Mask = 0;
        for (size_t i = 0; i < Slots; ++i) {
          if (!WriteWord(Pid, RegOffset(i), static_cast<const uint64_t*>(Iov->iov_base)[i])) {
            *Result = static_cast<uint64_t>(-ESRCH);
            return true;
          }
          Mask |= 1ULL << i;
        }
        MarkDirty(Pid, Mask);
        Iov->iov_len = NumUserRegs * sizeof(uint64_t);
      }
      *Result = 0;
      return true;
    }

    if (NtType == NT_PRFPREG) {
      // FEX does not expose the tracee's vector state: keep a shadow so Get-after-Set round trips work.
      Remote* R = FpState(Pid);
      if (!R) {
        *Result = static_cast<uint64_t>(-ESRCH);
        return true;
      }
      const size_t Len = std::min(Iov->iov_len, R->FpRegs.size());
      if (Get) {
        std::memcpy(Iov->iov_base, R->FpRegs.data(), Len);
      } else {
        std::memcpy(R->FpRegs.data(), Iov->iov_base, Len);
      }
      Iov->iov_len = Len;
      *Result = 0;
      return true;
    }
    return false;
  }

  default: return false;
  }
}

} // namespace FEX::HLE::PtraceEmu
