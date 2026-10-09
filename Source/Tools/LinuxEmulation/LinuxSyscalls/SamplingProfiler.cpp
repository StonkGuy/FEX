// SPDX-License-Identifier: MIT
#include "LinuxSyscalls/SamplingProfiler.h"
#include "LinuxSyscalls/SignalDelegator.h"
#include "LinuxSyscalls/PtraceEmu.h"
#include "ArchHelpers/MContext.h"

#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Debug/InternalThreadState.h>

#include <atomic>
#include <csignal>
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

namespace FEX::HLE {
namespace {
  struct Sample {
    uint64_t HostPC;
    uint64_t Info; ///< low 32 bits: host tid, high 32 bits: low half of the last guest RIP stored in the thread state
  };
  constexpr size_t MaxSamples = 1 << 18; // 4 MiB
  std::atomic<Sample*> RecordsPtr {nullptr};
  Sample* Records = nullptr;
  std::atomic<uint32_t> Count {0};

  // Snapshot mode (`/dev/shm/fex-<pid>-snapshot`): every thread of the process is signalled once and stores its x86 state, which
  // includes threads blocked in system calls that the sampler above skips. Used to find what a wedged thread is waiting in.
  struct SnapRecord {
    uint64_t Tid;
    uint64_t HostPC;
    uint64_t Rip;
    uint64_t FutexWord;     ///< bit 63 set when the thread is blocked in futex/futex_waitv; low 32 bits: the futex word at snapshot time
    uint64_t FutexExpected; ///< the value the wait was started with
    uint64_t FutexAddr;     ///< futex address (futex_waitv: of the first waiter)
    uint64_t Gregs[16];     ///< x86 order: rax rcx rdx rbx rsp rbp rsi rdi r8-r15
    uint64_t Stack[138];    ///< guest stack at rsp
  };
  static_assert(sizeof(SnapRecord) == 160 * 8);
  constexpr size_t MaxSnaps = 1024;
  SnapRecord* Snaps = nullptr;
  std::atomic<uint32_t> SnapCount {0};
  std::atomic<bool> SnapMode {false};
  // External mode (FEX_PROFILESAMPLEMINTHREADS=0): no sampler thread at all; every SIGPROF sent from outside (kill -PROF <pid>)
  // stores one snapshot record of the receiving thread into a ring in /dev/shm/fex-<pid>-snap. For processes that must not
  // grow an extra thread. FutexAddr holds the interrupted host SP, FutexExpected the sequence number.
  bool ExternalMode = false;
  FEX::HLE::SignalDelegator* Delegator = nullptr;
  std::atomic<bool> ExternalOpen {false};

  void OpenExternalSnaps() {
    if (ExternalOpen.exchange(true)) {
      return;
    }
    char Path[64];
    snprintf(Path, sizeof(Path), "/dev/shm/fex-%d-snap", static_cast<int>(getpid()));
    const int fd = open(Path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0 || ftruncate(fd, sizeof(SnapRecord) * MaxSnaps) != 0) {
      return;
    }
    void* Map = mmap(nullptr, sizeof(SnapRecord) * MaxSnaps, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (Map != MAP_FAILED) {
      Snaps = static_cast<SnapRecord*>(Map);
    }
  }

  // Threads worth sampling in "all threads" mode: the busy-prone ones. A process has hundreds of mostly idle threads
  // (Unity workers, thread pools); signalling all of them at the sampling rate would perturb what is measured. Samples
  // are taken from threads whose utime+stime advanced since the previous round.
  bool IsInteresting(pid_t Tid) {
    static thread_local std::unordered_map<pid_t, uint64_t> Last;
    char Path[64];
    snprintf(Path, sizeof(Path), "/proc/self/task/%d/stat", Tid);
    FILE* F = fopen(Path, "r");
    if (!F) {
      return false;
    }
    char Buf[512];
    const bool Ok = fgets(Buf, sizeof(Buf), F) != nullptr;
    fclose(F);
    if (!Ok) {
      return false;
    }
    const char* P = strrchr(Buf, ')');
    unsigned long Ut = 0, St = 0;
    if (!P || sscanf(P + 2, "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu", &Ut, &St) != 2) {
      return false;
    }
    auto& L = Last[Tid];
    const bool Busy = (Ut + St) > L;
    L = Ut + St;
    return Busy;
  }

  // The record file is created on the first trigger only: many FEX processes (a whole Steam/Wine session) enable the
  // profiler through the environment and most of them are never sampled.
  bool OpenRecords(pid_t Pid) {
    if (Records) {
      return true;
    }
    const std::string Path = "/dev/shm/fex-" + std::to_string(Pid) + "-samples";
    const int fd = open(Path.c_str(), O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0 || ftruncate(fd, sizeof(Sample) * MaxSamples) != 0) {
      return false;
    }
    void* Map = mmap(nullptr, sizeof(Sample) * MaxSamples, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (Map == MAP_FAILED) {
      return false;
    }
    Records = static_cast<Sample*>(Map);
    return true;
  }

  void TakeSnapshot(pid_t Pid) {
    if (!Snaps) {
      const std::string Path = "/dev/shm/fex-" + std::to_string(Pid) + "-snap";
      const int fd = open(Path.c_str(), O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
      if (fd < 0 || ftruncate(fd, sizeof(SnapRecord) * MaxSnaps) != 0) {
        return;
      }
      void* Map = mmap(nullptr, sizeof(SnapRecord) * MaxSnaps, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
      close(fd);
      if (Map == MAP_FAILED) {
        return;
      }
      Snaps = static_cast<SnapRecord*>(Map);
    }
    memset(Snaps, 0, sizeof(SnapRecord) * MaxSnaps);
    SnapCount = 0;
    SnapMode = true;
    if (DIR* D = opendir("/proc/self/task")) {
      while (auto* E = readdir(D)) {
        const pid_t Tid = atoi(E->d_name);
        if (Tid > 0 && Tid != static_cast<pid_t>(syscall(SYS_gettid))) {
          syscall(SYS_tgkill, Pid, Tid, SIGPROF);
        }
      }
      closedir(D);
    }
    usleep(700000); // let every handler finish
    SnapMode = false;
  }

  void* SamplerThread(void* Arg) {
    const uint32_t Hz = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(Arg) & 0xffff);
    const bool All = (reinterpret_cast<uintptr_t>(Arg) >> 16) != 0;
    const pid_t Pid = getpid();
    // Samples are only taken while /dev/shm/fex-<pid>-sample-on exists (create/remove it from outside), so that
    // starting the profiler never perturbs process start-up (an anti-cheat launcher may be ptracing us then) or the other
    // FEX processes of the same application.
    const std::string Trigger = "/dev/shm/fex-" + std::to_string(Pid) + "-sample-on";
    const std::string SnapTrigger = "/dev/shm/fex-" + std::to_string(Pid) + "-snapshot";
    for (;;) {
      if (access(SnapTrigger.c_str(), F_OK) == 0) {
        unlink(SnapTrigger.c_str());
        TakeSnapshot(Pid);
        continue;
      }
      if (access(Trigger.c_str(), F_OK) != 0) {
        usleep(100000);
        continue;
      }
      if (!OpenRecords(Pid)) {
        usleep(100000);
        continue;
      }
      usleep(1000000 / Hz);
      if (FEX::HLE::PtraceEmu::IsAttached()) {
        continue; // a host ptrace tracer would see every SIGPROF as a signal-delivery stop
      }
      if (All) {
        if (DIR* D = opendir("/proc/self/task")) {
          while (auto* E = readdir(D)) {
            const pid_t Tid = atoi(E->d_name);
            if (Tid > 0 && Tid != static_cast<pid_t>(syscall(SYS_gettid)) && IsInteresting(Tid)) {
              syscall(SYS_tgkill, Pid, Tid, SIGPROF);
            }
          }
          closedir(D);
        }
      } else {
        syscall(SYS_tgkill, Pid, Pid, SIGPROF);
      }
    }
    return nullptr;
  }
} // namespace

void StartSamplingProfiler(FEX::HLE::SignalDelegator* Signals, uint32_t Hz, bool AllThreads, bool External) {
  if (!Hz) {
    return;
  }
  ExternalMode = External;
  Delegator = Signals;
  Signals->RegisterHostSignalHandler(
    SIGPROF,
    [](FEXCore::Core::InternalThreadState* Thread, int, void*, void* UContext) {
      if (ExternalMode) {
        OpenExternalSnaps();
      }
      if (ExternalMode || SnapMode.load(std::memory_order_relaxed)) {
        uint32_t SIdx = SnapCount.fetch_add(1, std::memory_order_relaxed);
        const uint32_t Seq = SIdx;
        if (ExternalMode) {
          SIdx %= MaxSnaps;
        }
        if (Snaps && SIdx < MaxSnaps) {
          SnapRecord& R = Snaps[SIdx];
          R.Tid = static_cast<uint64_t>(syscall(SYS_gettid));
          R.HostPC = ArchHelpers::Context::GetPc(UContext);
          if (Thread) {
            const auto& St = Thread->CurrentFrame->State;
            R.Rip = St.rip;
            for (unsigned i = 0; i < 16; ++i) {
              R.Gregs[i] = St.gregs[i];
            }
            // process_vm_readv on ourselves reads the guest stack without risking a fault in the handler
            iovec Local {R.Stack, sizeof(R.Stack)};
            iovec Remote {reinterpret_cast<void*>(St.gregs[FEXCore::X86State::REG_RSP]), sizeof(R.Stack)};
            process_vm_readv(getpid(), &Local, 1, &Remote, 1, 0);

            // A thread asleep in a futex wait: record the futex word, to tell "nobody woke it" (word still equals the expected
            // value) from "the wake-up was lost" (the word changed but the thread still sleeps).
            const uint64_t Nr = St.gregs[FEXCore::X86State::REG_RAX];
            if (Nr == 202 || Nr == 449) {
              uint64_t Addr = St.gregs[FEXCore::X86State::REG_RDI];
              uint64_t Expected = St.gregs[FEXCore::X86State::REG_RDX];
              if (Nr == 449) {
                // futex_waitv(struct futex_waitv* waiters, ...): first waiter is {u64 val; u64 uaddr; u32 flags; u32 pad}
                uint64_t Waiter[3] {};
                iovec WL {Waiter, sizeof(Waiter)};
                iovec WR {reinterpret_cast<void*>(Addr), sizeof(Waiter)};
                Addr = process_vm_readv(getpid(), &WL, 1, &WR, 1, 0) == static_cast<ssize_t>(sizeof(Waiter)) ? Waiter[1] : 0;
                Expected = Waiter[0];
              }
              uint32_t Word = 0;
              iovec FL {&Word, sizeof(Word)};
              iovec FR {reinterpret_cast<void*>(Addr), sizeof(Word)};
              if (Addr && process_vm_readv(getpid(), &FL, 1, &FR, 1, 0) == static_cast<ssize_t>(sizeof(Word))) {
                R.FutexWord = (1ULL << 63) | Word;
                R.FutexExpected = Expected;
                R.FutexAddr = Addr;
              }
            }
          }
          if (ExternalMode) {
            R.FutexWord = 0;
            R.FutexExpected = Seq;
            R.FutexAddr = ArchHelpers::Context::GetSp(UContext);
            // Interrupted in translated code: the thread state is stale, take RIP and the statically allocated registers live.
            if (Thread && Thread->CTX->IsAddressInCodeBuffer(Thread, R.HostPC)) {
              R.FutexWord = 1;
              R.Rip = Thread->CTX->RestoreRIPFromHostPC(Thread, R.HostPC);
              const auto& Cfg = Delegator->GetConfig();
              for (size_t i = 0; i < Cfg.SRAGPRCount && i < 16; ++i) {
                R.Gregs[i] = ArchHelpers::Context::GetArmReg(UContext, Cfg.SRAGPRMapping[i]);
              }
              iovec Local {R.Stack, sizeof(R.Stack)};
              iovec Remote {reinterpret_cast<void*>(R.Gregs[FEXCore::X86State::REG_RSP]), sizeof(R.Stack)};
              process_vm_readv(getpid(), &Local, 1, &Remote, 1, 0);
            }
          }
        }
        return true;
      }
      const uint32_t Idx = Count.fetch_add(1, std::memory_order_relaxed);
      if (Records && Idx < MaxSamples) {
        Records[Idx] = {ArchHelpers::Context::GetPc(UContext),
                        static_cast<uint64_t>(static_cast<uint32_t>(syscall(SYS_gettid))) | (Thread ? (Thread->CurrentFrame->State.rip << 32) : 0)};
      }
      return true; // consumed: never forwarded to the guest
    },
    true);

  if (External) {
    return;
  }
  pthread_t T;
  pthread_attr_t Attr;
  pthread_attr_init(&Attr);
  pthread_attr_setdetachstate(&Attr, PTHREAD_CREATE_DETACHED);
  pthread_create(&T, &Attr, SamplerThread, reinterpret_cast<void*>(static_cast<uintptr_t>(Hz | (AllThreads ? 0x10000 : 0))));
}
} // namespace FEX::HLE
