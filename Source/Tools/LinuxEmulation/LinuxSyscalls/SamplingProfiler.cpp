// SPDX-License-Identifier: MIT
#include "LinuxSyscalls/SamplingProfiler.h"
#include "LinuxSyscalls/SignalDelegator.h"
#include "LinuxSyscalls/PtraceEmu.h"
#include "ArchHelpers/MContext.h"

#include <FEXCore/Core/CoreState.h>
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

  void* SamplerThread(void* Arg) {
    const uint32_t Hz = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(Arg) & 0xffff);
    const bool All = (reinterpret_cast<uintptr_t>(Arg) >> 16) != 0;
    const pid_t Pid = getpid();
    // Samples are only taken while /dev/shm/fex-<pid>-sample-on exists (create/remove it from outside), so that
    // starting the profiler never perturbs process start-up (an anti-cheat launcher may be ptracing us then) or the other
    // FEX processes of the same application.
    const std::string Trigger = "/dev/shm/fex-" + std::to_string(Pid) + "-sample-on";
    for (;;) {
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

void StartSamplingProfiler(FEX::HLE::SignalDelegator* Signals, uint32_t Hz, bool AllThreads) {
  if (!Hz) {
    return;
  }
  Signals->RegisterHostSignalHandler(
    SIGPROF,
    [](FEXCore::Core::InternalThreadState* Thread, int, void*, void* UContext) {
      const uint32_t Idx = Count.fetch_add(1, std::memory_order_relaxed);
      if (Records && Idx < MaxSamples) {
        Records[Idx] = {ArchHelpers::Context::GetPc(UContext),
                        static_cast<uint64_t>(static_cast<uint32_t>(syscall(SYS_gettid))) | (Thread ? (Thread->CurrentFrame->State.rip << 32) : 0)};
      }
      return true; // consumed: never forwarded to the guest
    },
    true);

  pthread_t T;
  pthread_attr_t Attr;
  pthread_attr_init(&Attr);
  pthread_attr_setdetachstate(&Attr, PTHREAD_CREATE_DETACHED);
  pthread_create(&T, &Attr, SamplerThread, reinterpret_cast<void*>(static_cast<uintptr_t>(Hz | (AllThreads ? 0x10000 : 0))));
}
} // namespace FEX::HLE
