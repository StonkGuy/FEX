// SPDX-License-Identifier: MIT
#include "LinuxSyscalls/SignalTrace.h"

#include <fcntl.h>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

namespace FEX::HLE::SigTrace {
Rec* Buf = nullptr;
std::atomic<uint32_t> Idx {0};

namespace {
  std::string PathFor(pid_t Pid) {
    return "/dev/shm/fex-" + std::to_string(Pid) + "-sigtrace";
  }
} // namespace

void Init() {
  if (Buf) {
    return;
  }
  const std::string Path = PathFor(getpid());
  const int fd = open(Path.c_str(), O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) {
    return;
  }
  if (ftruncate(fd, sizeof(Rec) * Recs) != 0) {
    close(fd);
    return;
  }
  void* Map = mmap(nullptr, sizeof(Rec) * Recs, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  close(fd);
  if (Map != MAP_FAILED) {
    Buf = static_cast<Rec*>(Map);
  }
}

void CleanupForExit() {
  if (!Buf) {
    return;
  }
  // The mapping goes away with the process; the named object would otherwise stay in /dev/shm (16 MiB each).
  // A forked child inherits Buf but never created its own name, so this unlink is a harmless ENOENT there.
  unlink(PathFor(getpid()).c_str());
}
} // namespace FEX::HLE::SigTrace
