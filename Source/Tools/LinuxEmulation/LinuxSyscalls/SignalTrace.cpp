// SPDX-License-Identifier: MIT
#include "LinuxSyscalls/SignalTrace.h"

#include <fcntl.h>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

namespace FEX::HLE::SigTrace {
Rec* Buf = nullptr;
std::atomic<uint32_t> Idx {0};

void Init() {
  if (Buf) {
    return;
  }
  const std::string Path = "/dev/shm/fex-" + std::to_string(getpid()) + "-sigtrace";
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
} // namespace FEX::HLE::SigTrace
