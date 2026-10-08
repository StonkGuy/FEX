// SPDX-License-Identifier: MIT
/*
$info$
tags: LinuxSyscalls|syscalls-shared
$end_info$
*/

#include <FEXCore/Utils/LogManager.h>

#include "LinuxSyscalls/Syscalls.h"
#include "LinuxSyscalls/x32/Syscalls.h"
#include "LinuxSyscalls/x64/Syscalls.h"

#include <errno.h>
#include <stdint.h>
#include <sys/types.h>

#define SYSCALL_STUB(name)                         \
  do {                                             \
    ERROR_AND_DIE_FMT("Syscall: " #name " stub!"); \
    return -ENOSYS;                                \
  } while (0)

namespace FEXCore::Core {
struct CpuStateFrame;
}

namespace FEX::HLE {
void RegisterStubs(FEX::HLE::SyscallHandler* Handler) {
  REGISTER_SYSCALL_IMPL(restart_syscall, [](FEXCore::Core::CpuStateFrame* Frame) -> uint64_t {
    // Linux only reaches this syscall when the kernel restarted an interrupted syscall. FEX never arms a
    // restart_block, so the call can only ever arrive with no pending restart: kernel/signal.c
    // do_no_restart_syscall() returns -EINTR. Returning that instead of killing the process (the old
    // SYSCALL_STUB did ERROR_AND_DIE) matches what a real kernel would report for this emulated process.
    return -EINTR;
  });

  REGISTER_SYSCALL_IMPL(rseq, [](FEXCore::Core::CpuStateFrame* Frame, struct rseq* rseq, uint32_t rseq_len, int flags, uint32_t sig) -> uint64_t {
    // We don't support this
    return -ENOSYS;
  });
}
} // namespace FEX::HLE
