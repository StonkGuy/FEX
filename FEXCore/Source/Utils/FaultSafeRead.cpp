// SPDX-License-Identifier: MIT
#include <FEXCore/Utils/FaultSafeRead.h>

#include <cstring>

namespace FEXCore::Utils::FaultSafeRead {
#if defined(ARCHITECTURE_arm64) && !defined(_WIN32)
// Returns 0 when every byte was copied. When the load faults, the frontend's SIGSEGV handler returns from here with
// a non-zero x0 (see IsFaultLocation).
__attribute__((naked)) static size_t CopyImpl(void* Dest, const void* Src, size_t Size) {
  __asm volatile(R"(
  // Early exit if a copy of size zero.
  cbz x2, 2f;

  1:
  .globl FEXCore_FaultSafeRead_FaultInst
  FEXCore_FaultSafeRead_FaultInst:
    ldrb w3, [x1], 1; // <- This line can fault.
    strb w3, [x0], 1;
    sub x2, x2, 1;
    cbnz x2, 1b;
2:
    mov x0, 0;
    ret;
  )" ::
                   : "memory");
}

extern "C" uint64_t FEXCore_FaultSafeRead_FaultInst;

bool Copy(void* Dest, const void* Src, size_t Size) {
  return CopyImpl(Dest, Src, Size) == 0;
}

bool IsFaultLocation(uint64_t PC) {
  return reinterpret_cast<void*>(PC) == &FEXCore_FaultSafeRead_FaultInst;
}
#else
bool Copy(void* Dest, const void* Src, size_t Size) {
  memcpy(Dest, Src, Size);
  return true;
}

bool IsFaultLocation(uint64_t PC) {
  return false;
}
#endif
} // namespace FEXCore::Utils::FaultSafeRead
