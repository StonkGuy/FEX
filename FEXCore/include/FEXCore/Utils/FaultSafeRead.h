// SPDX-License-Identifier: MIT
#pragma once
#include <FEXCore/Utils/CompilerDefs.h>

#include <cstddef>
#include <cstdint>

namespace FEXCore::Utils::FaultSafeRead {
/**
 * @brief Copies guest memory that another guest thread can unmap or protect at any time.
 *
 * The frontend decodes and hashes guest code while holding code-invalidation locks. A guest mprotect or munmap on
 * another thread can revoke a page between the frontend's executable-range check and its read. A plain load then
 * faults inside FEX, and that fault must never reach the guest: a guest handler that resumes elsewhere would leave the
 * locks held forever.
 *
 * The frontend's SIGSEGV handler resumes a fault at IsFaultLocation as a failed copy.
 *
 * @return true if all Size bytes were copied, false if the source faulted (Dest is then partly written)
 */
FEX_DEFAULT_VISIBILITY bool Copy(void* Dest, const void* Src, size_t Size);

/**
 * @brief Whether PC is the load in Copy that may fault.
 */
FEX_DEFAULT_VISIBILITY bool IsFaultLocation(uint64_t PC);
} // namespace FEXCore::Utils::FaultSafeRead
