// SPDX-License-Identifier: MIT
/*
$info$
tags: LinuxSyscalls|SMC
desc: Detects guest pages that keep taking self-modifying-code write faults
$end_info$
*/
#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

namespace FEX::HLE {

/**
 * Tracks guest pages that repeatedly fault on SMC write protection (`SMCChecks=mtrack`).
 *
 * Write-protecting a page that holds translated code is cheap when the page is code-only, but a page that mixes code
 * with frequently written data (a trampoline pool, a JIT code heap with inline constants, an anti-cheat hook page ...)
 * takes a SIGSEGV, a code invalidation and a re-translation for every write, which can stall a process for seconds.
 *
 * Once a page has faulted `SMCHotPageFaults` times (a FEX config option) it is declared *hot*: the page stops being write-protected, and the
 * JIT verifies the bytes of every instruction it translates from the page before running it (the same per-instruction
 * check as `SMCChecks=full`, applied to hot pages only). Correctness is unchanged, only the cost moves from the fault
 * path to the (rare) hot code.
 *
 * Both the counter table and the hot set are lock-free: `RecordFault` runs in the SIGSEGV handler and `IsHot` runs in
 * the JIT on every translated instruction.
 */
class SMCHotPageTracker final {
public:
  static constexpr uint64_t PageShift = 12;

  /// Records one SMC write fault on the page containing `Address`. Returns true exactly once, when the page has taken
  /// `FaultThreshold` faults and becomes hot. A threshold of 0 disables the tracking.
  bool RecordFault(uint64_t Address, uint32_t FaultThreshold) {
    if (!FaultThreshold) {
      return false;
    }
    const uint64_t Page = Address >> PageShift;
    auto& Slot = Counters[Hash(Page) & (CounterSlots - 1)];

    uint64_t Old = Slot.load(std::memory_order_relaxed);
    uint64_t New;
    do {
      // Slot layout: [page index : 44][fault count : 20]. A colliding page simply evicts the previous owner.
      const uint64_t Count = (Old >> CountBits) == Page ? (Old & CountMask) + 1 : 1;
      New = (Page << CountBits) | (Count < CountMask ? Count : CountMask);
    } while (!Slot.compare_exchange_weak(Old, New, std::memory_order_relaxed));

    return (New & CountMask) == FaultThreshold && MakeHot(Page);
  }

  /// Declares the page containing `Address` hot without waiting for faults. Returns false when it already was hot or the
  /// set is full (the page then stays on plain write protection).
  bool MarkHot(uint64_t Address) {
    return MakeHot(Address >> PageShift);
  }

  /// True if the page containing `Address` is hot.
  bool IsHot(uint64_t Address) const {
    if (HotCount.load(std::memory_order_relaxed) == 0) {
      return false;
    }

    const uint64_t Key = (Address >> PageShift) + 1; // 0 marks an empty slot
    for (size_t i = 0, Idx = Hash(Key - 1); i < HotSlots; ++i, ++Idx) {
      const uint64_t Entry = Hot[Idx & (HotSlots - 1)].load(std::memory_order_relaxed);
      if (Entry == Key) {
        return true;
      }
      if (Entry == 0) {
        return false;
      }
    }
    return false;
  }

private:
  static constexpr size_t CounterSlots = 4096;
  static constexpr size_t HotSlots = 2048;
  static constexpr unsigned CountBits = 20;
  static constexpr uint64_t CountMask = (1ULL << CountBits) - 1;
  static_assert((CounterSlots & (CounterSlots - 1)) == 0 && (HotSlots & (HotSlots - 1)) == 0);

  static size_t Hash(uint64_t Page) {
    return static_cast<size_t>((Page * 0x9E3779B97F4A7C15ULL) >> 40);
  }

  // Open-addressed insert. Gives up (the page stays on plain write protection) when the set is 3/4 full.
  bool MakeHot(uint64_t Page) {
    if (HotCount.load(std::memory_order_relaxed) >= HotSlots / 4 * 3) {
      return false;
    }

    const uint64_t Key = Page + 1;
    for (size_t i = 0, Idx = Hash(Page); i < HotSlots; ++i, ++Idx) {
      auto& Entry = Hot[Idx & (HotSlots - 1)];
      uint64_t Expected = 0;
      if (Entry.compare_exchange_strong(Expected, Key, std::memory_order_relaxed)) {
        HotCount.fetch_add(1, std::memory_order_relaxed);
        return true;
      }
      if (Expected == Key) {
        return false; // already hot
      }
    }
    return false;
  }

  std::array<std::atomic<uint64_t>, CounterSlots> Counters {};
  std::array<std::atomic<uint64_t>, HotSlots> Hot {};
  std::atomic<uint32_t> HotCount {};
};

} // namespace FEX::HLE
