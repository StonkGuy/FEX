// SPDX-License-Identifier: MIT
/*
$info$
tags: LinuxSyscalls|Debug
desc: Optional in-memory trace of guest signal handling (FEX_SIGNALTRACE=1), for diagnosing lost signals
$end_info$
*/
#pragma once

#include <atomic>
#include <cstdint>

namespace FEX::HLE::SigTrace {
/**
 * A lock-free ring of fixed-size records in /dev/shm/fex-<pid>-sigtrace. Log() is async-signal-safe (an atomic increment and
 * plain stores), so it can be used from the host signal handlers. Decode with tools/harness/sigtrace.py.
 */
enum Event : uint16_t {
  HostArrive = 1, ///< a host signal reached HandleGuestSignal: A = guest-visible mask, B = (deferral count << 32) | si_code
  Masked = 2,     ///< consumed because FEX considers the signal masked and recorded as pending: A = mask, B = pending set
  Deferred = 3,   ///< queued behind a signal-deferring section
  Delivered = 4,  ///< a guest handler frame was set up: A = handler, B = new host mask
  SigReturn = 5,  ///< guest rt_sigreturn: A = guest rsp
  ProcMask = 6,   ///< guest rt_sigprocmask: Sig = how, A = set, B = mask afterwards
  Reraise = 7,    ///< a pending signal was re-raised after being unmasked: A = mask, B = pending set
  Kill = 8,       ///< guest kill/tkill/tgkill: Sig = signal, A = target pid/tid, B = tgid (tgkill)
  Read16 = 9,     ///< guest read() of 16 bytes (Wine's wake-up replies) returned: Sig = fd, A = result, B = first 8 bytes read (or errno | 1<<63)
  Write16 = 10,   ///< guest write() of 16 bytes returned: Sig = fd, A = result, B = first 8 bytes written (or errno | 1<<63)
  EpollCtl = 11,  ///< guest epoll_ctl: Sig = op (1 add, 2 del, 3 mod), A = fd, B = events (| result << 32)
};

struct Rec {
  uint64_t Tsc; ///< CNTVCT_EL0 (24 MHz on Apple silicon)
  uint32_t Tid;
  uint16_t Ev;
  uint16_t Sig;
  uint64_t A;
  uint64_t B;
};

constexpr uint32_t Recs = 1u << 19; // 16 MiB
extern Rec* Buf;
extern std::atomic<uint32_t> Idx;

/// Creates the ring if FEX_SIGNALTRACE is enabled. Call once at start-up.
void Init();

inline bool Enabled() {
  return Buf != nullptr;
}

inline void Log(uint32_t Tid, uint16_t Ev, uint16_t Sig, uint64_t A, uint64_t B) {
  if (!Buf) {
    return;
  }
  uint64_t Tsc = 0;
#if defined(__aarch64__)
  asm volatile("mrs %0, cntvct_el0" : "=r"(Tsc));
#endif
  Rec& R = Buf[Idx.fetch_add(1, std::memory_order_relaxed) & (Recs - 1)];
  R = {Tsc, Tid, Ev, Sig, A, B};
}
} // namespace FEX::HLE::SigTrace
