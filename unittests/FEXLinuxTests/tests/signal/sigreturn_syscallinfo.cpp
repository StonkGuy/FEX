// SPDX-License-Identifier: MIT
#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <cstdint>
#include <pthread.h>
#include <signal.h>
#include <time.h>

// A normal rt_sigreturn (RIP unchanged) must not leave the frame marked as being inside a syscall.
// Otherwise the next asynchronous signal in JIT code skips spilling the live static registers, RSP included, and the
// guest signal frame is built from the RSP of the previous delivery, over live stack frames.
// A worker alternates a shallow loop with a deep call chain whose frames hold a pattern while it is sent SIGUSR1.

namespace {
constexpr int Depth = 12;
constexpr int Words = 96;
constexpr int Signals = 20000;

std::atomic<bool> Stop {};
std::atomic<uint64_t> SignalsSeen {};
std::atomic<uint64_t> Corrupted {};

uint64_t Pattern(int d, int i) {
  return 0x5a5a000000000000ULL ^ (uint64_t(d) << 32) ^ uint64_t(i);
}

void Handler(int, siginfo_t*, void*) {
  SignalsSeen.fetch_add(1, std::memory_order_relaxed);
}

void Spin(uint64_t Iters) {
  volatile uint64_t x = 0;
  for (uint64_t i = 0; i < Iters; i++) {
    x += i;
  }
}

__attribute__((noinline)) void Deep(int d) {
  volatile uint64_t Buf[Words];
  for (int i = 0; i < Words; i++) {
    Buf[i] = Pattern(d, i);
  }
  if (d < Depth) {
    Deep(d + 1);
  } else {
    Spin(20000);
  }
  for (int i = 0; i < Words; i++) {
    if (Buf[i] != Pattern(d, i)) {
      Corrupted.fetch_add(1, std::memory_order_relaxed);
      Buf[i] = Pattern(d, i);
    }
  }
}

void* Worker(void*) {
  while (!Stop.load(std::memory_order_relaxed) && Corrupted.load(std::memory_order_relaxed) == 0) {
    Spin(20000);
    Deep(1);
  }
  return nullptr;
}
} // namespace

TEST_CASE("Signal frames after a normal rt_sigreturn") {
  struct sigaction act {};
  act.sa_sigaction = Handler;
  act.sa_flags = SA_SIGINFO | SA_RESTART;
  sigemptyset(&act.sa_mask);
  REQUIRE(sigaction(SIGUSR1, &act, nullptr) == 0);

  pthread_t Thread;
  REQUIRE(pthread_create(&Thread, nullptr, Worker, nullptr) == 0);

  const struct timespec ts {0, 20000};
  for (int i = 0; i < Signals && Corrupted.load(std::memory_order_relaxed) == 0; i++) {
    pthread_kill(Thread, SIGUSR1);
    nanosleep(&ts, nullptr);
  }
  Stop = true;
  pthread_join(Thread, nullptr);

  CHECK(SignalsSeen.load() > 0);
  REQUIRE(Corrupted.load() == 0);
}
