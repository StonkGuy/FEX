// SPDX-License-Identifier: MIT
//
// Regression test: a signal frame is always placed below the interrupted code's live stack, also after an earlier
// handler returned normally through rt_sigreturn (FEX-Emu issue #5901).
//
// On x86-64 Linux the kernel builds a signal frame at the interrupted RSP minus the 128-byte red zone
// (get_sigframe() in arch/x86/kernel/signal.c); nothing above that RSP is ever written. A thread that keeps a known
// pattern in its stack frames therefore never sees it change, however many signals it takes.
//
// Under FEX the rt_sigreturn system call itself marks the frame "in a syscall" (InSyscallInfo, which says which host
// registers are already spilled). A normal return (RIP unchanged) resumes the interrupted JIT code directly, so the
// syscall op never clears that marker. The next signal that lands in JIT code then skips spilling the live registers,
// RSP included, and builds the guest frame from the RSP saved at the previous delivery: a stale, higher stack
// pointer, over live frames of the current call chain.
//
// The shape is the one from the issue: a worker thread alternates a shallow busy loop with a 12-deep call chain whose
// frames each hold a 768-byte pattern; the main thread sends it SIGUSR1 every 20 us; the handler only counts and
// returns. Checks: every frame's pattern intact after every signal, the handler's ucontext lies below the interrupted
// RSP minus the red zone, the worker took signals in both phases.
//
// Expected: PASS on x86-64 Linux (and with the fix); FAIL on eac-2610 before the fix within a few signals.
// Build: eac-tests/sigreturn-syscallinfo/build.sh [clang]   (x86-64 binary, run it under FEX)
// Run:   ./sigreturn_syscallinfo_test   (exit status = number of failed checks)

typedef unsigned long u64;
typedef long i64;

static inline i64 sc6(i64 nr, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f) {
  i64 ret;
  register i64 r10 __asm__("r10") = d;
  register i64 r8 __asm__("r8") = e;
  register i64 r9 __asm__("r9") = f;
  __asm__ volatile("syscall" : "=a"(ret) : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
  return ret;
}
#define sc0(n) sc6(n, 0, 0, 0, 0, 0, 0)
#define sc1(n, a) sc6(n, (i64)(a), 0, 0, 0, 0, 0)
#define sc2(n, a, b) sc6(n, (i64)(a), (i64)(b), 0, 0, 0, 0)
#define sc3(n, a, b, c) sc6(n, (i64)(a), (i64)(b), (i64)(c), 0, 0, 0)
#define sc4(n, a, b, c, d) sc6(n, (i64)(a), (i64)(b), (i64)(c), (i64)(d), 0, 0)
enum { SYS_write = 1, SYS_rt_sigaction = 13, SYS_sched_yield = 24, SYS_nanosleep = 35, SYS_getpid = 39, SYS_exit = 60,
       SYS_gettid = 186, SYS_exit_group = 231, SYS_tgkill = 234 };
enum { SIGUSR1 = 10 };
#define SA_SIGINFO 0x4UL
#define SA_RESTORER 0x04000000UL
#define SA_RESTART 0x10000000UL
#define REG_RSP 15

static u64 slen(const char* s) { u64 n = 0; while (s[n]) n++; return n; }
static void out(const char* s) { sc3(SYS_write, 1, (i64)s, slen(s)); }
static void out_hex(u64 v) {
  char b[19]; b[0] = '0'; b[1] = 'x';
  for (int i = 0; i < 16; i++) { int d = (v >> (60 - 4 * i)) & 15; b[2 + i] = d < 10 ? '0' + d : 'a' + d - 10; }
  b[18] = 0; out(b);
}
static void out_dec(u64 v) { char b[24]; int i = 23; b[i] = 0; do { b[--i] = '0' + v % 10; v /= 10; } while (v); out(b + i); }

static int failures;
static void check(int ok, const char* what) { out(ok ? "  ok   " : "  FAIL "); out(what); out("\n"); if (!ok) failures++; }

#define DEPTH 12
#define WORDS 96
#define SIGNALS 100000
#define PATTERN(d, i) (0x5a5a000000000000ULL ^ ((u64)(d) << 32) ^ (u64)(i))

struct ksigaction { void* handler; u64 flags; void (*restorer)(void); u64 mask; };

static volatile int worker_tid, stop, done, deep_phase;
static volatile u64 signals_seen, signals_deep, signals_shallow, bad_frame_pos;

__attribute__((naked)) static void restorer(void) { __asm__ volatile("mov $15, %eax\n syscall\n"); }

static void handler(int sig, void* si, void* uc) {
  (void)sig; (void)si;
  // The ucontext is part of the frame: it must lie below the interrupted RSP minus the red zone.
  u64 rsp = ((u64*)((char*)uc + 40))[REG_RSP];
  if ((u64)uc + 128 > rsp) bad_frame_pos++;
  signals_seen++;
  if (deep_phase) signals_deep++; else signals_shallow++;
}

static void spin(u64 iters) { volatile u64 x = 0; for (u64 i = 0; i < iters; i++) x += i; }

static __attribute__((noinline)) void deep(int d) {
  volatile u64 buf[WORDS];
  for (int i = 0; i < WORDS; i++) buf[i] = PATTERN(d, i);
  if (d < DEPTH) deep(d + 1); else { deep_phase = 1; spin(20000); deep_phase = 0; }
  for (int i = 0; i < WORDS; i++) {
    if (buf[i] != PATTERN(d, i)) {
      out("    frame corrupted: depth "); out_dec(d); out(" word "); out_dec(i); out(" = "); out_hex(buf[i]);
      out(" after "); out_dec(signals_seen); out(" signals\n");
      // The overwritten frames include return addresses: stop before returning through them.
      out("  FAIL no live stack frame was overwritten by a signal frame\nRESULT: FAIL\n");
      sc1(SYS_exit_group, 1);
    }
  }
}

static void worker(void) {
  worker_tid = sc0(SYS_gettid);
  while (!stop) { spin(20000); deep(1); }
  done = 1;
}

static char worker_stack[1 << 20] __attribute__((aligned(16)));

// clone(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM); the child calls fn on its own stack.
__attribute__((naked)) static i64 spawn(void (*fn)(void), void* stack_top) {
  __asm__ volatile(
    "push %r12\n mov %rdi, %r12\n"
    "mov $56, %eax\n mov $0x50f00, %edi\n xor %edx, %edx\n xor %r10d, %r10d\n xor %r8d, %r8d\n syscall\n"
    "test %rax, %rax\n jnz 1f\n"
    "call *%r12\n mov $60, %eax\n xor %edi, %edi\n syscall\n"
    "1: pop %r12\n ret\n");
}

__attribute__((used)) void entry_c(void) {
  out("sigreturn_syscallinfo_test: signal frames stay below the live stack after earlier normal sigreturns\n");
  struct ksigaction sa = {(void*)handler, SA_SIGINFO | SA_RESTART | SA_RESTORER, restorer, 0};
  check(sc4(SYS_rt_sigaction, SIGUSR1, &sa, 0, 8) == 0, "rt_sigaction(SIGUSR1)");
  i64 pid = sc0(SYS_getpid);
  check(spawn(worker, worker_stack + sizeof worker_stack) > 0, "clone worker thread");
  while (!worker_tid) sc0(SYS_sched_yield);

  struct { i64 s, ns; } ts = {0, 20000};
  u64 sent = 0;
  for (; sent < SIGNALS; sent++) {
    sc3(SYS_tgkill, pid, worker_tid, SIGUSR1);
    sc2(SYS_nanosleep, &ts, 0);
  }
  stop = 1;
  while (!done) sc0(SYS_sched_yield);

  out("  signals sent "); out_dec(sent); out(", handled "); out_dec(signals_seen); out(" (deep phase "); out_dec(signals_deep);
  out(", shallow "); out_dec(signals_shallow); out(")\n");
  check(1, "no live stack frame was overwritten by a signal frame");
  check(bad_frame_pos == 0, "every ucontext lies below the interrupted RSP minus the red zone");
  check(signals_deep > 0 && signals_shallow > 0, "signals landed in both the deep and the shallow phase");
  out(failures ? "RESULT: FAIL\n" : "RESULT: PASS\n");
  sc1(SYS_exit_group, failures);
}

__attribute__((naked, used)) void _start(void) { __asm__ volatile("mov %rsp, %rdi\n and $-16, %rsp\n call entry_c\n"); }
