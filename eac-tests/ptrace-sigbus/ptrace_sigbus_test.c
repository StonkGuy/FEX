// SPDX-License-Identifier: MIT
//
// Regression test for the SIGBUS stops a tracer sees from its tracee.
//
// The child asks to be traced, stops itself, and then makes N locked/atomic accesses at each of four unaligned
// addresses (lock inc, lock xadd, xchg, lock cmpxchg). Each crosses a 16-byte boundary but stays inside one 64-byte
// cache line, so on x86-64 it is not a split lock (which Linux's split-lock detection would slow down or kill with
// SIGBUS) and never faults. Then it
// loads from a shared mapping of an empty memfd, which is a real SIGBUS (BUS_ADRERR); its handler steps over the load.
// The parent traces it with wait4 and PTRACE_CONT, passing every signal back, and records each SIGBUS stop's si_code.
//
// On Linux the tracer sees exactly one SIGBUS stop, the BUS_ADRERR. Under FEX on arm64 an unaligned atomic across
// a 16-byte boundary raises a host SIGBUS (BUS_ADRALN) that FEX emulates in its own handler; the host kernel shows it
// to the tracer first. Before the fix those stops reached the guest tracer: one per access (the Easy Anti-Cheat
// launcher gives up after 1000 of them with "Unexpected error. (#2)").
//
// Expected: PASS on Linux. On eac-2610 before the fix the first check fails: the tracer sees 4000 BUS_ADRALN stops,
// one per access. Stops for other signals are counted and printed but not checked.
// Build: eac-tests/ptrace-sigbus/build.sh [clang]   (x86-64 binary, run it under FEX, and unchanged on x86-64 Linux)
// Run:   ./ptrace_sigbus_test   (exit status = number of failed checks)

typedef unsigned long u64;
typedef unsigned int u32;
typedef long i64;

static inline i64 sc6(i64 nr, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f) {
  i64 ret;
  register i64 r10 __asm__("r10") = d;
  register i64 r8 __asm__("r8") = e;
  register i64 r9 __asm__("r9") = f;
  __asm__ volatile("syscall" : "=a"(ret) : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
  return ret;
}
enum { SYS_write = 1, SYS_mmap = 9, SYS_rt_sigaction = 13, SYS_getpid = 39, SYS_fork = 57, SYS_wait4 = 61, SYS_kill = 62,
       SYS_ptrace = 101, SYS_exit_group = 231, SYS_memfd_create = 319 };
#define sc1(n, a) sc6(n, (i64)(a), 0, 0, 0, 0, 0)
#define sc2(n, a, b) sc6(n, (i64)(a), (i64)(b), 0, 0, 0, 0)
#define sc3(n, a, b, c) sc6(n, (i64)(a), (i64)(b), (i64)(c), 0, 0, 0)
#define sc4(n, a, b, c, d) sc6(n, (i64)(a), (i64)(b), (i64)(c), (i64)(d), 0, 0)

enum { PT_TRACEME = 0, PT_CONT = 7, PT_GETSIGINFO = 0x4202 };
enum { SIGBUS = 7, SIGSTOP = 19, BUS_ADRALN = 1, BUS_ADRERR = 2 };
#define WALL 0x40000000
#define SA_SIGINFO 0x4
#define SA_RESTORER 0x04000000
#define STOPPED(st) (((st) & 0xff) == 0x7f)
#define STOPSIG(st) (((st) >> 8) & 0xff)
enum { N = 1000 };

struct ksigaction { void* handler; u64 flags; void* restorer; u64 mask; };
__attribute__((naked, used)) static void restore_rt(void) { __asm__ volatile("mov $15, %eax\n syscall\n"); }

static u64 slen(const char* s) { u64 n = 0; while (s[n]) ++n; return n; }
static void out(const char* s) { sc3(SYS_write, 1, (i64)s, slen(s)); }
static void outdec(i64 v) {
  char b[24]; int n = 23; u64 u = v < 0 ? (u64)-v : (u64)v; b[n] = 0;
  do { b[--n] = '0' + u % 10; u /= 10; } while (u);
  if (v < 0) b[--n] = '-';
  out(b + n);
}

static int failures, stops_seen;
static void check(int ok, const char* what) {
  out(ok ? "PASS: " : "FAIL: "); out(what); out("\n"); if (!ok) ++failures;
}

// The child's SIGBUS handler counts the signal, keeps its si_code and resumes at bus_resume.
volatile u64 bus_count, bus_resume;
volatile int bus_code;
extern void hbus(void);
__asm__(".text\n.globl hbus\nhbus:\n"
        "  incq bus_count(%rip)\n"
        "  mov 8(%rsi), %eax\n mov %eax, bus_code(%rip)\n"   // siginfo_t.si_code
        "  mov bus_resume(%rip), %rax\n mov %rax, 168(%rdx)\n" // ucontext_t: uc_mcontext.gregs[REG_RIP]
        "  ret\n");

static char buf[256] __attribute__((aligned(64)));

static int child(void) {
  sc4(SYS_ptrace, PT_TRACEME, 0, 0, 0);
  sc2(SYS_kill, sc1(SYS_getpid, 0), SIGSTOP);

  struct ksigaction a = { (void*)hbus, SA_SIGINFO | SA_RESTORER, (void*)restore_rt, 0 };
  sc4(SYS_rt_sigaction, SIGBUS, (i64)&a, 0, 8);

  // Each access crosses a 16-byte granule (an alignment fault for an arm64 atomic, also with LSE2) inside one cache line.
  volatile u32* inc32 = (volatile u32*)(buf + 14);
  volatile u64* xadd64 = (volatile u64*)(buf + 64 + 12);
  volatile u64* xchg64 = (volatile u64*)(buf + 128 + 44);
  volatile u32* cas32 = (volatile u32*)(buf + 192 + 30);
  for (int i = 0; i < N; ++i) __asm__ volatile("lock incl %0" : "+m"(*inc32));
  for (int i = 0; i < N; ++i) { u64 one = 1; __asm__ volatile("lock xaddq %0, %1" : "+r"(one), "+m"(*xadd64)); }
  for (int i = 0; i < N; ++i) { u64 v = i; __asm__ volatile("xchgq %0, %1" : "+r"(v), "+m"(*xchg64)); }
  for (int i = 0; i < N; ++i) {
    u32 old = *cas32, ok;
    __asm__ volatile("lock cmpxchgl %3, %1\n sete %b2" : "+a"(old), "+m"(*cas32), "=q"(ok) : "r"(old + 1) : "cc");
    if (!ok) --i;
  }
  int bad = (*inc32 != N) + (*xadd64 != N) + (*xchg64 != N - 1) + (*cas32 != N) + (bus_count != 0);

  // A real SIGBUS: a load from a shared mapping past the end of an empty file.
  i64 fd = sc2(SYS_memfd_create, "ptrace-sigbus", 0);
  const char* p = (const char*)sc6(SYS_mmap, 0, 4096, 1 /*PROT_READ*/, 1 /*MAP_SHARED*/, fd, 0);
  if (fd < 0 || (u64)p > -4096UL) return 100;
  __asm__ volatile("lea 1f(%%rip), %%rax\n mov %%rax, bus_resume(%%rip)\n movb (%0), %%al\n1:\n" : : "r"(p) : "rax", "memory");
  bad += (bus_count != 1) + (bus_code != BUS_ADRERR);
  return bad;
}

__attribute__((used)) static void entry_c(void) {
  i64 pid = sc1(SYS_fork, 0);
  if (pid == 0) sc1(SYS_exit_group, child());
  if (pid < 0) { out("fork failed\nRESULT: FAIL\n"); sc1(SYS_exit_group, 1); }

  int adraln = 0, adrerr = 0, other_bus = 0, other = 0, other_sig = 0, st = 0, exited = 0, code = -1;
  for (;;) {
    if (sc4(SYS_wait4, pid, &st, WALL, 0) != pid) break;
    if (!STOPPED(st)) {
      exited = 1;
      code = (st & 0x7f) == 0 ? (st >> 8) & 0xff : -(st & 0x7f);
      break;
    }
    int sig = STOPSIG(st);
    if (sig == SIGBUS) {
      int info[32] = {0};
      sc4(SYS_ptrace, PT_GETSIGINFO, pid, 0, info);
      if (info[2] == BUS_ADRALN) ++adraln;
      else if (info[2] == BUS_ADRERR) ++adrerr;
      else ++other_bus;
    } else if (sig != SIGSTOP || stops_seen++) {
      ++other; other_sig = sig;
    }
    sc4(SYS_ptrace, PT_CONT, pid, 0, sig == SIGSTOP ? 0 : sig);
  }

  out("SIGBUS stops: BUS_ADRALN "); outdec(adraln); out(", BUS_ADRERR "); outdec(adrerr); out(", other "); outdec(other_bus);
  out("; other signal stops "); outdec(other);
  if (other) { out(" (last: signal "); outdec(other_sig); out(")"); }
  out("\n");
  check(adraln == 0, "no BUS_ADRALN stop for the unaligned atomic accesses");
  check(adrerr == 1 && other_bus == 0, "the child's own SIGBUS (BUS_ADRERR) is reported to the tracer exactly once");
  check(exited && code == 0, "the child exited 0: atomic results correct, its handler saw only the BUS_ADRERR");
  if (!(exited && code == 0)) { out("  child exit: "); outdec(code); out("\n"); }
  out(failures ? "RESULT: FAIL\n" : "RESULT: PASS\n");
  sc1(SYS_exit_group, failures);
}
__attribute__((naked, used)) void _start(void) { __asm__ volatile("and $-16, %rsp\n call entry_c\n"); }
