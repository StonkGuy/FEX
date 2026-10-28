// SPDX-License-Identifier: MIT
//
// Regression test: changing the protection of a page that code might branch to never makes a thread fault that does
// not execute it, and never stalls the process.
//
// A function on page P compares its argument with a value it is never given and branches to page Q when equal, so it
// never executes anything on Q. While one thread calls it in a loop, a second thread switches Q between PROT_NONE
// and PROT_READ | PROT_EXEC. On hardware nothing reads Q: no thread faults and the loop always finishes. Anti-tamper
// code decrypts and re-protects its code pages while other threads run next to them (THE FINALS' anti-cheat).
//
// A translator that decodes ahead (FEX follows branch targets into the next blocks of a multiblock) reads Q while
// compiling P. If the read faults because the other thread has just revoked Q, the fault must not reach the program,
// and the translator must not be left holding a lock: THE FINALS froze with every thread waiting for one, after the
// anti-cheat's handler resumed such a fault elsewhere. The handler here does the same (it resumes at the caller).
//
// The loop runs for 15 s in a child process; the parent kills it after 40 s. Printed: calls, faults delivered, how it ended.
// The binary is x86-64 only. Run it under FEX, and run the same binary on a real x86-64 Linux kernel for the reference.
// Build: eac-tests/decode-race/build.sh [clang]
// Run:   ./decode_race_test   (exit status = number of failed checks)

#if !defined(__x86_64__)
#error "x86-64 only: the test executes x86 instructions"
#endif

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
#define sc1(n, a) sc6(n, (i64)(a), 0, 0, 0, 0, 0)
#define sc3(n, a, b, c) sc6(n, (i64)(a), (i64)(b), (i64)(c), 0, 0, 0)
enum {
  SYS_write = 1, SYS_mmap = 9, SYS_mprotect = 10, SYS_rt_sigaction = 13, SYS_nanosleep = 35, SYS_fork = 57, SYS_exit = 60,
  SYS_wait4 = 61, SYS_kill = 62, SYS_clock_gettime = 228, SYS_exit_group = 231
};
enum { PROT_NONE = 0, PROT_READ = 1, PROT_WRITE = 2, PROT_EXEC = 4, MAP_PRIVATE = 2, MAP_ANONYMOUS = 0x20 };
enum { SIGKILL = 9, SIGSEGV = 11, SIGBUS = 7, SIGILL = 4, SA_SIGINFO = 4, SA_RESTORER = 0x04000000, WNOHANG = 1 };
enum { REG_RSP = 15, REG_RIP = 16 };
#define PAGE 4096UL

struct ksigaction { void* handler; u64 flags; void* restorer; u64 mask; };
__attribute__((naked, used)) static void restore_rt(void) { __asm__ volatile("mov $15, %eax\n syscall\n"); }

// call the code at rdi with argument rsi; a fault handler returns here as if it had returned
u64 call_at(u64 target, u64 arg);
__asm__(".text\n.globl call_at\ncall_at:\n push %rbx\n mov %rdi, %rax\n mov %rsi, %rdi\n call *%rax\n pop %rbx\n ret\n");

// spawn_thread(stack_top, fn): a CLONE_THREAD thread that calls fn (which does not return)
__asm__(".text\n.globl spawn_thread\nspawn_thread:\n"
        "  mov %rsi, -8(%rdi)\n  lea -8(%rdi), %rsi\n"
        "  mov $0x50f00, %edi\n" // CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM
        "  xor %edx, %edx\n  xor %r10d, %r10d\n  xor %r8d, %r8d\n  mov $56, %eax\n  syscall\n"
        "  test %rax, %rax\n  jnz 1f\n"
        "  pop %rbx\n  call *%rbx\n"
        "1: ret\n");
void spawn_thread(void* stack_top, void (*fn)(void));

static void out(const char* s) { u64 n = 0; while (s[n]) ++n; sc3(SYS_write, 1, s, n); }
static void outdec(u64 v) { char b[21]; int i = 20; b[i] = 0; do { b[--i] = '0' + v % 10; v /= 10; } while (v); out(b + i); }
static void outhex(u64 v) { char b[19]; int i = 18; b[i] = 0; do { int d = v & 15; b[--i] = d < 10 ? '0' + d : 'a' + d - 10; v >>= 4; } while (v); b[--i] = 'x'; b[--i] = '0'; out(b + i); }
static u64 now_ns(void) { u64 ts[2]; sc3(SYS_clock_gettime, 1, ts, 0); return ts[0] * 1000000000UL + ts[1]; }

static volatile u64 faults, fault_addr, fault_rip;
static void fault(int sig, void* info, void* uc) {
  u64* g = (u64*)((char*)uc + 40);
  if (!faults++) { fault_addr = *(u64*)((char*)info + 16); fault_rip = g[REG_RIP]; }
  // resume at the caller of the function, as anti-tamper code resumes such a fault somewhere else
  u64 rsp = g[REG_RSP];
  g[REG_RIP] = *(u64*)rsp;
  g[REG_RSP] = rsp + 8;
}

static volatile u64 page_q, toggles;
static void toggle(void) {
  for (;; ++toggles) {
    sc3(SYS_mprotect, page_q, PAGE, PROT_NONE);
    sc3(SYS_mprotect, page_q, PAGE, PROT_READ | PROT_EXEC);
  }
}

static int child(void) {
  struct ksigaction sa = {(void*)fault, SA_SIGINFO | SA_RESTORER, (void*)restore_rt, 0};
  sc6(SYS_rt_sigaction, SIGSEGV, (i64)&sa, 0, 8, 0, 0);
  sc6(SYS_rt_sigaction, SIGBUS, (i64)&sa, 0, 8, 0, 0);
  sc6(SYS_rt_sigaction, SIGILL, (i64)&sa, 0, 8, 0, 0);
  u64 mem = (u64)sc6(SYS_mmap, 0, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  u64 stack = (u64)sc6(SYS_mmap, 0, 16 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if ((i64)mem < 0 || (i64)stack < 0) { out("mmap failed\n"); return 99; }
  unsigned char* p = (unsigned char*)mem;
  for (u64 i = 0; i < 2 * PAGE; ++i) p[i] = 0x90; // nop
  // P (first page): 1000 x add eax, 1 (a long block: the decoder reaches the branch well after the compile began),
  // then cmp edi, 0x7ead1e55; je Q+0x10; mov eax, 1; ret
  unsigned char* f = p + 0x10;
  for (int i = 0; i < 1000; ++i) { f[3 * i] = 0x83; f[3 * i + 1] = 0xc0; f[3 * i + 2] = 0x01; }
  unsigned char* b = f + 3000;
  const u64 target = mem + PAGE + 0x10;
  const unsigned char head[] = {0x81, 0xff, 0x55, 0x1e, 0xad, 0x7e, 0x0f, 0x84};
  for (int i = 0; i < 8; ++i) b[i] = head[i];
  const int rel = (int)(target - (u64)(b + 12));
  for (int i = 0; i < 4; ++i) b[8 + i] = (unsigned char)(rel >> (8 * i));
  const unsigned char tail[] = {0xb8, 1, 0, 0, 0, 0xc3};
  for (int i = 0; i < 6; ++i) b[12 + i] = tail[i];
  // Q (second page): code that P never reaches, so that a decoder following the branch has something to decode
  p[PAGE + 0x30] = 0xc3;
  sc3(SYS_mprotect, mem, 2 * PAGE, PROT_READ | PROT_EXEC);
  page_q = mem + PAGE;
  spawn_thread((void*)(stack + 16 * PAGE), toggle);

  const u64 start = now_ns();
  u64 calls = 0, bad = 0;
  while (now_ns() - start < 15000000000UL) {
    if (call_at((u64)f, calls & 0xffff) != 1) ++bad;
    ++calls;
  }
  out("  "); outdec(calls); out(" calls in 15 s, "); outdec(faults); out(" faults");
  if (faults) { out(" (first: address "); outhex(fault_addr); out(", rip "); outhex(fault_rip); out(")"); }
  out(", "); outdec(bad); out(" wrong results, "); outdec(toggles); out(" protection toggles\n");
  return (faults ? 1 : 0) + (bad ? 1 : 0);
}

__attribute__((used)) void entry_c(void) {
  int failures = 0;
  i64 pid = sc1(SYS_fork, 0);
  if (pid == 0) sc1(SYS_exit_group, child());
  if (pid < 0) { out("fork failed\n"); sc1(SYS_exit_group, 99); }
  // the child must finish its 15 s loop well within 40 s
  int status = 0;
  const u64 start = now_ns();
  i64 r = 0;
  while ((r = sc6(SYS_wait4, pid, (i64)&status, WNOHANG, 0, 0, 0)) == 0 && now_ns() - start < 40000000000UL) {
    u64 ts[2] = {0, 100000000};
    sc3(SYS_nanosleep, ts, 0, 0);
  }
  if (r == 0) {
    sc3(SYS_kill, pid, SIGKILL, 0);
    sc6(SYS_wait4, pid, (i64)&status, 0, 0, 0, 0);
    out("  the calling thread stalled: no exit within 40 s (killed)\n");
    ++failures;
  } else {
    const int code = (status >> 8) & 0xff;
    if ((status & 0x7f) != 0) { out("  child died from signal "); outdec(status & 0x7f); out("\n"); ++failures; }
    else if (code) { out("  expected: no faults (nothing executes page Q), every call returns 1\n"); failures += code; }
  }
  out(failures ? "RESULT: FAIL (" : "RESULT: PASS ("); outdec((u64)failures); out(" unexpected)\n");
  sc1(SYS_exit_group, failures);
}

__attribute__((naked, used)) void _start(void) { __asm__ volatile("and $-16, %rsp\n call entry_c\n"); }
