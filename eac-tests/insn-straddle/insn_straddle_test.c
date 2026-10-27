// SPDX-License-Identifier: MIT
//
// Regression test for instruction fetch faults at a page boundary.
//
// An instruction that starts on an executable page and ends on a page the program may not execute (PROT_NONE, or
// readable without PROT_EXEC) faults on the fetch of its second part: a page fault (trapno 14) whose address is the
// start of the second page, with RIP at the instruction, before any of it executes. Jumping straight into such a page
// faults at the jump target. The kernel delivers SIGSEGV with si_addr the faulting address. Anti-tamper code places
// instructions across a guard page to tell hardware from a translator, which decodes ahead and may fault elsewhere or
// differently; THE FINALS' anti-cheat executes such a split instruction (FEX's log: "PartialDecode instruction in
// entry block").
//
// Cases: a 10-byte MOV r64, imm64 with 1, 4 and 9 bytes on the first page, the second page PROT_NONE or PROT_READ;
// a jump to the first byte of the second page. Printed per case: signal, si_code, si_addr and RIP relative to the
// page boundary, trapno, error code; checked against the hardware behaviour above. Not checked: the error code's
// present bit (hardware: 0 for a PROT_NONE page, 1 for a readable one; FEX reports 1 for both). Wine passes on only
// the fetch and write bits, so no Windows program sees it: a documented limit.
// The binary is x86-64 only. Run it under FEX, and run the same binary on a real x86-64 Linux kernel for the reference.
// Build: eac-tests/insn-straddle/build.sh [clang]
// Run:   ./insn_straddle_test   (exit status = number of failed checks)

#if !defined(__x86_64__)
#error "x86-64 only: the test executes x86 instructions across a page boundary"
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
enum { SYS_write = 1, SYS_mmap = 9, SYS_mprotect = 10, SYS_rt_sigaction = 13, SYS_alarm = 37, SYS_exit_group = 231 };
enum { PROT_NONE = 0, PROT_READ = 1, PROT_WRITE = 2, PROT_EXEC = 4, MAP_PRIVATE = 2, MAP_ANONYMOUS = 0x20 };
enum { SIGILL = 4, SIGBUS = 7, SIGSEGV = 11, SA_SIGINFO = 4, SA_RESTORER = 0x04000000, SEGV_ACCERR = 2 };
enum { REG_RSP = 15, REG_RIP = 16, REG_ERR = 19, REG_TRAPNO = 20 };
#define PAGE 4096UL

struct ksigaction { void* handler; u64 flags; void* restorer; u64 mask; };
__attribute__((naked, used)) static void restore_rt(void) { __asm__ volatile("mov $15, %eax\n syscall\n"); }

// call the code at rdi; a fault handler returns here as if it had returned
void run_at(u64 target);
__asm__(".text\n.globl run_at\nrun_at:\n push %rbx\n call *%rdi\n pop %rbx\n ret\n");

static volatile u64 faults, f_sig, f_code, f_addr, f_rip, f_trapno, f_err;
static void fault(int sig, void* info, void* uc) {
  u64* g = (u64*)((char*)uc + 40);
  ++faults;
  f_sig = (u64)sig;
  f_code = (u64)((int*)info)[2];
  f_addr = *(u64*)((char*)info + 16);
  f_rip = g[REG_RIP];
  f_trapno = g[REG_TRAPNO];
  f_err = g[REG_ERR];
  // return to run_at as the called code would have
  u64 rsp = g[REG_RSP];
  g[REG_RIP] = *(u64*)rsp;
  g[REG_RSP] = rsp + 8;
}

static int failures;
static void out(const char* s) { u64 n = 0; while (s[n]) ++n; sc3(SYS_write, 1, s, n); }
static void outhex(u64 v) { char b[19]; int i = 18; b[i] = 0; do { int d = v & 15; b[--i] = d < 10 ? '0' + d : 'a' + d - 10; v >>= 4; } while (v); b[--i] = 'x'; b[--i] = '0'; out(b + i); }
static void outdec(u64 v) { char b[21]; int i = 20; b[i] = 0; do { b[--i] = '0' + v % 10; v /= 10; } while (v); out(b + i); }
static void outrel(u64 v, u64 base) { if (v >= base) { out("+"); outdec(v - base); } else { out("-"); outdec(base - v); } }

static void one(u64 mem, int on_first, u64 second_prot, const char* what) {
  u64 boundary = mem + PAGE;
  sc3(SYS_mprotect, mem, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC);
  sc3(SYS_mprotect, boundary, PAGE, PROT_READ | PROT_WRITE);
  unsigned char* p = (unsigned char*)boundary;
  for (u64 i = 0; i < PAGE; ++i) p[i] = 0xc3; // ret, should the second page ever run
  u64 start = boundary - (u64)on_first;
  unsigned char* s = (unsigned char*)start;
  if (on_first > 0) {
    // mov rax, imm64 (48 b8 + 8 bytes), then ret
    static const unsigned char insn[11] = {0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8, 0xc3};
    for (int i = 0; i < 11; ++i) s[i] = insn[i];
  }
  sc3(SYS_mprotect, boundary, PAGE, second_prot);
  u64 before = faults;
  run_at(start);
  int faulted = faults != before;
  out("  "); out(what);
  if (on_first) { out(", "); outdec((u64)on_first); out(" of 10 bytes before it"); } else out(", jump to its first byte");
  out(": ");
  if (faulted) {
    out("signal "); outdec(f_sig); out(" code "); outdec(f_code); out(" addr boundary"); outrel(f_addr, boundary);
    out(" rip boundary"); outrel(f_rip, boundary); out(" trapno "); outdec(f_trapno); out(" err "); outhex(f_err);
  } else out("no fault");
  out("\n");
  // hardware: a page fault at the boundary with RIP at the instruction (its first byte when it starts on the first page)
  int ok = faulted && f_sig == SIGSEGV && f_code == SEGV_ACCERR && f_addr == boundary && f_rip == start && f_trapno == 14 &&
           (f_err & 0x14) == 0x14;
  if (!ok) { out("    expected SIGSEGV SEGV_ACCERR, addr = boundary, rip = instruction start, trapno 14, err with user + fetch bits\n"); ++failures; }
}

__attribute__((used)) void entry_c(void) {
  struct ksigaction sa = {(void*)fault, SA_SIGINFO | SA_RESTORER, (void*)restore_rt, 0};
  sc6(SYS_rt_sigaction, SIGSEGV, (i64)&sa, 0, 8, 0, 0);
  sc6(SYS_rt_sigaction, SIGILL, (i64)&sa, 0, 8, 0, 0);
  sc6(SYS_rt_sigaction, SIGBUS, (i64)&sa, 0, 8, 0, 0);
  sc1(SYS_alarm, 60);
  u64 mem = (u64)sc6(SYS_mmap, 0, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if ((i64)mem < 0) { out("mmap failed\n"); sc1(SYS_exit_group, 99); }
  static const int splits[] = {1, 4, 9};
  for (int n = 0; n < 2; ++n) {
    u64 prot = n ? PROT_READ : PROT_NONE;
    for (int i = 0; i < 3; ++i) one(mem, splits[i], prot, n ? "second page PROT_READ" : "second page PROT_NONE");
    one(mem, 0, prot, n ? "second page PROT_READ" : "second page PROT_NONE");
  }
  out(failures ? "RESULT: FAIL (" : "RESULT: PASS ("); outdec((u64)failures); out(" unexpected)\n");
  sc1(SYS_exit_group, failures);
}

__attribute__((naked, used)) void _start(void) { __asm__ volatile("and $-16, %rsp\n call entry_c\n"); }
