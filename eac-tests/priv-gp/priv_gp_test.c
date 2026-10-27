// SPDX-License-Identifier: MIT
//
// Regression test for privileged instructions in user mode.
//
// A privileged instruction at CPL 3 raises #GP(0) before it executes. The kernel delivers SIGSEGV, si_code SI_KERNEL,
// trapno 13, error code 0, RIP at the instruction; Wine reports it as an access violation with information
// 0 / 0xffffffffffffffff. THE FINALS' anti-cheat executes XSETBV every 20 s and inspects the exception; FEX's decoder
// rejected XSETBV as an invalid instruction (SIGILL, which Wine reports as an illegal instruction).
//
// Cases: XSETBV (0f 01 d1; the kernel enables XSAVE, so #GP rather than #UD), and HLT (f4), WBINVD (0f 09) and SWAPGS
// (0f 01 f8), which FEX already raises #GP(0) for. Printed per case: signal, si_code, RIP relative to the instruction,
// trapno, error code.
// The binary is x86-64 only. Run it under FEX, and run the same binary on a real x86-64 Linux kernel for the reference.
// Build: eac-tests/priv-gp/build.sh [clang]
// Run:   ./priv_gp_test   (exit status = number of failed checks)

#if !defined(__x86_64__)
#error "x86-64 only: the test executes privileged x86 instructions"
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
enum { SIGILL = 4, SIGBUS = 7, SIGSEGV = 11, SA_SIGINFO = 4, SA_RESTORER = 0x04000000, SI_KERNEL = 0x80 };
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

// at: offset of the privileged instruction after setup instructions
static void one(u64 mem, const char* what, const unsigned char* insn, int insn_size, int at) {
  unsigned char* s = (unsigned char*)(mem + 0x100);
  for (int i = 0; i < insn_size; ++i) s[i] = insn[i];
  s[insn_size] = 0xc3; // ret
  u64 start = (u64)s + (u64)at;
  u64 before = faults;
  run_at(start);
  int faulted = faults != before;
  out("  "); out(what); out(": ");
  if (faulted) {
    out("signal "); outdec(f_sig); out(" code "); outhex(f_code); out(" rip "); outrel(f_rip, start); out(" trapno ");
    outdec(f_trapno); out(" err "); outhex(f_err);
  } else out("executed");
  out("\n");
  int ok = faulted && f_sig == SIGSEGV && f_code == SI_KERNEL && f_rip == start && f_trapno == 13 && f_err == 0;
  if (!ok) { out("    expected SIGSEGV SI_KERNEL, rip = instruction, trapno 13, err 0\n"); ++failures; }
}

__attribute__((used)) void entry_c(void) {
  struct ksigaction sa = {(void*)fault, SA_SIGINFO | SA_RESTORER, (void*)restore_rt, 0};
  sc6(SYS_rt_sigaction, SIGSEGV, (i64)&sa, 0, 8, 0, 0);
  sc6(SYS_rt_sigaction, SIGILL, (i64)&sa, 0, 8, 0, 0);
  sc6(SYS_rt_sigaction, SIGBUS, (i64)&sa, 0, 8, 0, 0);
  sc1(SYS_alarm, 60);
  u64 mem = (u64)sc6(SYS_mmap, 0, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if ((i64)mem < 0) { out("mmap failed\n"); sc1(SYS_exit_group, 99); }
  // xsetbv with ecx = 0, edx:eax = 3 (x87 | SSE): a valid value, so only the privilege level faults
  static const unsigned char xsetbv[] = {0x31, 0xc9, 0x31, 0xd2, 0xb8, 3, 0, 0, 0, 0x0f, 0x01, 0xd1};
  static const unsigned char hlt[] = {0xf4}, wbinvd[] = {0x0f, 0x09}, swapgs[] = {0x0f, 0x01, 0xf8};
  one(mem, "xsetbv", xsetbv, sizeof(xsetbv), 9);
  one(mem, "hlt", hlt, sizeof(hlt), 0);
  one(mem, "wbinvd", wbinvd, sizeof(wbinvd), 0);
  one(mem, "swapgs", swapgs, sizeof(swapgs), 0);
  out(failures ? "RESULT: FAIL (" : "RESULT: PASS ("); outdec((u64)failures); out(" unexpected)\n");
  sc1(SYS_exit_group, failures);
}

__attribute__((naked, used)) void _start(void) { __asm__ volatile("and $-16, %rsp\n call entry_c\n"); }
