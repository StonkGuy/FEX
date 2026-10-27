// SPDX-License-Identifier: MIT
//
// Regression test for EFLAGS.NT (bit 14, nested task) in user mode.
//
// NT is readable and writable from user mode (POPFQ), and the CPU acts on it in one place a user program can reach:
// IRET with RFLAGS.NT = 1 in IA-32e mode raises #GP(0) (Intel SDM, IRET: "IF (IA32_EFER.LMA = 1) and RFLAGS.NT = 1 ->
// #GP(0)"), before it pops anything. Anti-tamper code uses this to tell real hardware from a translator: THE FINALS and
// ARC Raiders only run under another x86 translator once its NT behaviour matches hardware. Under FEX, IRETQ ignored NT
// and returned normally.
//
// Checks:
//   1. POPFQ sets NT and PUSHFQ reads it back (1000 times);
//   2. a raw syscall with NT = 1 returns R11 = RFLAGS with NT, and NT is still set afterwards (1000 times);
//   3. IRETQ with NT = 1 raises SIGSEGV (si_code SI_KERNEL, trapno 13, error code 0) at the IRETQ itself, with the
//      five-word frame still on the stack and NT = 1 in the signal context (500 times, so translated code is reused);
//   4. IRETQ with NT = 0 takes NT from the RFLAGS in its frame (NT 0 and 1, 500 times each);
//   5. a signal (ud2 -> SIGILL) reports the live NT in the context. Printed, not checked: NT the handler writes to the
//      context. Linux's rt_sigreturn does not apply it (NT is not one of the bits restore_sigcontext copies back, so
//      the interrupted NT stays); FEX applies it. No consumer of that difference is known: a documented limit.
// The binary is x86-64 only. Run it under FEX, and run the same binary on a real x86-64 Linux kernel for the reference.
// Build: eac-tests/iret-nt/build.sh [clang]
// Run:   ./iret_nt_test   (exit status = number of failed checks)

#if !defined(__x86_64__)
#error "x86-64 only: the test checks x86 EFLAGS"
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
enum { SYS_write = 1, SYS_rt_sigaction = 13, SYS_alarm = 37, SYS_exit_group = 231 };
enum { SIGILL = 4, SIGSEGV = 11, SA_SIGINFO = 4, SA_RESTORER = 0x04000000, SI_KERNEL = 0x80 };
enum { REG_RBX = 11, REG_RSP = 15, REG_RIP = 16, REG_EFL = 17, REG_ERR = 19, REG_TRAPNO = 20 };
#define NT 0x4000UL

struct ksigaction { void* handler; u64 flags; void* restorer; u64 mask; };
__attribute__((naked, used)) static void restore_rt(void) { __asm__ volatile("mov $15, %eax\n syscall\n"); }

u64 nt_popf_read(void);
void nt_syscall(u64* out);
u64 nt_iret_fault(void);
u64 nt_iret_load(u64 frame_nt);
u64 nt_ud2(u64 nt);
extern char nt_iret_site[], nt_iret_resume[], nt_ud2_site[];
__asm__(".text\n"
        // POPFQ NT = 1, PUSHFQ -> rax; the caller's flags are restored
        ".globl nt_popf_read\nnt_popf_read:\n"
        " pushfq\n pushfq\n orq $0x4000, (%rsp)\n popfq\n pushfq\n pop %rax\n popfq\n ret\n"
        // NT = 1, getpid: out[0] = R11, out[1] = flags after the syscall
        ".globl nt_syscall\nnt_syscall:\n"
        " push %rbx\n mov %rdi, %rbx\n pushfq\n pushfq\n orq $0x4000, (%rsp)\n popfq\n"
        " mov $39, %eax\n syscall\n mov %r11, (%rbx)\n pushfq\n pop %rax\n mov %rax, 8(%rbx)\n popfq\n pop %rbx\n ret\n"
        // NT = 1, IRETQ to nt_iret_resume with RSP = rbx (the caller's saved flags); the SIGSEGV handler of the expected
        // #GP moves there itself. Returns the flags at nt_iret_resume.
        ".globl nt_iret_fault\nnt_iret_fault:\n"
        " push %rbx\n pushfq\n mov %rsp, %rbx\n pushfq\n orq $0x4000, (%rsp)\n popfq\n"
        " xor %eax, %eax\n mov %ss, %ax\n push %rax\n push %rbx\n pushfq\n xor %eax, %eax\n mov %cs, %ax\n push %rax\n"
        " lea nt_iret_resume(%rip), %rax\n push %rax\n"
        ".globl nt_iret_site\nnt_iret_site:\n iretq\n"
        ".globl nt_iret_resume\nnt_iret_resume:\n"
        " pushfq\n pop %rax\n mov %rbx, %rsp\n popfq\n pop %rbx\n ret\n"
        // NT = 0, IRETQ whose frame RFLAGS has NT = rdi; returns the flags after it
        ".globl nt_iret_load\nnt_iret_load:\n"
        " push %rbx\n pushfq\n mov %rsp, %rbx\n mov (%rsp), %rax\n and $~0x4000, %rax\n push %rax\n popfq\n or %rdi, %rax\n"
        " xor %edx, %edx\n mov %ss, %dx\n push %rdx\n push %rbx\n push %rax\n xor %edx, %edx\n mov %cs, %dx\n push %rdx\n"
        " lea 1f(%rip), %rdx\n push %rdx\n iretq\n"
        "1:\n pushfq\n pop %rax\n mov %rbx, %rsp\n popfq\n pop %rbx\n ret\n"
        // NT = rdi, ud2 (the SIGILL handler skips it); returns the flags after the handler returned
        ".globl nt_ud2\nnt_ud2:\n"
        " pushfq\n mov (%rsp), %rax\n and $~0x4000, %rax\n or %rdi, %rax\n push %rax\n popfq\n"
        ".globl nt_ud2_site\nnt_ud2_site:\n ud2\n"
        " pushfq\n pop %rax\n popfq\n ret\n");

static volatile u64 segv_count, segv_code, segv_trapno, segv_err, segv_frame_ok, segv_nt;
static volatile u64 ill_count, ill_nt, ill_write_nt;
static void segv(int sig, void* info, void* uc) {
  u64* g = (u64*)((char*)uc + 40);
  (void)sig;
  ++segv_count;
  segv_code = (u64)((int*)info)[2];
  segv_trapno = g[REG_TRAPNO];
  segv_err = g[REG_ERR];
  segv_nt = (g[REG_EFL] & NT) != 0;
  if (g[REG_RIP] != (u64)nt_iret_site) { segv_frame_ok = 0; sc1(SYS_exit_group, 99); }
  segv_frame_ok = g[REG_RSP] == g[REG_RBX] - 40 && *(u64*)g[REG_RSP] == (u64)nt_iret_resume;
  g[REG_RSP] = g[REG_RBX];
  g[REG_RIP] = (u64)nt_iret_resume;
  g[REG_EFL] &= ~NT;
}
static void ill(int sig, void* info, void* uc) {
  u64* g = (u64*)((char*)uc + 40);
  (void)sig; (void)info;
  ++ill_count;
  ill_nt = (g[REG_EFL] & NT) != 0;
  g[REG_EFL] = (g[REG_EFL] & ~NT) | (ill_write_nt ? NT : 0);
  g[REG_RIP] += 2;
}

static int failures;
static void out(const char* s) { u64 n = 0; while (s[n]) ++n; sc3(SYS_write, 1, s, n); }
static void outhex(u64 v) { char b[19]; int i = 18; b[i] = 0; do { int d = v & 15; b[--i] = d < 10 ? '0' + d : 'a' + d - 10; v >>= 4; } while (v); b[--i] = 'x'; b[--i] = '0'; out(b + i); }
static void outdec(u64 v) { char b[21]; int i = 20; b[i] = 0; do { b[--i] = '0' + v % 10; v /= 10; } while (v); out(b + i); }
static void check(int ok, const char* what) { out(ok ? "PASS: " : "FAIL: "); out(what); out("\n"); if (!ok) ++failures; }

__attribute__((used)) void entry_c(void) {
  struct ksigaction sa_segv = {(void*)segv, SA_SIGINFO | SA_RESTORER, (void*)restore_rt, 0};
  struct ksigaction sa_ill = {(void*)ill, SA_SIGINFO | SA_RESTORER, (void*)restore_rt, 0};
  sc6(SYS_rt_sigaction, SIGSEGV, (i64)&sa_segv, 0, 8, 0, 0);
  sc6(SYS_rt_sigaction, SIGILL, (i64)&sa_ill, 0, 8, 0, 0);
  sc1(SYS_alarm, 60);

  int bad = 0;
  for (int i = 0; i < 1000; ++i) bad += !(nt_popf_read() & NT);
  check(!bad, "1. POPFQ sets NT, PUSHFQ reads it back");

  bad = 0;
  u64 r[2] = {0, 0};
  for (int i = 0; i < 1000; ++i) {
    nt_syscall(r);
    bad += !(r[0] & NT) || !(r[1] & NT);
  }
  out("  syscall: R11 "); outhex(r[0]); out(", flags after "); outhex(r[1]); out("\n");
  check(!bad, "2. a syscall with NT = 1 returns R11 = RFLAGS with NT, and NT stays set");

  bad = 0;
  u64 f = 0;
  for (int i = 0; i < 500; ++i) {
    u64 before = segv_count;
    segv_frame_ok = 0;
    f = nt_iret_fault();
    // NT after the handler is not checked: the handler clears it in the context, which Linux's rt_sigreturn ignores
    // (check 5), so natively it is still set at the resume point (flags 0x4246)
    if (segv_count != before + 1 || segv_code != SI_KERNEL || segv_trapno != 13 || segv_err != 0 || !segv_frame_ok ||
        !segv_nt) {
      if (!bad) {
        out("  iretq NT=1: repetition "); outdec(i); out(": faults "); outdec(segv_count - before); out(", si_code ");
        outhex(segv_code); out(", trapno "); outdec(segv_trapno); out(", err "); outhex(segv_err); out(", frame intact ");
        outdec(segv_frame_ok); out(", NT in context "); outdec(segv_nt); out(", flags after "); outhex(f); out("\n");
      }
      ++bad;
    }
  }
  check(!bad, "3. IRETQ with NT = 1 raises #GP (SIGSEGV, SI_KERNEL, trapno 13, error 0) at the IRETQ, frame untouched");

  bad = 0;
  for (u64 nt = 0; nt < 2; ++nt)
    for (int i = 0; i < 500; ++i) {
      u64 g = nt_iret_load(nt ? NT : 0);
      if (((g & NT) != 0) != nt) {
        if (!bad) { out("  iretq NT=0, frame NT "); outdec(nt); out(": flags after "); outhex(g); out("\n"); }
        ++bad;
      }
    }
  check(!bad, "4. IRETQ with NT = 0 takes NT from its frame");

  bad = 0;
  for (u64 in = 0; in < 2; ++in)
    for (u64 wr = 0; wr < 2; ++wr) {
      u64 before = ill_count;
      ill_write_nt = wr;
      u64 g = nt_ud2(in ? NT : 0);
      out("  ud2 NT "); outdec(in); out(", handler writes NT "); outdec(wr); out(": signals "); outdec(ill_count - before);
      out(", NT in context "); outdec(ill_nt); out(", NT after rt_sigreturn "); outdec((g & NT) != 0); out("\n");
      if (ill_count != before + 1 || ill_nt != in) ++bad;
    }
  check(!bad, "5. a signal reports the live NT in the context");

  out(failures ? "RESULT: FAIL\n" : "RESULT: PASS\n");
  sc1(SYS_exit_group, failures);
}

__attribute__((naked, used)) void _start(void) { __asm__ volatile("and $-16, %rsp\n call entry_c\n"); }
