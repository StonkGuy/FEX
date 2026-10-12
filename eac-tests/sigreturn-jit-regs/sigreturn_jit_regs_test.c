// SPDX-License-Identifier: MIT
//
// Regression test for the registers of code that a signal interrupted, between the handler's rt_sigreturn and that
// code's next system call.
//
// A SIGALRM (setitimer) interrupts a loop that makes no system call. The handler, written in assembly, sets a flag
// and clobbers r13/r14, and returns through rt_sigreturn with RIP unchanged. The loop sees the flag, puts new values
// in r13/r14, moves RSP down by 256 and then, still without a system call:
//   SMC write:  stores to the page that holds its own code (under FEX's default SMC mode a write fault into a page
//               holding translated code, after which FEX re-dispatches from the register frame);
//   SIGSEGV:    loads from address 0; a SIGSEGV handler records r13/r14/RSP from its ucontext and steps over the load.
// On Linux the loop keeps the new r13/r14/RSP, and the SIGSEGV handler sees them in its ucontext. RSP and the
// callee-saved registers are kept in memory, not on the stack, so a stale RSP is reported instead of crashing.
//
// Under FEX a guest rt_sigreturn is itself a syscall, so the dispatcher sets InSyscallInfo to 0xFFFF (every register
// spilled) for it. Before the fix, RestoreThreadState returned to the interrupted JIT code with that value left in
// place: until the next syscall every SpillSRA skipped all registers. The SIGSEGV handler was then given the RSP of
// the last real syscall (here 0x108 above the new one), and the SMC path reloaded the RSP from before the window
// (0x100 above). The loop's own `ret` then used the wrong stack slot.
//
// Each case runs ITER times; a run where the timer fires outside the loop exercises nothing and passes.
// Expected: PASS on Linux. On eac-2610 before the fix the SIGSEGV case fails every run; the SMC case fails until the
// page turns hot (FEX_SMCHOTPAGEFAULTS, 32 runs by default; every run with FEX_SMCHOTPAGEFAULTS=0) and passes with
// FEX_SMCCHECKS=full, which takes no write fault.
// Build: eac-tests/sigreturn-jit-regs/build.sh [clang]   (x86-64 binary, run it under FEX, and unchanged on x86-64 Linux)
// Run:   ./sigreturn_jit_regs_test   (exit status = number of failed cases)

typedef unsigned long u64;
typedef long i64;

static inline i64 sc4(i64 nr, i64 a, i64 b, i64 c, i64 d) {
  i64 ret;
  register i64 r10 __asm__("r10") = d;
  __asm__ volatile("syscall" : "=a"(ret) : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx", "r11", "memory");
  return ret;
}
enum { SYS_write = 1, SYS_rt_sigaction = 13, SYS_setitimer = 38, SYS_exit_group = 231 };
struct ksigaction { void* handler; u64 flags; void* restorer; u64 mask; };
__attribute__((naked, used)) static void restore_rt(void) { __asm__ volatile("mov $15, %eax\n syscall\n"); }
#define SA_SIGINFO 0x4
#define SA_RESTORER 0x04000000
enum { SIGSEGV = 11, SIGALRM = 14, ITIMER_REAL = 0 };
enum { ITER = 300 };

#define NEW_R13 0xa5a5a5a5a5a5a5a5UL
#define NEW_R14 0x5a5a5a5a5a5a5a5aUL

static u64 slen(const char* s) { u64 n = 0; while (s[n]) ++n; return n; }
static void out(const char* s) { sc4(SYS_write, 1, (i64)s, slen(s), 0); }
static void outdec(u64 v) {
  char b[24]; int n = 23; b[n] = 0;
  do { b[--n] = '0' + v % 10; v /= 10; } while (v);
  out(b + n);
}
static void outhex(u64 v) {
  char b[19]; b[0] = '0'; b[1] = 'x';
  for (int i = 0; i < 16; i++) b[2 + i] = "0123456789abcdef"[(v >> (60 - 4 * i)) & 15];
  b[18] = 0; out(b);
}

volatile int fired;
volatile u64 seen_r13, seen_r14, seen_rsp, segv_r13, segv_r14, segv_rsp, saved_regs[7];
extern void run_case(i64 mode);
extern void halrm(void);
extern void hsegv(void);

// run_case(0): SMC write, run_case(1): SIGSEGV. The code and the slot it stores to share one RWX section.
__asm__(".section .rwx,\"awx\",@progbits\n.balign 4096\n"
        ".globl run_case\nrun_case:\n"
        "  mov %rsp, saved_regs+0(%rip)\n"           // kept in memory, not on the stack: a stale RSP must not
        "  mov %rbx, saved_regs+8(%rip)\n"           // take the caller down with it
        "  mov %rbp, saved_regs+16(%rip)\n"
        "  mov %r12, saved_regs+24(%rip)\n"
        "  mov %r13, saved_regs+32(%rip)\n"
        "  mov %r14, saved_regs+40(%rip)\n"
        "  mov %r15, saved_regs+48(%rip)\n"
        "  movabs $0x1111111111111111, %r13\n"
        "  movabs $0x2222222222222222, %r14\n"
        "1: cmpl $0, fired(%rip)\n"                  // spin, no system call, until the SIGALRM handler ran
        "  je 1b\n"
        "  movabs $0xa5a5a5a5a5a5a5a5, %r13\n"
        "  movabs $0x5a5a5a5a5a5a5a5a, %r14\n"
        "  lea -256(%rsp), %rsp\n"                  // and a new RSP
        "  test %edi, %edi\n jnz 2f\n"
        "  mov %r13, slot(%rip)\n"                   // store into the page that holds this code
        "  jmp 3f\n"
        "2: xor %eax, %eax\n"
        "  mov (%rax), %rax\n"                       // SIGSEGV; hsegv steps over these 3 bytes
        "3: mov %r13, seen_r13(%rip)\n"
        "  mov %r14, seen_r14(%rip)\n"
        "  mov %rsp, seen_rsp(%rip)\n"
        "  mov saved_regs+0(%rip), %rsp\n"
        "  mov saved_regs+8(%rip), %rbx\n"
        "  mov saved_regs+16(%rip), %rbp\n"
        "  mov saved_regs+24(%rip), %r12\n"
        "  mov saved_regs+32(%rip), %r13\n"
        "  mov saved_regs+40(%rip), %r14\n"
        "  mov saved_regs+48(%rip), %r15\n"
        "  ret\n"
        ".balign 64\nslot: .quad 0\n"
        ".text\n"
        ".globl halrm\nhalrm:\n"
        "  movl $1, fired(%rip)\n"
        "  movabs $0xdeaddeaddeaddead, %r13\n"       // the kernel restores both from the frame
        "  movabs $0xbeefbeefbeefbeef, %r14\n"
        "  ret\n"
        ".globl hsegv\nhsegv:\n"
        "  mov 80(%rdx), %rax\n mov %rax, segv_r13(%rip)\n"   // ucontext_t: uc_mcontext.gregs[REG_R13]
        "  mov 88(%rdx), %rax\n mov %rax, segv_r14(%rip)\n"   // gregs[REG_R14]
        "  mov 160(%rdx), %rax\n mov %rax, segv_rsp(%rip)\n"  // gregs[REG_RSP]
        "  addq $3, 168(%rdx)\n"                              // gregs[REG_RIP] += 3
        "  ret\n");

static void install(int sig, void* h) {
  struct ksigaction a = { h, SA_SIGINFO | SA_RESTORER, (void*)restore_rt, 0 };
  sc4(SYS_rt_sigaction, sig, (i64)&a, 0, 8);
}

static int failures;
static void run(i64 mode, const char* what) {
  int bad = 0;
  u64 bad13 = 0, bad14 = 0, badsp = 0;
  for (int i = 0; i < ITER; ++i) {
    struct { i64 interval_s, interval_us, value_s, value_us; } timer = {0, 0, 0, 1000};
    fired = 0;
    seen_r13 = seen_r14 = seen_rsp = segv_r13 = segv_r14 = segv_rsp = 0;
    sc4(SYS_setitimer, ITIMER_REAL, (i64)&timer, 0, 0);
    run_case(mode);
    const u64 new_rsp = saved_regs[0] - 256;
    int ok = seen_r13 == NEW_R13 && seen_r14 == NEW_R14 && seen_rsp == new_rsp;
    if (mode == 1 && (segv_r13 != NEW_R13 || segv_r14 != NEW_R14 || segv_rsp != new_rsp)) {
      ok = 0; seen_r13 = segv_r13; seen_r14 = segv_r14; seen_rsp = segv_rsp;
    }
    if (!ok && !bad++) { bad13 = seen_r13; bad14 = seen_r14; badsp = seen_rsp - new_rsp; }
  }
  out(bad ? "FAIL: " : "PASS: "); out(what);
  if (bad) {
    out("  ("); outdec(bad); out(" of "); outdec(ITER); out(" runs; first: r13="); outhex(bad13); out(" r14="); outhex(bad14);
    out(" rsp-new_rsp="); outhex(badsp); out(")");
    ++failures;
  }
  out("\n");
}

__attribute__((used)) static void entry_c(void) {
  install(SIGALRM, (void*)halrm);
  install(SIGSEGV, (void*)hsegv);
  run(0, "after rt_sigreturn into the loop, a store to its own code page keeps r13/r14/rsp");
  run(1, "after rt_sigreturn into the loop, a SIGSEGV handler sees the current r13/r14/rsp");
  out(failures ? "RESULT: FAIL\n" : "RESULT: PASS\n");
  sc4(SYS_exit_group, failures, 0, 0, 0);
}
__attribute__((naked, used)) void _start(void) { __asm__ volatile("and $-16, %rsp\n call entry_c\n"); }
