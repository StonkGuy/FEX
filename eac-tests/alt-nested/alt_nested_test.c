// SPDX-License-Identifier: MIT
//
// Checks SIGSEGV delivery on a sigaltstack, in four steps:
//   1. a handler installed with SA_ONSTACK runs on the alt stack: sigaltstack(NULL, &s) inside the handler reports
//      ss_flags == SS_ONSTACK, the handler's own frame sits inside the alt-stack mapping, and the fault that entered
//      it came from ordinary code (its saved RSP is outside the alt stack)
//   2. a SIGSEGV taken INSIDE that handler (a wild write in a helper it calls) is delivered recursively to the same
//      handler, again on the alt stack: the nested frame is built below the outer handler's frame, the nested handler
//      sees the second fault's si_addr, and both entries report the ucontext REG_TRAPNO/REG_ERR. For this to happen the
//      handler needs SA_NODEFER - a signal is masked while its own handler runs otherwise, and the nested fault would
//      take the default action and kill the process
//   3. a stack overflow ON the alt stack itself (unbounded recursion inside the handler until it runs off the bottom
//      of the alt-stack mapping) is NOT recoverable. The handler is re-installed WITHOUT SA_NODEFER here, so the
//      SIGSEGV raised by the overflow is masked (its own handler is still running) and takes the default action: the
//      process dies with SIGSEGV. Verified via fork: the child must die with SIGSEGV (WIFSIGNALED, WTERMSIG == 11)
//   4. the SIGSEGV si_code / REG_TRAPNO / REG_ERR table for three ordinary faults: an unmapped read, a read of a
//      PROT_NONE page and a write to a PROT_READ page. On x86 a not-present PTE reports err = USER only (bit 0 clear),
//      a present-but-denied write reports USER|WRITE; all three trapno 14 (X86_TRAP_PF); si_code SEGV_MAPERR only when
//      no VMA covers the address, SEGV_ACCERR otherwise
//
// Who observes this: Wine's user_mode_abort_thread runs on the signal alt stack (SIGQUIT thread termination); FEX
// patch 0026 fixes FEX unmapping the alt stack while a thread executes on it. The nested-fault path is what FEX logged
// ~50 times as "virtual_setup_exception nested exception on signal stack" (FINALS O-FINALS iteration 3): the real
// consumer is Wine's exception handling while already inside a guest handler. The trapno/err table feeds the hunt for
// the FEX path that raises SIGSEGV with REG_TRAPNO 0, which Wine turns into STATUS_ILLEGAL_INSTRUCTION instead of an
// access violation.
//
// Expected values, from Linux x86-64 mainline (arch/x86/kernel/signal*.c, arch/x86/mm/fault.c):
//   * A SIGSEGV handler with SA_ONSTACK runs on the alt stack; sigaltstack() inside it reports SS_ONSTACK (1).
//   * A fault raised inside an alt-stack handler is delivered on the alt stack again (get_sigframe's sigsp() leaves sp
//     unchanged when sas_ss_flags(sp) == SS_ONSTACK), so the nested handler's frame is below the outer one.
//   * SIGSEGV is blocked while its own handler runs unless SA_NODEFER is set (the kernel adds the signal to the
//     handler's mask). A fault raised inside a handler that ran off its stack therefore takes the default action: the
//     process dies with SIGSEGV (WIFSIGNALED, WTERMSIG == 11). Check 3 relies on this masking rather than on force_fatal.
//   * trapno 14 = X86_TRAP_PF for every SIGSEGV. REG_ERR bits: PROT=1 (page present), WRITE=2, USER=4, INSTR=16. A
//     user-mode fault always has USER set; bit 0 is clear on x86 for a not-present PTE.
//   * si_code: SEGV_MAPERR (1) with no VMA, SEGV_ACCERR (2) with a VMA that denies the access.
//   * Signal numbers / si_code: include/uapi/asm-generic/siginfo.h. REG_* indices:
//     arch/x86/include/uapi/asm/sigcontext.h (REG_RSP 15, REG_RIP 16, REG_ERR 19, REG_TRAPNO 20).
//
// Native x86-64 Linux is the reference (kernel 6.19.10-300.fc44.x86_64); the three recorded runs are in README.md.
// The binary is x86-64 only: it takes x86 page faults and reads x86 ucontext fields, so it only makes sense as an x86-64
// binary. Run it under FEX, and run the same binary on a real x86-64 Linux kernel for the reference result.
// Build: tests/alt-nested/build.sh [cc] [output]
// Run:   ./alt_nested_test   (exit status = number of failed checks)

#if !defined(__x86_64__)
#error "x86-64 only: the test checks x86 page-fault error codes and ucontext layout"
#endif

typedef unsigned long u64;
typedef unsigned int u32;
typedef long i64;

static inline i64 sc6(i64 nr, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f) {
  i64 ret;
  register i64 r10 __asm__("r10") = d;
  register i64 r8 __asm__("r8") = e;
  register i64 r9 __asm__("r9") = f;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                   : "rcx", "r11", "memory");
  return ret;
}
enum { SYS_write = 1, SYS_mmap = 9, SYS_munmap = 11, SYS_rt_sigaction = 13, SYS_sigaltstack = 131,
       SYS_fork = 57, SYS_wait4 = 61, SYS_setrlimit = 160, SYS_exit = 60, SYS_exit_group = 231 };
enum { SIGSEGV = 11 };
enum { SEGV_MAPERR = 1, SEGV_ACCERR = 2 };
enum { PROT_NONE = 0, PROT_READ = 1, PROT_WRITE = 2, MAP_PRIVATE = 2, MAP_ANONYMOUS = 0x20 };
enum { REG_RSP = 15, REG_RIP = 16, REG_ERR = 19, REG_TRAPNO = 20 };
enum { X86_TRAP_PF = 14 };
enum { SS_ONSTACK = 1, SS_DISABLE = 2 };
enum { RLIMIT_CORE = 4 };
enum { PAGE = 4096 };
#define SA_SIGINFO 0x4
#define SA_ONSTACK 0x08000000
#define SA_NODEFER 0x40000000
#define SA_RESTORER 0x04000000
struct ksigaction { void* handler; u64 flags; void* restorer; u64 mask; };
struct kstack { void* ss_sp; i64 ss_flags; u64 ss_size; };
struct rlimit { u64 cur, max; };

// Kernel ucontext_t as the signal frame lays it out: uc_flags, uc_link, uc_stack (stack_t, 24 bytes), then
// uc_mcontext.gregs[23] at offset 40. siginfo_t: si_signo/si_errno/si_code then si_addr at offset 16.
struct uctx {
  u64 flags;
  u64 link;
  void* ss_sp;
  u32 ss_flags;
  u32 ss_pad;
  u64 ss_size;
  u64 gregs[23];
};
_Static_assert(__builtin_offsetof(struct uctx, gregs) == 40, "gregs must sit at offset 40 of ucontext_t");
struct sinfo {
  int signo;
  int errno_;
  int code;
  int pad;
  void* addr;
};
_Static_assert(__builtin_offsetof(struct sinfo, addr) == 16, "si_addr must sit at offset 16 of siginfo_t");

__attribute__((naked, used)) static void restore_rt(void) { __asm__ volatile("mov $15, %eax\n syscall\n"); }

// ------------------------------------------------------------------ output helpers
static u64 slen(const char* s) { u64 n = 0; while (s[n]) ++n; return n; }
static void out(const char* s) { sc6(SYS_write, 1, (i64)s, (i64)slen(s), 0, 0, 0); }
static void outdec(u64 v) { char b[24]; int i = 23; b[i] = 0; do { b[--i] = '0' + v % 10; v /= 10; } while (v); out(b + i); }
static void outhex(u64 v) {
  char b[19]; int i = 18; b[i] = 0;
  do { b[--i] = "0123456789abcdef"[v & 15]; v >>= 4; } while (v);
  b[--i] = 'x'; b[--i] = '0';
  out(b + i);
}
static int failures;
static void check(int ok, const char* what) { out(ok ? "PASS: " : "FAIL: "); out(what); out("\n"); if (!ok) failures++; }

// ------------------------------------------------------------------ shared state
// Records of the last two faults the handler saw; the handler runs recursively, so record[0] is the outer fault and
// record[1] the nested one (check 2). depth counts handler entries.
//   rsp  = ucontext REG_RSP at the fault (the stack the fault was taken on)
//   hrsp = address of the handler's own frame (the stack the handler runs on)
//   srip/srsp = where this handler will resume the faulting context (set by RECOVER_SETUP at the faulting site)
struct rec { u64 signo, code, addr, err, trapno, rip, rsp, hrsp, srip, srsp, onstack; };
// volatile: written by the signal handler, which the compiler cannot see, so plain reads would be folded to the
// pre-fault value the compiler knows.
static volatile struct rec g_rec[2];
static volatile int g_depth;
static u64 g_alt_lo, g_alt_hi;      // alt-stack extent, to prove handler/fault RSP placement
static volatile int g_phase;        // 1 = record only, 2 = record then take a nested fault, 3 = recurse off the stack
static u64 g_bad_ptr;               // the wild pointer for the nested fault
// Where the handler resumes: set at the faulting instruction. Non-static so the inline asm can name them (an asm
// reference does not keep a symbol's internal linkage, so a `static` here fails to link).
u64 g_recover_rip, g_recover_rsp;

static void recurse_until_overflow(void);
__attribute__((noinline, used)) static void nested_fault(void);
static void on_segv(int sig, struct sinfo* si, struct uctx* uc);

// Read sigaltstack(NULL, &s) flags without libc: the syscall takes (NULL, &stack_t).
static i64 cur_ss_flags(struct kstack* s) { return sc6(SYS_sigaltstack, 0, (i64)s, 0, 0, 0, 0); }

// Map a page, unmap it, and return the now-unmapped address: an address with no VMA, so a fault there is SEGV_MAPERR.
static u64 fresh_unmapped(void) {
  i64 m = sc6(SYS_mmap, 0, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  sc6(SYS_munmap, m, PAGE, 0, 0, 0, 0);
  return (u64)m;
}

// Record the fault, then resume execution of the faulting context at the label the faulting site published in
// g_recover_rip/g_recover_rsp. Every faulting site sets those first (RECOVER_SETUP), so the faulting instruction is
// never re-executed - without this the handler would fault again on the same instruction forever.
static void on_segv(int sig, struct sinfo* si, struct uctx* uc) {
  // The outer fault lands in slot 0, the nested fault in slot 1 (deeper entries of check 3 never return and are never
  // read). The handler can be re-entered, so do not keep anything in a local across the nested fault.
  int slot = g_depth < 1 ? 0 : 1;
  volatile struct rec* r = &g_rec[slot];
  volatile struct kstack ss;
  g_depth++;
  r->signo = (u64)sig;
  r->code = (u64)(i64)si->code;
  r->addr = (u64)si->addr;
  r->err = uc->gregs[REG_ERR];
  r->trapno = uc->gregs[REG_TRAPNO];
  r->rip = uc->gregs[REG_RIP];
  r->rsp = uc->gregs[REG_RSP];
  r->srip = g_recover_rip;   // this fault's resume point, captured before a nested fault can overwrite it
  r->srsp = g_recover_rsp;
  cur_ss_flags((struct kstack*)&ss);
  r->onstack = (u64)ss.ss_flags == SS_ONSTACK;
  r->hrsp = (u64)&ss;

  if (g_phase == 3) recurse_until_overflow();       // check 3: never returns
  if (g_phase == 2 && slot == 0) {                  // check 2: take a nested fault from inside the handler
    g_phase = 1;                                    // the nested entry only records
    nested_fault();                                 // sets its own g_recover_* and faults; the nested entry resumes it
  }

  // Return from the handler (restorer -> rt_sigreturn) resumes the context this frame describes at the saved point.
  uc->gregs[REG_RIP] = r->srip;
  uc->gregs[REG_RSP] = r->srsp;
}

// ------------------------------------------------------------------ faulting sites
// Publish the resume point (the label just after the faulting instruction) and the pre-fault stack, then take the
// fault. The label is numeric-local to the asm block it belongs to.
#define RECOVER_SETUP                          \
  "leaq 1f(%%rip), %%rcx\n"                    \
  "movq %%rcx, g_recover_rip(%%rip)\n"         \
  "movq %%rsp, g_recover_rsp(%%rip)\n"

static void fault_read(volatile unsigned char* p) {
  __asm__ volatile(RECOVER_SETUP "movb (%[p]), %%al\n"
                   "1:\n"
                   :
                   : [p] "r"(p)
                   : "rax", "rcx", "memory", "cc");
}

static void fault_write(volatile unsigned char* p) {
  __asm__ volatile(RECOVER_SETUP "movb $0x5a, (%[p])\n"
                   "1:\n"
                   :
                   : [p] "r"(p)
                   : "rcx", "memory", "cc");
}

// The nested fault of check 2: a store to an unmapped address from inside the handler. RECOVER_SETUP publishes a
// resume label inside this function, so the nested handler returns here and this function returns to the handler.
__attribute__((noinline, used)) static void nested_fault(void) {
  __asm__ volatile(RECOVER_SETUP "movq $0x5a, (%[p])\n"
                   "1:\n"
                   :
                   : [p] "r"((void*)g_bad_ptr)
                   : "rcx", "memory", "cc");
}

// ------------------------------------------------------------------ check 3: alt-stack overflow via fork
// Unbounded recursion inside the handler. The handler is already running on the alt stack, so when the recursion runs
// off the bottom of the alt-stack mapping the resulting fault cannot be delivered there and the kernel force-fails
// into the default action, killing the process with SIGSEGV. mark-after-call keeps the compiler from making the call a
// tail call.
__attribute__((noinline, used)) static void recurse_until_overflow(void) {
  volatile char pad[4096];
  pad[0] = (char)g_depth;
  pad[1] = pad[0];
  recurse_until_overflow();
  pad[2] = pad[1];
}

// In the child: no core dump (the SIGSEGV death of check 3 is expected), then a benign fault to enter the handler on
// the alt stack, where g_phase == 3 makes it recurse off the stack. Never returns.
__attribute__((noinline, used)) static void child_overflow(void) {
  struct rlimit rl = { 0, 0 };
  u64 bad = fresh_unmapped();
  sc6(SYS_setrlimit, RLIMIT_CORE, (i64)&rl, 0, 0, 0, 0);
  g_phase = 3;
  *(volatile u64*)bad = 0;   // benign fault -> handler runs on the alt stack -> recursion -> death
  for (;;) { }
}

// ------------------------------------------------------------------ main
__attribute__((used)) static void entry_c(void) {
  // SA_NODEFER so a SIGSEGV raised inside the handler (check 2) is delivered instead of blocked: a signal is masked
  // while its own handler runs unless SA_NODEFER is set, so without it the nested check-2 fault has the default action
  // and kills the process. Check 3 re-installs the handler without SA_NODEFER because it wants the opposite (the masked
  // fault is NOT delivered and the process dies).
  struct ksigaction segv = { (void*)on_segv, SA_SIGINFO | SA_ONSTACK | SA_NODEFER | SA_RESTORER, (void*)restore_rt, 0 };

  // alt stack: 64 KiB is plenty for two nested signal frames, small enough that unbounded recursion runs off it fast.
  static struct kstack g_alt;
  g_alt.ss_size = 64 * 1024;
  i64 r = sc6(SYS_mmap, 0, (i64)g_alt.ss_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (r < 0 && r > -4096) { out("FAIL: mmap alt stack\n"); sc6(SYS_exit_group, 1, 0, 0, 0, 0, 0); }
  g_alt.ss_sp = (void*)r;
  g_alt_lo = (u64)r;
  g_alt_hi = (u64)r + g_alt.ss_size;
  check(sc6(SYS_sigaltstack, (i64)&g_alt, 0, 0, 0, 0, 0) == 0, "install the sigaltstack");
  check(sc6(SYS_rt_sigaction, SIGSEGV, (i64)&segv, 0, 8, 0, 0) == 0, "install the SIGSEGV handler (SA_ONSTACK)");

  // ---- check 1: benign fault in normal code; the handler must run on the alt stack and be usable from there
  g_phase = 1;
  g_depth = 0;
  { struct rec z = {0}; g_rec[0] = z; g_rec[1] = z; }
  fault_read((volatile unsigned char*)(fresh_unmapped() + 0x123));
  {
    volatile struct rec* r0 = &g_rec[0];
    int rsp_on_alt = r0->rsp > g_alt_lo && r0->rsp <= g_alt_hi;
    int hrsp_on_alt = r0->hrsp > g_alt_lo && r0->hrsp <= g_alt_hi;
    out("RAW check1: signo="); outdec(r0->signo);
    out(" code="); outdec(r0->code);
    out(" trapno="); outdec(r0->trapno);
    out(" err="); outhex(r0->err);
    out(" onstack="); outdec(r0->onstack);
    out(" fault_rsp_on_alt="); outdec((u64)rsp_on_alt);
    out(" handler_rsp_on_alt="); outdec((u64)hrsp_on_alt);
    out(" depth="); outdec((u64)g_depth);
    out("\n");
    int ok = r0->signo == SIGSEGV && r0->onstack == SS_ONSTACK
          && hrsp_on_alt            // the handler runs on the alt stack
          && !rsp_on_alt            // but the fault it handles came from ordinary (main-stack) code
          && r0->trapno == X86_TRAP_PF
          && g_depth == 1;
    check(ok, "check 1: handler ran on the alt stack (SS_ONSTACK), fault taken off it");
  }

  // ---- check 2: nested fault inside the handler
  g_phase = 2;
  g_depth = 0;
  { struct rec z = {0}; g_rec[0] = z; g_rec[1] = z; }
  {
    u64 m = fresh_unmapped();
    g_bad_ptr = m + 0x321;                        // the nested fault's address (unmapped)
    fault_read((volatile unsigned char*)(m + 0x45));   // outer fault; the handler then faults at g_bad_ptr
  }
  {
    volatile struct rec* r0 = &g_rec[0];
    volatile struct rec* r1 = &g_rec[1];
    int r1_rsp_on_alt = r1->rsp > g_alt_lo && r1->rsp <= g_alt_hi;
    out("RAW check2 outer:  addr="); outhex(r0->addr);
    out(" err="); outhex(r0->err);
    out(" trapno="); outdec(r0->trapno);
    out(" onstack="); outdec(r0->onstack);
    out(" fault_rsp="); outhex(r0->rsp);
    out(" handler_rsp="); outhex(r0->hrsp);
    out("\n");
    out("RAW check2 nested: addr="); outhex(r1->addr);
    out(" err="); outhex(r1->err);
    out(" trapno="); outdec(r1->trapno);
    out(" onstack="); outdec(r1->onstack);
    out(" fault_rsp="); outhex(r1->rsp);
    out(" handler_rsp="); outhex(r1->hrsp);
    out(" depth="); outdec((u64)g_depth);
    out("\n");
    int ok = g_depth == 2
          && r1->addr == g_bad_ptr                   // the nested handler saw the second faulting address
          && r0->addr != r1->addr
          && r0->trapno == X86_TRAP_PF && r1->trapno == X86_TRAP_PF
          && r0->onstack == SS_ONSTACK && r1->onstack == SS_ONSTACK   // both entries ran on the alt stack
          && r1_rsp_on_alt                           // the nested fault was taken *on* the alt stack
          && r1->hrsp < r0->hrsp;                    // the nested frame sits below the outer handler's frame
    check(ok, "check 2: nested SIGSEGV delivered recursively to the same handler on the alt stack");
  }

  // ---- check 3: overflow the alt stack inside the handler -> the child dies with SIGSEGV.
  // Re-install the handler WITHOUT SA_NODEFER: SIGSEGV is then masked for the duration of its own handler, so when the
  // recursion runs off the alt stack and faults, that fault is not delivered - the kernel takes the default action and
  // kills the process (WIFSIGNALED, WTERMSIG == SIGSEGV). This is the behaviour a guest sees when a handler overflows
  // its own alt stack.
  {
    struct ksigaction no_segv = { (void*)on_segv, SA_SIGINFO | SA_ONSTACK | SA_RESTORER, (void*)restore_rt, 0 };
    check(sc6(SYS_rt_sigaction, SIGSEGV, (i64)&no_segv, 0, 8, 0, 0) == 0,
          "re-install the SIGSEGV handler without SA_NODEFER for the overflow check");
    i64 pid = sc6(SYS_fork, 0, 0, 0, 0, 0, 0);
    if (pid == 0) {
      child_overflow();                              // never returns (child dies with SIGSEGV)
      sc6(SYS_exit, 0, 0, 0, 0, 0, 0);               // unreachable
    }
    int wstatus = 0;
    i64 wr = sc6(SYS_wait4, pid, (i64)&wstatus, 0, 0, 0, 0);
    int signaled = wr == pid && (wstatus & 0x7f) != 0 && (wstatus & 0x7f) != 0x7f;
    int termsig = wstatus & 0x7f;
    int coredump = (wstatus >> 7) & 1;
    out("RAW check3: wait="); outdec((u64)wr);
    out(" wstatus="); outhex((u64)(u32)wstatus);
    out(" signaled="); outdec((u64)signaled);
    out(" termsig="); outdec((u64)termsig);
    out(" core="); outdec((u64)coredump);
    out("\n");
    check(signaled && termsig == SIGSEGV, "check 3: alt-stack overflow killed the child with SIGSEGV (default action)");
  }

  // ---- check 4: the si_code / trapno / err table for three ordinary faults
  {
    i64 none = sc6(SYS_mmap, 0, PAGE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    i64 ro   = sc6(SYS_mmap, 0, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    // 4a: read a PROT_NONE page -> a VMA exists but denies the access
    g_phase = 1; g_depth = 0;
    { struct rec z = {0}; g_rec[0] = z; }
    fault_read((volatile unsigned char*)(none + 0x40));
    volatile struct rec* rn = &g_rec[0];
    out("RAW check4a protnone-read:  signo="); outdec(rn->signo);
    out(" code="); outdec(rn->code);
    out(" addr="); outhex(rn->addr);
    out(" err="); outhex(rn->err);
    out(" trapno="); outdec(rn->trapno);
    out("\n");
    check(rn->signo == SIGSEGV && rn->code == SEGV_ACCERR && rn->addr == (u64)none + 0x40
          && rn->trapno == X86_TRAP_PF && rn->err == 0x4,   // USER only: not-present PTE, read
          "check 4a: PROT_NONE read -> SEGV_ACCERR, trapno 14, err 0x4");

    // 4b: write a PROT_READ page -> the PTE is present, the write is denied
    g_phase = 1; g_depth = 0;
    { struct rec z = {0}; g_rec[0] = z; }
    fault_write((volatile unsigned char*)(ro + 0x80));
    volatile struct rec* rw = &g_rec[0];
    out("RAW check4b protread-write: signo="); outdec(rw->signo);
    out(" code="); outdec(rw->code);
    out(" addr="); outhex(rw->addr);
    out(" err="); outhex(rw->err);
    out(" trapno="); outdec(rw->trapno);
    out("\n");
    check(rw->signo == SIGSEGV && rw->code == SEGV_ACCERR && rw->addr == (u64)ro + 0x80
          && rw->trapno == X86_TRAP_PF && rw->err == 0x6,   // USER|WRITE: present page, write denied
          "check 4b: PROT_READ write -> SEGV_ACCERR, trapno 14, err 0x6");

    // 4c: read an unmapped page -> no VMA covers the address
    g_phase = 1; g_depth = 0;
    { struct rec z = {0}; g_rec[0] = z; }
    u64 um = fresh_unmapped() + 0x40;
    fault_read((volatile unsigned char*)um);
    volatile struct rec* rm = &g_rec[0];
    out("RAW check4c read-unmapped:  signo="); outdec(rm->signo);
    out(" code="); outdec(rm->code);
    out(" addr="); outhex(rm->addr);
    out(" err="); outhex(rm->err);
    out(" trapno="); outdec(rm->trapno);
    out("\n");
    check(rm->signo == SIGSEGV && rm->code == SEGV_MAPERR && rm->addr == um
          && rm->trapno == X86_TRAP_PF && rm->err == 0x4,
          "check 4c: unmapped read -> SEGV_MAPERR, trapno 14, err 0x4");
  }

  out(failures ? "RESULT: FAIL\n" : "RESULT: PASS\n");
  sc6(SYS_exit_group, failures, 0, 0, 0, 0, 0);
}

__attribute__((naked, used)) void _start(void) { __asm__ volatile("and $-16, %rsp\n call entry_c\n"); }
