// SPDX-License-Identifier: MIT
//
// Regression test for the way Wine on x86_64 turns a raw `syscall` made by Windows code into an NT system call
// (dlls/ntdll/unix/signal_x86_64.c, sigsys_handler). The trap is raised either by a seccomp filter (SECCOMP_RET_TRAP,
// Proton 10 and earlier; under FEX this needs FEX_NEEDSSECCOMP=1) or by Syscall User Dispatch
// (prctl(PR_SET_SYSCALL_USER_DISPATCH), Wine 11). The handler does not return a value: it rewrites the ucontext so that
// rt_sigreturn lands in Wine's syscall dispatcher (rip = dispatcher, rcx = syscall frame, r11 = eflags). Protected
// titles (Denuvo Anti-Cheat in ARC Raiders) then issue raw NtContinue (0x43) in a tight loop, each one a trap followed
// by a full context switch to a new rip/rsp that never returns to the trapping code.
//
// The test does exactly that from code in a fixed low page, 200000 times per phase, and checks on every trap:
//   - siginfo: si_signo SIGSYS, si_code SYS_SECCOMP (1) or SYS_USER_DISPATCH (2), si_errno, si_call_addr just past the
//     syscall, si_syscall 0x43, si_arch AUDIT_ARCH_X86_64
//   - ucontext: rip just past the syscall, rax the syscall number, the six argument registers, the arithmetic flags set
//     before the syscall, rcx/r11 as the `syscall` instruction left them (return address, rflags), rsp of the trapping code
//   - the signal frame lands at the same address every time (nothing leaks per trap) and the loop finishes
// Phases:
//   A  seccomp, Wine-style ucontext redirect to a dispatcher that performs the context switch
//   B  as A, handler on a sigaltstack (Wine runs its handlers with SA_ONSTACK)
//   C  seccomp, the handler switches context itself and never returns (no rt_sigreturn: longjmp-style escape); the
//      process must not grow while it does
//   D  seccomp, nested: every 1000th trap the handler (SA_NODEFER) makes a trapped syscall of its own
//   E  seccomp, four threads in the A loop at once
//   F  Syscall User Dispatch (Wine 11), Wine-style redirect, selector byte toggled like Wine
// Expected: passes on a Linux x86-64 kernel (phase F needs CONFIG_GENERIC_ENTRY, i.e. any x86-64 kernel >= 5.11).
// Build: eac-tests/sigsys-redirect/build.sh [clang] [output]
// Run:   FEX_NEEDSSECCOMP=1 ./sigsys_redirect_test   (exit status = number of failed checks)

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;

static inline i64 sc6(i64 nr, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f) {
  i64 ret;
  register i64 r10 __asm__("r10") = d;
  register i64 r8 __asm__("r8") = e;
  register i64 r9 __asm__("r9") = f;
  __asm__ volatile("syscall" : "=a"(ret) : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
  return ret;
}
#define sc2(n, a, b) sc6(n, (i64)(a), (i64)(b), 0, 0, 0, 0)
#define sc3(n, a, b, c) sc6(n, (i64)(a), (i64)(b), (i64)(c), 0, 0, 0)
#define sc4(n, a, b, c, d) sc6(n, (i64)(a), (i64)(b), (i64)(c), (i64)(d), 0, 0)
#define sc5(n, a, b, c, d, e) sc6(n, (i64)(a), (i64)(b), (i64)(c), (i64)(d), (i64)(e), 0)

enum { SYS_write = 1, SYS_mmap = 9, SYS_rt_sigaction = 13, SYS_rt_sigprocmask = 14, SYS_rt_sigreturn = 15,
       SYS_sched_yield = 24, SYS_nanosleep = 35, SYS_clone = 56, SYS_exit = 60, SYS_sigaltstack = 131,
       SYS_prctl = 157, SYS_exit_group = 231, SYS_seccomp = 317 };
enum { SIGSYS = 31, SA_SIGINFO = 4, SA_ONSTACK = 0x08000000, SA_NODEFER = 0x40000000, SA_RESTORER = 0x04000000 };
enum { PR_SET_NO_NEW_PRIVS = 38, PR_SET_SYSCALL_USER_DISPATCH = 59, PR_SYS_DISPATCH_ON = 1, PR_SYS_DISPATCH_OFF = 0 };
enum { SECCOMP_SET_MODE_FILTER = 1, SECCOMP_RET_ALLOW = 0x7fff0000, SECCOMP_RET_TRAP = 0x00030000 };
enum { AUDIT_ARCH_X86_64 = 0xC000003Eu };
// ucontext gregs (byte offset 40) slots
enum { R8 = 0, R9, R10, R11, R12, R13, R14, R15, RDI, RSI, RBP, RBX, RDX, RAX, RCX, RSP, RIP, EFL };
#define GREG(uc, r) (((u64*)((char*)(uc) + 40))[r])

#define TRAP_PAGE 0x20000000UL
#define NT_CONTINUE 0x43
#define NESTED_NR 0x1234
#define FLAGS_IN 0x8d7UL       // OF SF ZF AF PF CF + reserved bit 1
#define FLAGS_MASK 0x8d5UL     // the arithmetic flags
#define ITERS 200000

static u64 slen(const char* s) { u64 n = 0; while (s[n]) ++n; return n; }
static void out(const char* s) { sc3(SYS_write, 1, s, slen(s)); }
static void outhex(u64 v) {
  char b[19]; b[0] = '0'; b[1] = 'x';
  for (int i = 0; i < 16; ++i) { int d = (v >> (60 - 4 * i)) & 15; b[2 + i] = d < 10 ? '0' + d : 'a' + d - 10; }
  b[18] = 0; out(b);
}
// VmRSS in KiB from /proc/self/status, -1 when unavailable.
static i64 rss_kib(void) {
  static char buf[4096];
  i64 fd = sc3(2 /* open */, "/proc/self/status", 0, 0);
  if (fd < 0) return -1;
  i64 n = sc3(0 /* read */, fd, buf, sizeof buf - 1);
  sc2(3 /* close */, fd, 0);
  if (n <= 0) return -1;
  buf[n] = 0;
  for (i64 i = 0; i + 6 < n; ++i) {
    if (buf[i] == 'V' && buf[i + 1] == 'm' && buf[i + 2] == 'R' && buf[i + 3] == 'S' && buf[i + 4] == 'S' && buf[i + 5] == ':') {
      i64 v = 0;
      for (i += 6; buf[i] == ' ' || buf[i] == '\t'; ++i) {}
      for (; buf[i] >= '0' && buf[i] <= '9'; ++i) v = v * 10 + (buf[i] - '0');
      return v;
    }
  }
  return -1;
}
static int failures;
static void check(int ok, const char* what) { out(ok ? "PASS: " : "FAIL: "); out(what); out("\n"); if (!ok) ++failures; }
static void kv(const char* k, u64 v) { out("  "); out(k); out("="); outhex(v); out("\n"); }

// ----------------------------------------------------------------------------------------------------------------
// The "Windows" code, copied to TRAP_PAGE (outside the program image, so the seccomp filter and the SUD range can tell
// it apart). Entered through switch_to with rbx = context, r13 = &counter, r14 = exit address.
//   loop: if (--*counter == 0) goto *exit; flags = FLAGS_IN; NtContinue(rbx) via raw syscall; ud2
//   nested: a trapped syscall with rax = NESTED_NR that returns rax
// ----------------------------------------------------------------------------------------------------------------
__asm__(".section .rodata\n.globl blob_start\nblob_start:\n"
        "  decq (%r13)\n  jz 1f\n"
        "  pushq $0x8d7\n  popfq\n"
        "  mov $0x43, %eax\n  mov %rbx, %rdi\n  mov $0x1111, %esi\n  mov $0x2222, %edx\n"
        "  mov $0x3333, %r10d\n  mov $0x4444, %r8d\n  mov $0x5555, %r9d\n"
        ".globl blob_syscall\nblob_syscall:\n  syscall\n  ud2\n"
        "1:\n  jmp *%r14\n"
        ".globl blob_nested\nblob_nested:\n  mov $0x1234, %eax\n.globl blob_nested_syscall\nblob_nested_syscall:\n  syscall\n  ret\n"
        ".globl blob_end\nblob_end:\n.text\n");
extern const unsigned char blob_start[], blob_syscall[], blob_nested[], blob_nested_syscall[], blob_end[];
#define TP(sym) (TRAP_PAGE + (u64)((sym) - blob_start))

// Per-thread state; the context NtContinue switches to is its first member (the trapped code passes it in rdi).
struct ctx { u64 rip, rsp, efl, rbx, r13, r14; };
struct ts {
  struct ctx c;                      // offset 0: read by switch_to
  u64 counter;
  u64 frame[4];                      // Wine's syscall_frame: rip, rcx, eflags, restore_flags
  u64 traps, bad, first_bad, uc_min, uc_max, nested_ok, nested_bad;
  u64 snap[24];                      // first trap: siginfo + ucontext
  unsigned char* selector;           // SUD selector byte (phase F)
  unsigned char stack[65536] __attribute__((aligned(16)));
};

// switch_to(ctx): the NtContinue half, a full context switch that loads rsp, eflags, rbx, r13, r14 and jumps to rip.
__attribute__((naked, used)) static void switch_to(struct ctx* c) {
  __asm__ volatile("mov 8(%rdi), %rsp\n pushq 16(%rdi)\n popfq\n mov 24(%rdi), %rbx\n mov 32(%rdi), %r13\n"
                   " mov 40(%rdi), %r14\n jmp *(%rdi)\n");
}
// Wine's __wine_syscall_dispatcher stand-in: entered from rt_sigreturn with rcx = frame, rax = syscall number,
// rdi = first argument. Phase F re-allows syscalls (selector = ALLOW) as Wine does on entering the Unix side; the
// context switch then re-blocks them before returning to the "Windows" code.
static u64 g_mode;
__attribute__((used)) static void dispatcher_c(struct ts* t) {
  if (t->selector) *t->selector = 0;
  if (g_mode == 'F') *t->selector = 1;
  switch_to(&t->c);
}
__attribute__((naked, used)) static void dispatcher(void) {
  __asm__ volatile("and $-16, %rsp\n call dispatcher_c\n ud2\n");
}
__attribute__((naked, used)) static void restore_rt(void) { __asm__ volatile("mov $15, %eax\n syscall\n"); }

static u64 g_si_code;
static void bad(struct ts* t, u64 bit) { if (!t->bad) t->first_bad = bit; t->bad |= bit; }

__attribute__((used)) static void handler(int sig, void* info, void* uc) {
  u32* si = (u32*)info;
  u64 nr = GREG(uc, RAX);
  if (nr == NESTED_NR) {
    // Phase D, inner trap: return a value through rax, the plain seccomp contract.
    GREG(uc, RAX) = 0x5678;
    if (*(u64*)((char*)info + 16) != TP(blob_nested_syscall) + 2 || GREG(uc, RIP) != TP(blob_nested_syscall) + 2) GREG(uc, RAX) = 0xbad;
    return;
  }
  struct ts* t = (struct ts*)GREG(uc, RDI);
  t->traps++;
  const u64 after = TP(blob_syscall) + 2;
  if (si[0] != SIGSYS) bad(t, 1);
  if (si[2] != g_si_code) bad(t, 2);
  if (si[1] != 0) bad(t, 4);                                    // si_errno: the filter's RET_DATA / 0 for SUD
  if (*(u64*)((char*)info + 16) != after) bad(t, 8);            // si_call_addr
  if (si[6] != NT_CONTINUE) bad(t, 0x10);                       // si_syscall
  if (si[7] != AUDIT_ARCH_X86_64) bad(t, 0x20);                 // si_arch
  if (GREG(uc, RIP) != after) bad(t, 0x40);
  if (nr != NT_CONTINUE) bad(t, 0x80);
  if (GREG(uc, RSI) != 0x1111 || GREG(uc, RDX) != 0x2222 || GREG(uc, R10) != 0x3333 || GREG(uc, R8) != 0x4444 ||
      GREG(uc, R9) != 0x5555) bad(t, 0x100);
  if ((GREG(uc, EFL) & FLAGS_MASK) != (FLAGS_IN & FLAGS_MASK)) bad(t, 0x200);
  if (GREG(uc, RSP) != t->c.rsp) bad(t, 0x400);
  if (GREG(uc, RBX) != (u64)t || GREG(uc, R13) != (u64)&t->counter) bad(t, 0x800);
  if (GREG(uc, RCX) != after || GREG(uc, R11) != GREG(uc, EFL)) bad(t, 0x1000);   // what `syscall` itself left in rcx/r11
  if (t->traps == 1) {
    u64* s = t->snap;
    s[0] = si[0]; s[1] = si[1]; s[2] = si[2]; s[3] = *(u64*)((char*)info + 16); s[4] = si[6]; s[5] = si[7];
    s[6] = GREG(uc, RIP); s[7] = GREG(uc, RAX); s[8] = GREG(uc, RCX); s[9] = GREG(uc, R11); s[10] = GREG(uc, EFL);
    s[11] = GREG(uc, RSP); s[12] = (u64)t->c.rsp - (u64)uc;
    t->uc_min = t->uc_max = (u64)uc;
  }
  if ((u64)uc < t->uc_min) t->uc_min = (u64)uc;
  if ((u64)uc > t->uc_max) t->uc_max = (u64)uc;

  if (g_mode == 'D' && t->traps % 1000 == 0) {
    i64 r = ((i64(*)(void))TP(blob_nested))();
    if (r == 0x5678) t->nested_ok++; else t->nested_bad++;
  }
  if (g_mode == 'C') {
    // Escape: never return from the handler. Unblock SIGSYS (the kernel blocked it on entry) and switch context.
    u64 m = 1UL << (SIGSYS - 1);
    sc4(SYS_rt_sigprocmask, 1 /* SIG_UNBLOCK */, &m, 0, 8);
    switch_to(&t->c);
  }
  // Wine's redirect (sigsys_handler).
  t->frame[0] = GREG(uc, RIP) + 0xb;
  t->frame[1] = GREG(uc, RIP);
  t->frame[2] = GREG(uc, EFL);
  t->frame[3] = 0;
  GREG(uc, RCX) = (u64)t->frame;
  GREG(uc, R11) = t->frame[2];
  GREG(uc, RIP) = (u64)dispatcher;
  GREG(uc, RDI) = (u64)t;
}

// run_loop(ctx): saves the C callee-saved state, then enters the trapped loop; main_exit comes back here.
__attribute__((used)) u64 saved_rsp;
__attribute__((naked, used)) static void run_loop(struct ctx* c) {
  __asm__ volatile("push %rbp\n push %rbx\n push %r12\n push %r13\n push %r14\n push %r15\n"
                   " mov %rsp, saved_rsp(%rip)\n jmp switch_to\n");
}
__attribute__((naked, used)) static void main_exit(void) {
  __asm__ volatile("mov saved_rsp(%rip), %rsp\n pop %r15\n pop %r14\n pop %r13\n pop %r12\n pop %rbx\n pop %rbp\n ret\n");
}
__attribute__((used)) volatile u32 threads_done;
__attribute__((naked, used)) static void thread_exit(void) {
  __asm__ volatile("lock incl threads_done(%rip)\n mov $60, %eax\n xor %edi, %edi\n syscall\n ud2\n");
}
// spawn(ctx): a CLONE_THREAD thread that starts in switch_to(ctx).
__attribute__((naked, used)) static i64 spawn(struct ctx* c, void* sp) {
  __asm__ volatile("push %r12\n mov %rdi, %r12\n mov $0x50f00, %edi\n xor %edx, %edx\n xor %r10d, %r10d\n"
                   " xor %r8d, %r8d\n mov $56, %eax\n syscall\n test %rax, %rax\n jnz 1f\n mov %r12, %rdi\n"
                   " jmp switch_to\n1:\n pop %r12\n ret\n");
}

static struct ts T[4];
static unsigned char altstack[65536] __attribute__((aligned(16)));
static unsigned char selector_byte;

struct ksigaction { void* handler; u64 flags; void* restorer; u64 mask; };
static void set_handler(u64 extra) {
  struct ksigaction a = {(void*)handler, SA_SIGINFO | SA_RESTORER | extra, (void*)restore_rt, 0};
  sc4(SYS_rt_sigaction, SIGSYS, &a, 0, 8);
}

static void prep(struct ts* t, u64 exit_addr) {
  t->c.rip = TP(blob_start);
  t->c.rsp = (u64)(t->stack + sizeof t->stack - 64);
  t->c.efl = 0x202;
  t->c.rbx = (u64)t;
  t->c.r13 = (u64)&t->counter;
  t->c.r14 = exit_addr;
  t->counter = ITERS + 1;
  t->traps = t->bad = t->first_bad = t->nested_ok = t->nested_bad = 0;
}

static void report(struct ts* t, const char* name, int verbose) {
  out(name); out(": traps="); outhex(t->traps); out(" bad="); outhex(t->bad); out(" first_bad="); outhex(t->first_bad);
  out(" frame_spread="); outhex(t->uc_max - t->uc_min); out("\n");
  if (verbose) {
    static const char* const names[] = {"si_signo", "si_errno", "si_code", "si_call_addr", "si_syscall", "si_arch",
                                        "uc.rip", "uc.rax", "uc.rcx", "uc.r11", "uc.eflags", "uc.rsp", "rsp-uc"};
    for (int i = 0; i < 13; ++i) kv(names[i], t->snap[i]);
  }
}

static int phase_ok(struct ts* t) { return t->traps == ITERS && t->bad == 0 && t->uc_max == t->uc_min; }

static i64 install_seccomp(void) {
  struct sock_filter { unsigned short code; unsigned char jt, jf; u32 k; };
  struct sock_fprog { unsigned short len; struct sock_filter* filter; };
  // trap x86-64 syscalls whose instruction pointer is inside [TRAP_PAGE, TRAP_PAGE + 4096), allow the rest
  static struct sock_filter f[] = {
    {0x20, 0, 0, 12},                    // ld ip_hi
    {0x15, 0, 5, 0},                     // jeq 0 ? next : allow
    {0x20, 0, 0, 8},                     // ld ip_lo
    {0x35, 0, 3, (u32)TRAP_PAGE},        // jge lo ? next : allow
    {0x35, 2, 0, (u32)TRAP_PAGE + 4096}, // jge hi ? allow : next
    {0x20, 0, 0, 4},                     // ld arch
    {0x15, 1, 0, AUDIT_ARCH_X86_64},     // jeq x86_64 ? trap : allow
    {0x06, 0, 0, SECCOMP_RET_ALLOW},
    {0x06, 0, 0, SECCOMP_RET_TRAP},
  };
  struct sock_fprog p = {sizeof f / sizeof f[0], f};
  if (sc5(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
  return sc3(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 4 /* SPEC_ALLOW, like Wine */, &p);
}

__attribute__((used)) void entry_c(void) {
  // The trap page: a copy of the blob at a fixed low address.
  i64 m = sc6(SYS_mmap, TRAP_PAGE, 4096, 7, 0x22 | 0x100000 /* MAP_FIXED_NOREPLACE */, -1, 0);
  if (m != (i64)TRAP_PAGE) { out("mmap trap page failed\nRESULT: FAIL\n"); sc2(SYS_exit_group, 1, 0); }
  for (u64 i = 0; i < (u64)(blob_end - blob_start); ++i) ((unsigned char*)TRAP_PAGE)[i] = blob_start[i];

  // Phase F first (seccomp cannot be removed once installed): Syscall User Dispatch. Syscalls from the allowed region
  // [0, TRAP_PAGE), which holds the whole static program image, always run; those from anywhere else trap while the
  // selector byte says BLOCK.
  {
    g_mode = 'F'; g_si_code = 2 /* SYS_USER_DISPATCH */;
    set_handler(0);
    T[0].selector = &selector_byte;
    prep(&T[0], (u64)main_exit);
    selector_byte = 0;
    i64 r = sc6(SYS_prctl, PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, 0, TRAP_PAGE, (i64)&selector_byte, 0);
    if (r != 0) {
      out("F: prctl(PR_SET_SYSCALL_USER_DISPATCH) = "); outhex(r); out("\n");
      check(0, "F: Syscall User Dispatch can be enabled");
    } else {
      // switch_to does not touch the selector: block from here, the dispatcher re-blocks before each switch back.
      selector_byte = 1;
      run_loop(&T[0].c);
      selector_byte = 0;
      sc6(SYS_prctl, PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_OFF, 0, 0, 0, 0);
      report(&T[0], "F", 1);
      check(phase_ok(&T[0]), "F: 200000 SUD-trapped NtContinue, Wine redirect: siginfo/ucontext exact, frame does not move");
    }
    T[0].selector = 0;
  }

  i64 r = install_seccomp();
  if (r != 0) {
    out("seccomp install = "); outhex(r); out("\n");
    check(0, "seccomp filter installs (under FEX: FEX_NEEDSSECCOMP=1)");
    out("RESULT: FAIL\n"); sc2(SYS_exit_group, failures, 0);
  }
  g_si_code = 1; // SYS_SECCOMP

  g_mode = 'A'; set_handler(0); prep(&T[0], (u64)main_exit); run_loop(&T[0].c); report(&T[0], "A", 1);
  check(phase_ok(&T[0]), "A: 200000 seccomp-trapped NtContinue, Wine redirect: siginfo/ucontext exact, frame does not move");

  {
    struct { void* sp; int flags; u64 size; } ss = {altstack, 0, sizeof altstack};
    sc2(SYS_sigaltstack, &ss, 0);
    g_mode = 'B'; set_handler(SA_ONSTACK); prep(&T[0], (u64)main_exit); run_loop(&T[0].c); report(&T[0], "B", 0);
    check(phase_ok(&T[0]), "B: same on a sigaltstack (SA_ONSTACK, as Wine)");
    ss.flags = 2; /* SS_DISABLE */ sc2(SYS_sigaltstack, &ss, 0);
  }

  {
    // Nothing may be kept per abandoned frame: natively the process does not grow at all here. Under an emulator that
    // keeps host state per guest signal frame, 200000 abandoned frames of a few KiB each add hundreds of MiB.
    const i64 rss0 = rss_kib();
    g_mode = 'C'; set_handler(0); prep(&T[0], (u64)main_exit); run_loop(&T[0].c); report(&T[0], "C", 0);
    const i64 grew = rss_kib() - rss0;
    out("  rss_growth_kib="); outhex((u64)grew); out("\n");
    check(phase_ok(&T[0]), "C: 200000 traps whose handler switches context and never returns (no rt_sigreturn)");
    check(rss0 > 0 && grew < 32768, "C: abandoned signal frames do not accumulate (resident size grows < 32 MiB)");
  }

  g_mode = 'D'; set_handler(SA_NODEFER); prep(&T[0], (u64)main_exit); run_loop(&T[0].c); report(&T[0], "D", 0);
  out("  nested_ok="); outhex(T[0].nested_ok); out(" nested_bad="); outhex(T[0].nested_bad); out("\n");
  check(phase_ok(&T[0]) && T[0].nested_ok == ITERS / 1000 && !T[0].nested_bad,
        "D: a trapped syscall inside the SIGSYS handler (SA_NODEFER) returns its value, outer loop unaffected");

  {
    g_mode = 'E'; set_handler(0); threads_done = 0;
    for (int i = 0; i < 4; ++i) { prep(&T[i], (u64)thread_exit); spawn(&T[i].c, (void*)T[i].c.rsp); }
    struct { i64 s, ns; } ms = {0, 1000000};
    for (int w = 0; threads_done < 4 && w < 120000; ++w) sc2(SYS_nanosleep, &ms, 0);
    int ok = threads_done == 4;
    for (int i = 0; i < 4; ++i) { report(&T[i], "E", 0); ok &= phase_ok(&T[i]); }
    check(ok, "E: four threads in the trapped NtContinue loop at once");
  }

  out(failures ? "RESULT: FAIL\n" : "RESULT: PASS\n");
  sc2(SYS_exit_group, failures, 0);
}
__attribute__((naked, used)) void _start(void) { __asm__ volatile("and $-16, %rsp\n call entry_c\n"); }
