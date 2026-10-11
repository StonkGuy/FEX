// SPDX-License-Identifier: MIT
//
// Executes one instruction per case that raises a fault in x86-64 user mode (encodings undefined in 64-bit mode,
// privileged instructions, software interrupts) and records the signal number, si_code, REG_TRAPNO, REG_ERR and the
// reported RIP. Phase 1 runs every case in a forked child with its own fresh code page and a 5 s alarm, so a case that
// hangs is reported as HANG and the other cases still run. Phase 2 runs the same cases in order in one process on one
// reused code page (the way Wine's own exception tests and anti-tamper code reuse a page), with a 60 s alarm. Phase 3
// rewrites one page alternately with an instruction the emulator may reject at decode time (lldt) and a valid one that
// shares its leading bytes (ltr, swapgs): the valid one must raise its own fault, not the cached result of the other.
//
// Who observes this: Wine maps SIGILL/SIGSEGV/SIGTRAP plus REG_TRAPNO (dlls/ntdll/unix/signal_x86_64.c, segv_handler /
// trap_handler) to the NT exception code; a wrong or missing signal changes the exception class a Windows program sees,
// and a case that never returns hangs the program.
//
// Native x86-64 Linux is the reference. The expected values below were recorded from a native run. Build: tests/invalid-ops/build.sh [clang]. Run: ./invalid_ops_test (exit status = number of failed checks).

#if !defined(__x86_64__)
#error "x86-64 only"
#endif
typedef unsigned long u64;
typedef unsigned int u32;
typedef unsigned char u8;
typedef long i64;

static inline i64 sc6(i64 nr, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f) {
  i64 ret;
  register i64 r10 __asm__("r10") = d;
  register i64 r8 __asm__("r8") = e;
  register i64 r9 __asm__("r9") = f;
  __asm__ volatile("syscall" : "=a"(ret) : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
  return ret;
}
enum { SYS_write = 1, SYS_mmap = 9, SYS_rt_sigaction = 13, SYS_alarm = 37, SYS_fork = 57, SYS_exit_group = 231, SYS_wait4 = 61, SYS_kill = 62 };
enum { SIGILL = 4, SIGTRAP = 5, SIGSEGV = 11, SIGALRM = 14, SIGKILL = 9 };
enum { REG_RSP = 15, REG_RIP = 16, REG_ERR = 19, REG_TRAPNO = 20 };
#define SA_SIGINFO 0x4
#define SA_RESTORER 0x04000000
#define SA_NODEFER 0x40000000
struct ksigaction { void* handler; u64 flags; void* restorer; u64 mask; };
struct uctx { u64 flags; u64 link; void* ss_sp; u32 ss_flags; u32 ss_pad; u64 ss_size; u64 gregs[23]; };
struct sinfo { int signo; int errno_; int code; int pad; void* addr; };
__attribute__((naked, used)) static void restore_rt(void) { __asm__ volatile("mov $15, %eax\n syscall\n"); }

static u64 slen(const char* s) { u64 n = 0; while (s[n]) ++n; return n; }
static void out(const char* s) { sc6(SYS_write, 1, (i64)s, (i64)slen(s), 0, 0, 0); }
static void outdec(i64 v) {
  char b[24]; int i = 23; b[i] = 0; u64 u = v < 0 ? (u64)-v : (u64)v;
  do { b[--i] = '0' + u % 10; u /= 10; } while (u);
  if (v < 0) b[--i] = '-';
  out(b + i);
}

struct rec { u64 hits, signo, code, trapno, err, rip; };
static volatile struct rec g_rec;
static u64 g_resume;  // where the handler resumes (the ret that follows the instruction)

static void handler(int sig, struct sinfo* si, struct uctx* uc) {
  if (sig == SIGALRM) sc6(SYS_exit_group, 99, 0, 0, 0, 0, 0);
  g_rec.hits++;
  g_rec.signo = (u64)sig;
  g_rec.code = (u64)(i64)si->code;
  g_rec.trapno = uc->gregs[REG_TRAPNO];
  g_rec.err = uc->gregs[REG_ERR];
  g_rec.rip = uc->gregs[REG_RIP];
  uc->gregs[REG_RIP] = g_resume;
}

// FEX decodes some privileged opcodes (LGDT/LLDT class) as invalid, so they are only required to raise exactly one signal.
// Expected: signo, si_code, trapno, error code, RIP offset from the start of the instruction. -1 = not checked.
struct tcase { const char* name; u8 len; u8 b[8]; int sig, code, trap, err, ripoff; };
#define ILL SIGILL, 2, 6, 0, 0
#define GP SIGSEGV, 0x80, 13, 0, 0
// Recorded from a native x86-64 Linux run (x86 reference box).
static const struct tcase tcs[] = {
  {"push-es", 1, {0x06}, ILL}, {"pop-es", 1, {0x07}, ILL}, {"push-cs", 1, {0x0e}, ILL}, {"push-ss", 1, {0x16}, ILL},
  {"pop-ss", 1, {0x17}, ILL}, {"push-ds", 1, {0x1e}, ILL}, {"pop-ds", 1, {0x1f}, ILL}, {"daa", 1, {0x27}, ILL},
  {"das", 1, {0x2f}, ILL}, {"aaa", 1, {0x37}, ILL}, {"aas", 1, {0x3f}, ILL}, {"pusha", 1, {0x60}, ILL},
  {"popa", 1, {0x61}, ILL}, {"bound", 3, {0x62, 0x00, 0x00}, ILL}, {"op-82", 3, {0x82, 0xc0, 0x01}, ILL},
  {"far-call", 7, {0x9a, 0, 0, 0, 0, 0, 0}, ILL}, {"aam", 2, {0xd4, 0x0a}, ILL}, {"aad", 2, {0xd5, 0x0a}, ILL},
  {"salc", 1, {0xd6}, ILL}, {"far-jmp", 7, {0xea, 0, 0, 0, 0, 0, 0}, ILL}, {"into", 1, {0xce}, ILL},
  {"lock-reg", 3, {0xf0, 0x01, 0xd8}, ILL}, {"ud2", 2, {0x0f, 0x0b}, ILL}, {"ud0", 3, {0x0f, 0xff, 0xc0}, ILL},
  {"ud1", 3, {0x0f, 0xb9, 0xc0}, ILL}, {"sysenter-ud", 2, {0x0f, 0x34}, ILL},
  {"hlt", 1, {0xf4}, GP}, {"cli", 1, {0xfa}, GP}, {"sti", 1, {0xfb}, GP}, {"in-dx", 1, {0xec}, GP},
  {"out-dx", 1, {0xee}, GP}, {"mov-rax-cr0", 3, {0x0f, 0x20, 0xc0}, GP}, {"rdmsr", 2, {0x0f, 0x32}, GP},
  {"lgdt", 3, {0x0f, 0x01, 0x10}, -1, -1, -1, -1, -1}, {"lldt-ax", 3, {0x0f, 0x00, 0xd0}, -1, -1, -1, -1, -1},
  {"ltr-ax", 3, {0x0f, 0x00, 0xd8}, GP}, {"swapgs", 3, {0x0f, 0x01, 0xf8}, GP},
  {"int3-cd03", 2, {0xcd, 0x03}, SIGTRAP, 0x80, 3, 0, 2}, {"int1-cd01", 2, {0xcd, 0x01}, SIGSEGV, 0x80, 13, 10, 0},
  {"int4-cd04", 2, {0xcd, 0x04}, SIGSEGV, 0x80, 4, 0, 2}, {"int0-cd00", 2, {0xcd, 0x00}, SIGSEGV, 0x80, 13, 2, 0},
  {"int-0x2d", 2, {0xcd, 0x2d}, SIGSEGV, 0x80, 13, 362, 0},
  {"int-0x21", 2, {0xcd, 0x21}, SIGSEGV, 0x80, 13, 266, 0}, {"icebp", 1, {0xf1}, SIGTRAP, 1, 1, 0, 1},
};
#define NCASES (int)(sizeof(tcs) / sizeof(tcs[0]))

static void install(void) {
  struct ksigaction act = {(void*)handler, SA_SIGINFO | SA_RESTORER | SA_NODEFER, (void*)restore_rt, 0};
  sc6(SYS_rt_sigaction, SIGILL, (i64)&act, 0, 8, 0, 0);
  sc6(SYS_rt_sigaction, SIGSEGV, (i64)&act, 0, 8, 0, 0);
  sc6(SYS_rt_sigaction, SIGTRAP, (i64)&act, 0, 8, 0, 0);
  sc6(SYS_rt_sigaction, SIGALRM, (i64)&act, 0, 8, 0, 0);
}

// Runs one case on `page`; returns 0 when the observed values match the expectation (or it is unchecked).
static int run_case(u8* page, const struct tcase* t, int verbose) {
  for (int k = 0; k < 64; k++) page[k] = 0x90;
  for (int k = 0; k < t->len; k++) page[k] = t->b[k];
  page[t->len] = 0xc3;
  g_resume = (u64)page + t->len;
  g_rec.hits = g_rec.signo = g_rec.code = g_rec.trapno = g_rec.err = g_rec.rip = 0;
  __asm__ volatile("movq %0, %%rax\n callq *%1\n" : : "r"((u64)page + 2048), "r"(page)
                   : "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "memory", "cc");
  i64 ripoff = (i64)(g_rec.rip - (u64)page);
  if (verbose) {
    out("RAW "); out(t->name); out(": hits="); outdec((i64)g_rec.hits); out(" sig="); outdec((i64)g_rec.signo);
    out(" code="); outdec((i64)g_rec.code); out(" trap="); outdec((i64)g_rec.trapno); out(" err="); outdec((i64)g_rec.err);
    out(" ripoff="); outdec(ripoff); out("\n");
  }
  int bad = g_rec.hits != 1;
  if (t->sig >= 0) bad |= (int)g_rec.signo != t->sig || (int)g_rec.code != t->code || (int)g_rec.trapno != t->trap ||
                          (int)g_rec.err != t->err;
  if (t->ripoff >= 0) bad |= ripoff != t->ripoff;
  return bad;
}

static u8* newpage(void) {
  return (u8*)sc6(SYS_mmap, 0, 4096, 7 /*RWX*/, 0x22 /*PRIVATE|ANON*/, -1, 0);
}

__attribute__((used)) static void entry_c(void) {
  int failures = 0;
  install();
  out("== phase 1: one forked child per case, fresh page, 5 s alarm\n");
  for (int i = 0; i < NCASES; i++) {
    i64 pid = sc6(SYS_fork, 0, 0, 0, 0, 0, 0);
    if (pid == 0) {
      sc6(SYS_alarm, 5, 0, 0, 0, 0, 0);
      int bad = run_case(newpage(), &tcs[i], 1);
      sc6(SYS_exit_group, bad, 0, 0, 0, 0, 0);
    }
    int st = 0;
    sc6(SYS_wait4, pid, (i64)&st, 0, 0, 0, 0);
    int hang = (st & 0x7f) == SIGALRM || (st >> 8) == 99;
    int bad = hang || (st & 0x7f) || (st >> 8);
    out(hang ? "HANG: " : bad ? "FAIL: " : "PASS: "); out(tcs[i].name); out("\n");
    failures += bad;
  }
  out("== phase 2: all cases in one process on one reused page, 60 s alarm\n");
  sc6(SYS_alarm, 60, 0, 0, 0, 0, 0);
  u8* page = newpage();
  for (int i = 0; i < NCASES; i++) {
    int bad = run_case(page, &tcs[i], 0);
    out(bad ? "FAIL: " : "PASS: "); out(tcs[i].name); out("\n");
    failures += bad;
  }
  out("== phase 3: rejected and valid instructions sharing leading bytes, rewritten on one page\n");
  static const char* const seq[] = {"lldt-ax", "ltr-ax", "lldt-ax", "swapgs", "lgdt", "swapgs", "lldt-ax", "ltr-ax"};
  u8* page3 = newpage();
  for (int r = 0; r < 3; r++) {
    for (int s = 0; s < (int)(sizeof(seq) / sizeof(seq[0])); s++) {
      const struct tcase* t = 0;
      for (int i = 0; i < NCASES; i++) {
        const char *a = tcs[i].name, *b = seq[s];
        while (*a && *a == *b) a++, b++;
        if (*a == *b) t = &tcs[i];
      }
      int bad = run_case(page3, t, 0);
      out(bad ? "FAIL: " : "PASS: "); out(t->name); out("\n");
      failures += bad;
    }
  }
  out(failures ? "RESULT: FAIL\n" : "RESULT: PASS\n");
  sc6(SYS_exit_group, failures, 0, 0, 0, 0, 0);
}
__attribute__((naked, used)) void _start(void) { __asm__ volatile("and $-16, %rsp\n call entry_c\n"); }
