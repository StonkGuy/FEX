// SPDX-License-Identifier: MIT
//
// Checks the fields a process sees when it executes an instruction that raises #UD on x86-64: si_signo, si_code,
// and the ucontext gregs REG_TRAPNO, REG_ERR and RIP. The faulting instruction is chosen from encodings that are
// undefined in 64-bit mode (and from UD2/UD0, which are architecturally defined #UD), each taken by a SA_SIGINFO
// handler that records the values and resumes at the label after the instruction.
//
// Who observes this: Wine installs one handler for SIGSEGV, SIGILL and SIGBUS (dlls/ntdll/unix/signal_x86_64.c,
// segv_handler) and maps REG_TRAPNO to the NT exception code; trapno 6 is the case it expects for an invalid opcode,
// and any other value it does not know is logged as "Got unexpected trap N" before it falls back to the same
// EXCEPTION_ILLEGAL_INSTRUCTION. A program's own SIGILL handler can also test si_code == ILL_ILLOPN.
//
// Expected values, from the Linux x86 trap path (mainline arch/x86/kernel/traps.c, handle_invalid_op() ->
// do_error_trap(SIGILL, ILL_ILLOPN)): signo 4 (SIGILL), si_code 2 (ILL_ILLOPN), trapno 6 (X86_TRAP_UD), error code 0,
// RIP = the faulting instruction. Not checked against a local kernel tree; the native run is the reference.
//
// Native x86-64 Linux is the reference. Build: tests/ud-regs/build.sh [clang]. Run: ./ud_regs_test (exit status =
// number of failed checks).

#if !defined(__x86_64__)
#error "x86-64 only: the test checks x86 trap numbers and ucontext layout"
#endif

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
enum { SYS_write = 1, SYS_rt_sigaction = 13, SYS_exit_group = 231 };
enum { SIGILL = 4 };
enum { ILL_ILLOPN = 2 };
enum { REG_RSP = 15, REG_RIP = 16, REG_ERR = 19, REG_TRAPNO = 20 };
enum { X86_TRAP_UD = 6 };
#define SA_SIGINFO 0x4
#define SA_RESTORER 0x04000000
struct ksigaction { void* handler; u64 flags; void* restorer; u64 mask; };

struct uctx { u64 flags; u64 link; void* ss_sp; u32 ss_flags; u32 ss_pad; u64 ss_size; u64 gregs[23]; };
_Static_assert(__builtin_offsetof(struct uctx, gregs) == 40, "gregs must sit at offset 40 of ucontext_t");
struct sinfo { int signo; int errno_; int code; int pad; void* addr; };

__attribute__((naked, used)) static void restore_rt(void) { __asm__ volatile("mov $15, %eax\n syscall\n"); }

struct rec { u64 signo, code, err, trapno, rip, hits; };
static struct rec g_rec;
u64 g_recover_rip, g_recover_rsp;

static void on_sigill(int sig, struct sinfo* si, struct uctx* uc) {
  g_rec.signo = (u64)sig;
  g_rec.code = (u64)(i64)si->code;
  g_rec.err = uc->gregs[REG_ERR];
  g_rec.trapno = uc->gregs[REG_TRAPNO];
  g_rec.rip = uc->gregs[REG_RIP];
  g_rec.hits++;
  uc->gregs[REG_RIP] = g_recover_rip;
  uc->gregs[REG_RSP] = g_recover_rsp;
}

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

// The label "2:" marks the faulting instruction (its address is checked against RIP); "1:" is where the handler
// resumes. Raw .byte encodings keep the instruction independent of what the assembler accepts in 64-bit mode.
#define CASE(fn, bytes)                                 \
  __attribute__((noinline)) static u64 fn(void) {      \
    u64 at;                                             \
    __asm__ volatile("leaq 1f(%%rip), %%rcx\n"         \
                     "movq %%rcx, g_recover_rip(%%rip)\n" \
                     "movq %%rsp, g_recover_rsp(%%rip)\n" \
                     "leaq 2f(%%rip), %[at]\n"          \
                     "2:\n" bytes "\n"                  \
                     "1:\n"                             \
                     : [at] "=&r"(at)                   \
                     :                                  \
                     : "rax", "rcx", "memory", "cc");   \
    return at;                                          \
  }
CASE(do_ud2, ".byte 0x0f, 0x0b")
CASE(do_ud0, ".byte 0x0f, 0xff, 0xc0")
CASE(do_push_es, ".byte 0x06")
CASE(do_pusha, ".byte 0x60")
CASE(do_daa, ".byte 0x27")
CASE(do_aam, ".byte 0xd4, 0x0a")
CASE(do_lock_reg, ".byte 0xf0, 0x01, 0xd8")  // lock add eax, ebx: LOCK needs a memory destination

static void reset_rec(void) { g_rec.signo = g_rec.code = g_rec.err = g_rec.trapno = g_rec.rip = g_rec.hits = 0; }

static void verify(int n, const char* name, u64 at) {
  out("RAW case "); outdec((u64)n); out(" "); out(name);
  out(": signo="); outdec(g_rec.signo);
  out(" code="); outdec(g_rec.code);
  out(" err="); outhex(g_rec.err);
  out(" trapno="); outdec(g_rec.trapno);
  out(" rip_ok="); outdec(g_rec.rip == at);
  out(" hits="); outdec(g_rec.hits);
  out("\n");
  int ok_hits = g_rec.hits == 1, ok_sig = g_rec.signo == SIGILL, ok_code = g_rec.code == ILL_ILLOPN;
  int ok_trap = g_rec.trapno == X86_TRAP_UD, ok_err = g_rec.err == 0, ok_rip = g_rec.rip == at;
  int ok = ok_hits && ok_sig && ok_code && ok_trap && ok_err && ok_rip;
  out(ok ? "PASS: " : "FAIL: ");
  out("case "); outdec((u64)n); out(" "); out(name);
  out(ok_hits ? "" : " [hits]"); out(ok_sig ? "" : " [signo]"); out(ok_code ? "" : " [si_code]");
  out(ok_trap ? "" : " [trapno]"); out(ok_err ? "" : " [err]"); out(ok_rip ? "" : " [rip]");
  out("\n");
  if (!ok) failures++;
}

__attribute__((used)) static void entry_c(void) {
  struct ksigaction act = { (void*)on_sigill, SA_SIGINFO | SA_RESTORER, (void*)restore_rt, 0 };
  check(sc6(SYS_rt_sigaction, SIGILL, (i64)&act, 0, 8, 0, 0) == 0, "install the SIGILL handler");
  u64 at;
  reset_rec(); at = do_ud2();      verify(1, "ud2", at);
  reset_rec(); at = do_ud0();      verify(2, "ud0", at);
  reset_rec(); at = do_push_es();  verify(3, "push-es-invalid-in-64bit", at);
  reset_rec(); at = do_pusha();    verify(4, "pusha-invalid-in-64bit", at);
  reset_rec(); at = do_daa();      verify(5, "daa-invalid-in-64bit", at);
  reset_rec(); at = do_aam();      verify(6, "aam-invalid-in-64bit", at);
  reset_rec(); at = do_lock_reg(); verify(7, "lock-on-register-operand", at);
  out(failures ? "RESULT: FAIL\n" : "RESULT: PASS\n");
  sc6(SYS_exit_group, failures, 0, 0, 0, 0, 0);
}
__attribute__((naked, used)) void _start(void) { __asm__ volatile("and $-16, %rsp\n call entry_c\n"); }
