// SPDX-License-Identifier: MIT
//
// Regression test: a SECCOMP_RET_TRAP syscall is never executed, and its SIGSYS is forced like Linux forces it.
//
// Linux (kernel/seccomp.c, __seccomp_filter): for SECCOMP_RET_TRAP the kernel rolls the registers back
// (syscall_rollback(), RAX = the syscall number), calls force_sig_seccomp() and skips the syscall. force_sig_seccomp()
// uses force_sig_info_to_task() with HANDLER_CURRENT (kernel/signal.c): when the thread blocks SIGSYS or ignores it,
// the disposition is reset to SIG_DFL and SIGSYS is unblocked, so the process dies from SIGSYS. The trapped syscall
// does not run in any case.
//
// FEX queued the SIGSYS as an ordinary asynchronous signal and then carried on into the syscall. With SIGSYS
// delivered at once that did not matter (the guest handler's rt_sigreturn abandons the syscall handler), but with
// SIGSYS blocked or ignored the signal stayed pending or was dropped and the trapped syscall ran as a Linux syscall:
// the process kept going with the result of a syscall its filter had refused. Under Wine, whose filter traps the raw
// NT syscalls of Windows code, that is an NT service number executed as an unrelated Linux syscall.
//
// Each case runs in a forked child that installs a filter trapping write() to one pipe, then writes one byte there:
//   1. SIGSYS handled: the handler runs once, the RAX it writes is the result, nothing reaches the pipe;
//   2. SIGSYS blocked: the child dies from SIGSYS and nothing reaches the pipe;
//   3. SIGSYS ignored: the child dies from SIGSYS and nothing reaches the pipe.
// The children disable core dumps first (RLIMIT_CORE = 0).
//
// Expected: passes on x86-64 Linux. On eac-2610.2 case 2 fails (the child survives and the byte is written); case 3
// already passes there, as FEX lets the host default action of an ignored queued SIGSYS kill the process.
// Build: eac-tests/seccomp-trap-blocked/build.sh [clang]   (x86-64 binary, run it under FEX)
// Run:   FEX_NEEDSSECCOMP=1 ./seccomp_trap_blocked_test   (exit status = number of failed checks)

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

static inline i64 sc6(i64 nr, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f) {
  i64 ret;
  register i64 r10 __asm__("r10") = d;
  register i64 r8 __asm__("r8") = e;
  register i64 r9 __asm__("r9") = f;
  __asm__ volatile("syscall" : "=a"(ret) : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
  return ret;
}
#define sc1(n, a) sc6(n, (i64)(a), 0, 0, 0, 0, 0)
#define sc2(n, a, b) sc6(n, (i64)(a), (i64)(b), 0, 0, 0, 0)
#define sc3(n, a, b, c) sc6(n, (i64)(a), (i64)(b), (i64)(c), 0, 0, 0)
#define sc4(n, a, b, c, d) sc6(n, (i64)(a), (i64)(b), (i64)(c), (i64)(d), 0, 0)
enum { SYS_read = 0, SYS_write = 1, SYS_rt_sigaction = 13, SYS_rt_sigprocmask = 14, SYS_fork = 57, SYS_exit = 60,
       SYS_wait4 = 61, SYS_prctl = 157, SYS_setrlimit = 160, SYS_exit_group = 231, SYS_pipe2 = 293, SYS_seccomp = 317 };
enum { SIGSYS = 31, SIG_BLOCK = 0, O_NONBLOCK = 04000, RLIMIT_CORE = 4, EAGAIN = 11 };
enum { PR_SET_NO_NEW_PRIVS = 38, SECCOMP_SET_MODE_FILTER = 1 };
enum { REG_RAX = 13 };
#define SA_SIGINFO 0x4
#define SA_RESTORER 0x04000000
#define SIG_IGN ((void*)1)

struct ksigaction { void* handler; u64 flags; void* restorer; u64 mask; };
struct sock_filter { u16 code; u8 jt, jf; u32 k; };
struct sock_fprog { u16 len; struct sock_filter* filter; };
struct rlimit { u64 cur, max; };
__attribute__((naked, used)) static void restore_rt(void) { __asm__ volatile("mov $15, %eax\n syscall\n"); }

static u64 slen(const char* s) { u64 n = 0; while (s[n]) n++; return n; }
static void out(const char* s) { sc3(SYS_write, 1, (i64)s, slen(s)); }
static void out_dec(i64 v) {
  char b[24]; int i = 23; b[i] = 0; int neg = v < 0; u64 u = neg ? -v : v;
  do { b[--i] = '0' + u % 10; u /= 10; } while (u);
  if (neg) b[--i] = '-';
  out(b + i);
}

static int failures;
static void check(int ok, const char* what) { out(ok ? "  ok   " : "  FAIL "); out(what); out("\n"); if (!ok) failures++; }

static int pipefd[2];
static volatile int handled;
static void sigsys_handler(int sig, void* info, void* uc) {
  (void)sig; (void)info;
  handled++;
  ((i64*)((char*)uc + 40))[REG_RAX] = -1234; // uc_mcontext.gregs[REG_RAX]
}

enum Mode { HANDLED, BLOCKED, IGNORED };

// Child: install the disposition, the filter (trap write() to the pipe's write end, allow everything else) and write.
// Exit status: 0 when the handled case behaved, 42 when the trapped write returned (SIGSYS did not end the process).
__attribute__((noreturn)) static void child(enum Mode mode) {
  struct rlimit nocore = {0, 0};
  sc2(SYS_setrlimit, RLIMIT_CORE, &nocore);

  struct ksigaction act = {mode == IGNORED ? SIG_IGN : (void*)sigsys_handler, SA_SIGINFO | SA_RESTORER, (void*)restore_rt, 0};
  sc4(SYS_rt_sigaction, SIGSYS, &act, 0, 8);
  if (mode == BLOCKED) {
    u64 set = 1UL << (SIGSYS - 1);
    sc4(SYS_rt_sigprocmask, SIG_BLOCK, &set, 0, 8);
  }

  struct sock_filter filter[] = {
    {0x20, 0, 0, 0},                      // A = nr
    {0x15, 0, 3, SYS_write},              // nr == write ? : allow
    {0x20, 0, 0, 16},                     // A = args[0] (low 32 bits)
    {0x15, 0, 1, (u32)pipefd[1]},         // fd == pipe write end ? : allow
    {0x06, 0, 0, 0x00030000},             // SECCOMP_RET_TRAP
    {0x06, 0, 0, 0x7fff0000},             // SECCOMP_RET_ALLOW
  };
  struct sock_fprog prog = {sizeof(filter) / sizeof(filter[0]), filter};
  sc6(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0);
  if (sc3(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) != 0) {
    sc1(SYS_exit, 10);
  }

  i64 r = sc3(SYS_write, pipefd[1], "x", 1);
  if (mode == HANDLED) {
    sc1(SYS_exit, (r == -1234 && handled == 1) ? 0 : 1);
  }
  sc1(SYS_exit, 42);
  __builtin_unreachable();
}

static int run(enum Mode mode) {
  i64 pid = sc1(SYS_fork, 0);
  if (pid == 0) {
    child(mode);
  }
  int status = -1;
  sc4(SYS_wait4, pid, &status, 0, 0);
  return status;
}

// The trapped write never ran: the pipe is empty.
static int pipe_empty(void) {
  char c;
  return sc3(SYS_read, pipefd[0], &c, 1) == -EAGAIN;
}

static void report_status(int status) {
  out("    wait status ");
  out_dec(status);
  if ((status & 0x7f) == 0) { out(" (exit "); out_dec((status >> 8) & 0xff); out(")"); }
  else { out(" (signal "); out_dec(status & 0x7f); out(")"); }
  out("\n");
}

void _start_c(void) {
  if (sc2(SYS_pipe2, pipefd, O_NONBLOCK) != 0) {
    check(0, "pipe2");
    out("RESULT: FAIL\n");
    sc1(SYS_exit_group, 1);
  }

  int status = run(HANDLED);
  check(status == 0, "SIGSYS handled: the handler runs once and its RAX is the result of the trapped write");
  if (status != 0) report_status(status);
  check(pipe_empty(), "SIGSYS handled: the trapped write is not executed");

  status = run(BLOCKED);
  check((status & 0x7f) == SIGSYS, "SIGSYS blocked: the process dies from SIGSYS");
  if ((status & 0x7f) != SIGSYS) report_status(status);
  check(pipe_empty(), "SIGSYS blocked: the trapped write is not executed");

  status = run(IGNORED);
  check((status & 0x7f) == SIGSYS, "SIGSYS ignored: the process dies from SIGSYS");
  if ((status & 0x7f) != SIGSYS) report_status(status);
  check(pipe_empty(), "SIGSYS ignored: the trapped write is not executed");

  out(failures ? "RESULT: FAIL\n" : "RESULT: PASS\n");
  sc1(SYS_exit_group, failures);
}

__asm__(".globl _start\n_start:\n  andq $-16, %rsp\n  call _start_c\n  hlt\n");
