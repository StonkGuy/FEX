// SPDX-License-Identifier: MIT
//
// Regression test: system calls given a bad user pointer return -EFAULT and the process survives (FEX-Emu issue #3942).
//
// On x86-64 Linux every user pointer a system call reads or writes goes through copy_from_user/copy_to_user/get_user/
// put_user (or strncpy_from_user for paths); a fault there is caught by the exception table and turns into -EFAULT. A
// pointer into a PROT_NONE page, or a structure that starts on a readable page and runs into a PROT_NONE one, never
// kills the caller.
//
// Under FEX most system calls pass straight through to the host kernel and behave the same. The ones FEX implements
// itself (signal state, sigaltstack, uname, paths it rewrites, execve, seccomp filters...) read or write guest memory
// from host C++ code: a bad pointer there faults inside FEX instead.
//
// Each case runs in a forked child that exits 0 when the call returned -EFAULT, 1 for another result, and is reported
// as "crashed" if a signal killed it. Expected: PASS on x86-64 Linux (kernel 6.19), FAIL on eac-2610 before the fix.
// Build: eac-tests/syscall-efault/build.sh [clang]   (x86-64 binary, run it under FEX)
// Run:   FEX_NEEDSSECCOMP=1 ./syscall_efault_test   (exit status = number of failed checks; the variable makes FEX emulate
//        seccomp, which the last case needs, and is ignored natively)

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
#define sc2(n, a, b) sc6(n, (i64)(a), (i64)(b), 0, 0, 0, 0)
#define sc3(n, a, b, c) sc6(n, (i64)(a), (i64)(b), (i64)(c), 0, 0, 0)
#define sc4(n, a, b, c, d) sc6(n, (i64)(a), (i64)(b), (i64)(c), (i64)(d), 0, 0)
#define sc5(n, a, b, c, d, e) sc6(n, (i64)(a), (i64)(b), (i64)(c), (i64)(d), (i64)(e), 0)
enum { SYS_write = 1, SYS_open = 2, SYS_stat = 4, SYS_fstat = 5, SYS_lstat = 6, SYS_poll = 7, SYS_mmap = 9,
       SYS_rt_sigaction = 13, SYS_rt_sigprocmask = 14, SYS_access = 21, SYS_pipe = 22, SYS_select = 23,
       SYS_nanosleep = 35, SYS_getitimer = 36, SYS_socketpair = 53, SYS_fork = 57, SYS_execve = 59, SYS_exit = 60,
       SYS_wait4 = 61, SYS_uname = 63, SYS_readlink = 89, SYS_getrlimit = 97, SYS_sysinfo = 99, SYS_times = 100,
       SYS_getresuid = 118, SYS_rt_sigpending = 127, SYS_rt_sigtimedwait = 128, SYS_sigaltstack = 131,
       SYS_prctl = 157, SYS_arch_prctl = 158, SYS_futex = 202, SYS_sched_getaffinity = 204, SYS_getdents64 = 217,
       SYS_clock_gettime = 228, SYS_clock_nanosleep = 230, SYS_exit_group = 231, SYS_openat = 257,
       SYS_newfstatat = 262, SYS_readlinkat = 267, SYS_faccessat = 269, SYS_pselect6 = 270, SYS_ppoll = 271,
       SYS_pipe2 = 293, SYS_prlimit64 = 302, SYS_getcpu = 309, SYS_seccomp = 317, SYS_getrandom = 318,
       SYS_statx = 332 };
#define EFAULT 14
#define AT_FDCWD -100

static u64 slen(const char* s) { u64 n = 0; while (s[n]) n++; return n; }
static void out(const char* s) { sc3(SYS_write, 1, (i64)s, slen(s)); }
static void out_dec(i64 v) { char b[24]; int i = 23, neg = v < 0; u64 u = neg ? -v : v; b[i] = 0; do { b[--i] = '0' + u % 10; u /= 10; } while (u); if (neg) b[--i] = '-'; out(b + i); }

static int failures;
static char* bad;   // a PROT_NONE page
static char* edge;  // the last 8 bytes of a read-write page directly followed by `bad`
static int futex_word;
static char buf[4096];

// Runs one case in a child; the child exits with 0 when the call returned -EFAULT.
static void expect_efault(const char* what, i64 nr, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f) {
  i64 pid = sc1(SYS_fork, 0);
  if (pid == 0) {
    i64 r = sc6(nr, a, b, c, d, e, f);
    if (r != -EFAULT) { out("    "); out(what); out(" returned "); out_dec(r); out("\n"); }
    sc1(SYS_exit, r == -EFAULT ? 0 : 1);
  }
  int status = 0;
  sc4(SYS_wait4, pid, &status, 0, 0);
  int ok = (status & 0x7f) == 0 && ((status >> 8) & 0xff) == 0;
  out(ok ? "  ok   " : "  FAIL "); out(what);
  if ((status & 0x7f) != 0) { out(" (killed by signal "); out_dec(status & 0x7f); out(")"); }
  out("\n");
  if (!ok) failures++;
}
#define T(what, nr, ...) expect_efault(what, nr, __VA_ARGS__)

__attribute__((used)) void entry_c(void) {
  out("syscall_efault_test: a bad user pointer gives -EFAULT, not a crash\n");
  char* m = (char*)sc6(SYS_mmap, 0, 8192, 3, 0x22, -1, 0);
  sc6(10 /* mprotect */, (i64)(m + 4096), 4096, 0, 0, 0, 0);
  bad = m + 4096;
  edge = bad - 8;
  i64 dirfd = sc3(SYS_open, "/", 0x10000 /* O_DIRECTORY */, 0);
  struct { int fd; short ev, rev; } pfd = {1, 0, 0};
  struct { i64 s, ns; } ts0 = {0, 0};
  u64 set = 0;

  T("poll(bad fds)", SYS_poll, (i64)bad, 1, 0, 0, 0, 0);
  T("ppoll(bad fds)", SYS_ppoll, (i64)bad, 1, 0, 0, 8, 0);
  T("ppoll(bad timespec)", SYS_ppoll, (i64)&pfd, 1, (i64)bad, 0, 8, 0);
  T("ppoll(bad sigset)", SYS_ppoll, (i64)&pfd, 1, (i64)&ts0, (i64)bad, 8, 0);
  T("select(bad readfds)", SYS_select, 1, (i64)bad, 0, 0, (i64)&ts0, 0);
  T("pselect6(bad timespec)", SYS_pselect6, 0, 0, 0, 0, (i64)bad, 0);
  T("rt_sigaction(bad act)", SYS_rt_sigaction, 10, (i64)bad, 0, 8, 0, 0);
  T("rt_sigaction(act across into PROT_NONE)", SYS_rt_sigaction, 10, (i64)edge, 0, 8, 0, 0);
  T("rt_sigaction(bad oldact)", SYS_rt_sigaction, 10, 0, (i64)bad, 8, 0, 0);
  T("rt_sigprocmask(bad set)", SYS_rt_sigprocmask, 0, (i64)bad, 0, 8, 0, 0);
  T("rt_sigprocmask(bad oldset)", SYS_rt_sigprocmask, 0, 0, (i64)bad, 8, 0, 0);
  T("rt_sigpending(bad set)", SYS_rt_sigpending, (i64)bad, 8, 0, 0, 0, 0);
  T("rt_sigtimedwait(bad set)", SYS_rt_sigtimedwait, (i64)bad, 0, (i64)&ts0, 8, 0, 0);
  T("sigaltstack(bad ss)", SYS_sigaltstack, (i64)bad, 0, 0, 0, 0, 0);
  T("sigaltstack(bad old_ss)", SYS_sigaltstack, 0, (i64)bad, 0, 0, 0, 0);
  T("uname(bad)", SYS_uname, (i64)bad, 0, 0, 0, 0, 0);
  T("uname(across into PROT_NONE)", SYS_uname, (i64)edge, 0, 0, 0, 0, 0);
  T("open(bad path)", SYS_open, (i64)bad, 0, 0, 0, 0, 0);
  T("openat(bad path)", SYS_openat, AT_FDCWD, (i64)bad, 0, 0, 0, 0);
  T("access(bad path)", SYS_access, (i64)bad, 0, 0, 0, 0, 0);
  T("faccessat(bad path)", SYS_faccessat, AT_FDCWD, (i64)bad, 0, 0, 0, 0);
  T("stat(bad path)", SYS_stat, (i64)bad, (i64)buf, 0, 0, 0, 0);
  T("stat(bad buf)", SYS_stat, (i64)"/", (i64)bad, 0, 0, 0, 0);
  T("lstat(bad buf)", SYS_lstat, (i64)"/", (i64)bad, 0, 0, 0, 0);
  T("fstat(bad buf)", SYS_fstat, 1, (i64)bad, 0, 0, 0, 0);
  T("newfstatat(bad buf)", SYS_newfstatat, AT_FDCWD, (i64)"/", (i64)bad, 0, 0, 0);
  T("statx(bad buf)", SYS_statx, AT_FDCWD, (i64)"/", 0, 0x7ff, (i64)bad, 0);
  T("readlink(bad path)", SYS_readlink, (i64)bad, (i64)buf, 100, 0, 0, 0);
  T("readlink(/proc/self/exe, bad buf)", SYS_readlink, (i64)"/proc/self/exe", (i64)bad, 100, 0, 0, 0);
  T("readlinkat(/proc/self/exe, bad buf)", SYS_readlinkat, AT_FDCWD, (i64)"/proc/self/exe", (i64)bad, 100, 0, 0);
  T("getdents64(bad buf)", SYS_getdents64, dirfd, (i64)bad, 4096, 0, 0, 0);
  T("execve(bad path)", SYS_execve, (i64)bad, 0, 0, 0, 0, 0);
  T("execve(bad argv)", SYS_execve, (i64)"/proc/self/exe", (i64)bad, 0, 0, 0, 0);
  T("nanosleep(bad req)", SYS_nanosleep, (i64)bad, 0, 0, 0, 0, 0);
  T("clock_nanosleep(bad req)", SYS_clock_nanosleep, 1, 0, (i64)bad, 0, 0, 0);
  T("clock_gettime(bad)", SYS_clock_gettime, 1, (i64)bad, 0, 0, 0, 0);
  T("futex(FUTEX_WAIT, bad timeout)", SYS_futex, (i64)&futex_word, 0, 0, (i64)bad, 0, 0);
  T("getitimer(bad)", SYS_getitimer, 0, (i64)bad, 0, 0, 0, 0);
  T("getrlimit(bad)", SYS_getrlimit, 7, (i64)bad, 0, 0, 0, 0);
  T("prlimit64(bad old)", SYS_prlimit64, 0, 7, 0, (i64)bad, 0, 0);
  T("sysinfo(bad)", SYS_sysinfo, (i64)bad, 0, 0, 0, 0, 0);
  T("times(bad)", SYS_times, (i64)bad, 0, 0, 0, 0, 0);
  T("getresuid(bad)", SYS_getresuid, (i64)bad, (i64)bad, (i64)bad, 0, 0, 0);
  T("pipe(bad)", SYS_pipe, (i64)bad, 0, 0, 0, 0, 0);
  T("pipe2(bad)", SYS_pipe2, (i64)bad, 0, 0, 0, 0, 0);
  T("socketpair(bad sv)", SYS_socketpair, 1, 1, 0, (i64)bad, 0, 0);
  T("sched_getaffinity(bad)", SYS_sched_getaffinity, 0, 128, (i64)bad, 0, 0, 0);
  T("getcpu(bad)", SYS_getcpu, (i64)bad, 0, 0, 0, 0, 0);
  T("arch_prctl(ARCH_GET_FS, bad)", SYS_arch_prctl, 0x1003, (i64)bad, 0, 0, 0, 0);
  T("getrandom(bad)", SYS_getrandom, (i64)bad, 16, 0, 0, 0, 0);
  sc5(SYS_prctl, 38 /* PR_SET_NO_NEW_PRIVS */, 1, 0, 0, 0);
  T("seccomp(SET_MODE_FILTER, bad prog)", SYS_seccomp, 1, 0, (i64)bad, 0, 0, 0);
  (void)set;

  out(failures ? "RESULT: FAIL\n" : "RESULT: PASS\n");
  sc1(SYS_exit_group, failures);
}

__attribute__((naked, used)) void _start(void) { __asm__ volatile("mov %rsp, %rdi\n and $-16, %rsp\n call entry_c\n"); }
