// SPDX-License-Identifier: MIT
//
// Regression test: exec of a file descriptor passes argv and envp through unchanged.
//
// Linux hands the new program exactly the argv and envp given to execve/execveat, whatever names the file: a path,
// an FD with AT_EMPTY_PATH (glibc's fexecve()), or the /proc/self/fd/N link (fexecve()'s fallback). Under FEX without
// a binfmt_misc registration, an FD execveat goes through the FEX loader with the FD in `FEX_EXECVEFD`, and the
// caller's argv[0] used to be dropped on the way: argv {"custom-argv0", "a", "b"} arrived as {"a", "b"}.
//
// Each case forks and execs this binary with FDEXEC_CHILD=1 in the environment; the child compares its argv and
// envp with the expected lists and exits 42 when both match exactly. Cases: path execve (control), fexecve()
// (execveat(fd, "", argv, envp, AT_EMPTY_PATH)), the same with an FD_CLOEXEC fd, and execve of /proc/self/fd/N.
// Run it with and without FEX's binfmt_misc registration: with it, a plain FD exec goes straight to the kernel and an
// FD_CLOEXEC one still goes through the FEX loader.
// The same source builds for x86-64 (run under FEX) and for the host architecture (reference run on a real kernel).
// Build: eac-tests/fdexec-argv/build.sh [clang]   (x86-64 binary, run it under FEX)   or   build.sh native
// Run:   ./fdexec_argv_test   (exit status = number of failed checks)

typedef unsigned long u64;
typedef long i64;

// ------------------------------------------------------------------------------------------------------
// raw syscalls (no libc)
// ------------------------------------------------------------------------------------------------------
#if defined(__x86_64__)
static inline i64 sc6(i64 nr, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f) {
  i64 ret;
  register i64 r10 __asm__("r10") = d;
  register i64 r8 __asm__("r8") = e;
  register i64 r9 __asm__("r9") = f;
  __asm__ volatile("syscall" : "=a"(ret) : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
  return ret;
}
enum { SYS_write = 1, SYS_close = 3, SYS_clone = 56, SYS_execve = 59, SYS_wait4 = 61, SYS_exit_group = 231,
       SYS_openat = 257, SYS_readlinkat = 267, SYS_execveat = 322 };
#elif defined(__aarch64__)
static inline i64 sc6(i64 nr, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f) {
  register i64 x8 __asm__("x8") = nr;
  register i64 x0 __asm__("x0") = a;
  register i64 x1 __asm__("x1") = b;
  register i64 x2 __asm__("x2") = c;
  register i64 x3 __asm__("x3") = d;
  register i64 x4 __asm__("x4") = e;
  register i64 x5 __asm__("x5") = f;
  __asm__ volatile("svc 0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "memory");
  return x0;
}
enum { SYS_write = 64, SYS_close = 57, SYS_clone = 220, SYS_execve = 221, SYS_wait4 = 260, SYS_exit_group = 94,
       SYS_openat = 56, SYS_readlinkat = 78, SYS_execveat = 281 };
#else
#error "x86-64 and aarch64 only"
#endif
#define sc1(n, a) sc6(n, (i64)(a), 0, 0, 0, 0, 0)
#define sc3(n, a, b, c) sc6(n, (i64)(a), (i64)(b), (i64)(c), 0, 0, 0)
#define sc4(n, a, b, c, d) sc6(n, (i64)(a), (i64)(b), (i64)(c), (i64)(d), 0, 0)
#define sc5(n, a, b, c, d, e) sc6(n, (i64)(a), (i64)(b), (i64)(c), (i64)(d), (i64)(e), 0)

enum { AT_FDCWD = -100, AT_EMPTY_PATH = 0x1000 };
enum { O_RDONLY = 0, O_CLOEXEC = 02000000 };
enum { SIGCHLD = 17, CHILD_OK = 42 };

// ------------------------------------------------------------------------------------------------------
// helpers (no libc)
// ------------------------------------------------------------------------------------------------------
static u64 slen(const char* s) { u64 n = 0; while (s[n]) ++n; return n; }
static int same(const char* a, const char* b) { while (*a && *a == *b) { ++a; ++b; } return *a == *b; }
static void out(const char* s) { sc3(SYS_write, 1, s, slen(s)); }
static void cat(char* d, const char* s) { d += slen(d); while ((*d++ = *s++)) {} }
static void num(char* d, u64 v) {
  char t[24]; int n = 0;
  do { t[n++] = '0' + v % 10; v /= 10; } while (v);
  d += slen(d);
  while (n) *d++ = t[--n];
  *d = 0;
}
static int failures;
static void check(int ok, const char* what) {
  out(ok ? "PASS: " : "FAIL: "); out(what); out("\n"); if (!ok) ++failures;
}

// What every child is started with. argv[0] differs from the file name on purpose; an empty argument and one with
// a space must survive as they are.
static char* const g_argv[] = {"custom-argv0", "first", "", "with space", "last", 0};
static char* const g_envp[] = {"FDEXEC_CHILD=1", "FDEXEC_B=x y", "FDEXEC_C=", 0};

static int list_equal(char** got, char* const* want, const char* what) {
  int i = 0, ok = 1;
  for (; want[i] && got[i]; ++i)
    if (!same(got[i], want[i])) {
      out("  child: "); out(what); out(" differs: got ["); out(got[i]); out("] expected ["); out(want[i]); out("]\n");
      ok = 0;
    }
  if (want[i] || got[i]) {
    out("  child: "); out(what); out(want[i] ? " is shorter than expected\n" : " is longer than expected\n");
    ok = 0;
  }
  return ok;
}

// Runs one exec in a forked child; returns its exit status (or 256 + signal, or -1).
static int run_case(i64 nr, i64 a, i64 b, i64 c, i64 d, i64 e) {
  i64 pid = sc5(SYS_clone, SIGCHLD, 0, 0, 0, 0);
  if (pid < 0) return -1;
  if (pid == 0) {
    i64 r = sc6(nr, a, b, c, d, e, 0);
    out("  exec returned an error\n");
    sc1(SYS_exit_group, r < 0 ? (int)-r : 1);
  }
  int status = 0;
  if (sc4(SYS_wait4, pid, &status, 0, 0) != pid) return -1;
  if ((status & 0x7f) == 0) return (status >> 8) & 0xff;
  return 256 + (status & 0x7f);
}

static void report(const char* what, int got) {
  char line[256] = "";
  cat(line, what);
  if (got != CHILD_OK) { cat(line, " (child status "); num(line, (u64)(i64)got); cat(line, ")"); }
  check(got == CHILD_OK, line);
}

__attribute__((used)) static void entry_c(u64* sp) {
  int argc = (int)sp[0];
  char** argv = (char**)(sp + 1);
  char** envp = argv + argc + 1;
  for (char** e = envp; *e; ++e)
    if (same(*e, "FDEXEC_CHILD=1")) {
      int ok = list_equal(argv, g_argv, "argv");
      ok &= list_equal(envp, g_envp, "envp");
      sc1(SYS_exit_group, ok ? CHILD_OK : 1);
    }

  static char self[4096], fdpath[64];
  i64 n = sc4(SYS_readlinkat, AT_FDCWD, "/proc/self/exe", self, sizeof(self) - 1);
  check(n > 0, "readlink /proc/self/exe");
  if (n <= 0) { out("RESULT: FAIL\n"); sc1(SYS_exit_group, 1); }
  self[n] = 0;

  i64 efd = sc4(SYS_openat, AT_FDCWD, self, O_RDONLY, 0);
  i64 efd_cloexec = sc4(SYS_openat, AT_FDCWD, self, O_RDONLY | O_CLOEXEC, 0);
  check(efd >= 0 && efd_cloexec >= 0, "open this binary");
  cat(fdpath, "/proc/self/fd/");
  num(fdpath, (u64)efd);

  report("path execve passes argv and envp unchanged",
         run_case(SYS_execve, (i64)self, (i64)g_argv, (i64)g_envp, 0, 0));
  report("fexecve(): execveat(fd, \"\", AT_EMPTY_PATH) passes argv and envp unchanged",
         run_case(SYS_execveat, efd, (i64)"", (i64)g_argv, (i64)g_envp, AT_EMPTY_PATH));
  report("execveat of an FD_CLOEXEC fd passes argv and envp unchanged",
         run_case(SYS_execveat, efd_cloexec, (i64)"", (i64)g_argv, (i64)g_envp, AT_EMPTY_PATH));
  report("execve(\"/proc/self/fd/N\") (fexecve() fallback) passes argv and envp unchanged",
         run_case(SYS_execve, (i64)fdpath, (i64)g_argv, (i64)g_envp, 0, 0));

  out(failures ? "RESULT: FAIL\n" : "RESULT: PASS\n");
  sc1(SYS_exit_group, failures);
}
#if defined(__x86_64__)
__attribute__((naked, used)) void _start(void) { __asm__ volatile("mov %rsp, %rdi\n and $-16, %rsp\n call entry_c\n"); }
#else
__asm__(".text\n.globl _start\n_start:\n mov x0, sp\n bl entry_c\n");
#endif
