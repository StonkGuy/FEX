// SPDX-License-Identifier: MIT
//
// Regression test for the lifetime of the FEX_SIGNALTRACE ring, /dev/shm/fex-<pid>-sigtrace.
//
// With FEX_SIGNALTRACE=1 FEX creates a named 16 MiB tmpfs object per process. It used to be left in /dev/shm after the
// process exited, so every traced run leaked 16 MiB of shared memory. FEX now unlinks it on exit_group (a death by
// signal keeps it for post-mortem decoding).
//
// The binary re-execs itself with FEX_SIGNALTRACE=1 as a child that reports whether its ring exists while it runs, then
// exits normally; the parent checks that the name is gone afterwards. On a real kernel the variable is ignored, the
// ring never exists and the test passes with the "during run" check reported as not applicable.
//
// Expected: passes on Linux (native reference) and under the patched FEX; fails under FEX without the fix.
// Build: eac-tests/sigtrace-unlink/build.sh [clang]   (x86-64 binary, run it under FEX)   or   build.sh native (x86-64)
// Run:   ./sigtrace_unlink_test   (exit status = number of failed checks)

typedef long i64;

static inline i64 sc3(i64 nr, i64 a, i64 b, i64 c) {
  i64 ret;
  __asm__ volatile("syscall" : "=a"(ret) : "a"(nr), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
  return ret;
}
static inline i64 sc4(i64 nr, i64 a, i64 b, i64 c, i64 d) {
  i64 ret;
  register i64 r10 __asm__("r10") = d;
  __asm__ volatile("syscall" : "=a"(ret) : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx", "r11", "memory");
  return ret;
}
enum { NR_write = 1, NR_access = 21, NR_getpid = 39, NR_fork = 57, NR_execve = 59, NR_wait4 = 61, NR_exit_group = 231 };

static unsigned long slen(const char* s) {
  unsigned long n = 0;
  while (s[n]) n++;
  return n;
}
static void puts_(const char* s) {
  sc3(NR_write, 1, (i64)s, slen(s));
}
static void trace_path(char* buf, i64 pid) {
  const char* a = "/dev/shm/fex-";
  const char* b = "-sigtrace";
  char d[24];
  int n = 0, i = 0;
  while (*a) buf[i++] = *a++;
  do { d[n++] = '0' + pid % 10; pid /= 10; } while (pid);
  while (n) buf[i++] = d[--n];
  while (*b) buf[i++] = *b++;
  buf[i] = 0;
}
static int exists(i64 pid) {
  char p[64];
  trace_path(p, pid);
  return sc3(NR_access, (i64)p, 0, 0) == 0;
}

static int run(char** argv) {
  // Child mode: report whether this process's ring exists while it runs, then leave through exit_group.
  if (argv[1] && argv[1][0] == 'c') {
    sc3(NR_exit_group, exists(sc3(NR_getpid, 0, 0, 0)) ? 10 : 11, 0, 0);
  }
  int fails = 0;
  i64 pid = sc3(NR_fork, 0, 0, 0);
  if (pid == 0) {
    char* cargv[] = {argv[0], "c", 0};
    char* cenv[] = {"FEX_SIGNALTRACE=1", 0};
    sc3(NR_execve, (i64)"/proc/self/exe", (i64)cargv, (i64)cenv);
    sc3(NR_exit_group, 12, 0, 0);
  }
  int status = 0;
  sc4(NR_wait4, pid, (i64)&status, 0, 0);
  int code = (status & 0x7f) ? -1 : (status >> 8) & 0xff;
  if (code == 10) {
    puts_("ok   ring exists while the traced process runs\n");
  } else if (code == 11) {
    puts_("n/a  no ring while running (not under FEX)\n");
  } else {
    puts_("FAIL child did not report (exec/exit failed)\n");
    fails++;
  }
  if (exists(pid)) {
    puts_("FAIL /dev/shm/fex-<pid>-sigtrace still exists after a normal exit\n");
    char p[64];
    trace_path(p, pid);
    sc3(87 /* unlink */, (i64)p, 0, 0); // do not leak 16 MiB per failing run
    fails++;
  } else {
    puts_("ok   ring name gone after a normal exit\n");
  }
  puts_(fails ? "RESULT: FAIL\n" : "RESULT: PASS\n");
  return fails;
}

__attribute__((used)) static void start_c(long* sp) {
  char** argv = (char**)(sp + 1);
  sc3(NR_exit_group, run(argv), 0, 0);
}
__asm__(".globl _start\n_start:\n  mov %rsp, %rdi\n  and $-16, %rsp\n  call start_c\n  hlt\n");
