// SPDX-License-Identifier: MIT
//
// Regression test: another process can write into a code page once the guest has made it writable.
//
// On Linux, process_vm_writev() reaches the target's pages through pin_user_pages_remote() with FOLL_WRITE and without
// FOLL_FORCE (mm/process_vm_access.c), so it succeeds exactly when the target page is mapped writable. Wine's
// NtWriteVirtualMemory is wineserver's process_vm_writev; a hook installer calls
// NtProtectVirtualMemory(PAGE_EXECUTE_READWRITE) on a code page and then writes its jump with NtWriteVirtualMemory.
//
// Under FEX with SMCChecks=mtrack the host page of translated guest code is write-protected. A write by the guest
// itself faults into FEX and is let through; a write from another process takes no fault and fails with EFAULT,
// even though the guest mapped the page RWX. The protection comes back whenever code is translated from the page
// again, so the page only has to be executed after the mprotect (other threads keep running a hooked ntdll page).
//
// Steps: map a page with `mov eax, 1; ret`, mprotect it RX and call it, mprotect it RWX and call it again; a forked
// child writes `mov eax, 2; ret` into the parent's page with process_vm_writev; the parent calls the page again.
// Checks:
//   1. process_vm_writev writes all 6 bytes;
//   2. the parent then executes the new code (returns 2).
//
// process_vm_writev needs PTRACE_MODE_ATTACH access, so with Yama ptrace_scope 1 the parent first allows it with
// prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) (EINVAL without Yama is harmless).
//
// Not covered: PTRACE_POKEDATA. It uses FOLL_FORCE and succeeds natively even on a read-only page; under FEX's ptrace
// emulation (patch 0001) a POKEDATA into a FEX tracee is a different code path and is left out of this test.
//
// Expected: passes on x86-64 Linux (derived from the kernel source above; the x86 reference box was offline when this
// test was written) and with the change; check 1 and 2 fail on eac-2610.1.
// Build: eac-tests/smc-remote-write/build.sh [clang]   (x86-64 binary, run it under FEX)
// Run:   ./smc_remote_write_test   (exit status = number of failed checks)

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
#define sc4(n, a, b, c, d) sc6(n, (i64)(a), (i64)(b), (i64)(c), (i64)(d), 0, 0)
enum { SYS_write = 1, SYS_mmap = 9, SYS_mprotect = 10, SYS_fork = 57, SYS_exit = 60, SYS_wait4 = 61, SYS_getppid = 110,
       SYS_prctl = 157, SYS_exit_group = 231, SYS_process_vm_writev = 311 };
enum { PR_SET_PTRACER = 0x59616d61 };
enum { PROT_READ = 1, PROT_WRITE = 2, PROT_EXEC = 4, MAP_PRIVATE = 2, MAP_ANONYMOUS = 0x20 };

struct iovec { void* base; u64 len; };

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

static const unsigned char Code1[6] = {0xb8, 1, 0, 0, 0, 0xc3}; // mov eax, 1; ret
static const unsigned char Code2[6] = {0xb8, 2, 0, 0, 0, 0xc3}; // mov eax, 2; ret

static int call(volatile unsigned char* page) {
  return ((int (*)(void))page)();
}

__attribute__((noreturn)) static void finish(void) {
  out(failures ? "RESULT: FAIL\n" : "RESULT: PASS\n");
  sc1(SYS_exit_group, failures);
  __builtin_unreachable();
}

void _start_c(void) {
  volatile unsigned char* page = (volatile unsigned char*)sc6(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE,
                                                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if ((i64)page < 0) { check(0, "mmap"); finish(); }
  for (int i = 0; i < 6; i++) page[i] = Code1[i];

  sc3(SYS_mprotect, page, 4096, PROT_READ | PROT_EXEC);
  check(call(page) == 1, "code runs from the RX page");
  sc3(SYS_mprotect, page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
  check(call(page) == 1, "code runs from the page after mprotect(RWX)");

  // Under Yama ptrace_scope 1 a child may not access its parent's memory unless the parent allows it.
  sc3(SYS_prctl, PR_SET_PTRACER, -1 /* PR_SET_PTRACER_ANY */, 0);
  i64 pid = sc1(SYS_fork, 0);
  if (pid == 0) {
    struct iovec local = {(void*)Code2, sizeof(Code2)};
    struct iovec remote = {(void*)page, sizeof(Code2)};
    i64 r = sc6(SYS_process_vm_writev, sc1(SYS_getppid, 0), (i64)&local, 1, (i64)&remote, 1, 0);
    if (r != sizeof(Code2)) { out("  child: process_vm_writev returned "); out_dec(r); out("\n"); }
    sc1(SYS_exit, r == sizeof(Code2) ? 0 : 1);
  }
  int status = -1;
  sc4(SYS_wait4, pid, (i64)&status, 0, 0);
  check(pid > 0 && status == 0, "process_vm_writev from another process writes the RWX code page");
  int got = call(page);
  check(got == 2, "the page executes the code written by the other process");
  if (got != 2) { out("  returned "); out_dec(got); out("\n"); }
  finish();
}

__asm__(".globl _start\n_start:\n  andq $-16, %rsp\n  call _start_c\n  hlt\n");
