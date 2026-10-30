// SPDX-License-Identifier: MIT
//
// Regression test for Proton's "native syscalls" hack for Easy Anti-Cheat (Valve Wine experimental_11.0, ntdll:
// "HACK: Allow native syscalls for EAC", CW-Bug-Id #27869). Wine 11 traps raw `syscall`s from Windows code with
// Syscall User Dispatch (SUD): the allowed region is libc's text, the selector byte in the TEB says BLOCK while Windows
// code runs. When start_protected_game.exe is launched Wine sets WINE_HACK_NATIVE_SYSCALLS=1, and EAC's bootstrapper
// then makes raw Linux syscalls from its own code at 0x7001'0000'0000 (memfd_create(name, MFD_ALLOW_SEALING) first).
// sigsys_handler sees such a trap from above 0x7000'0000'0000, re-arms SUD from inside the handler with the allowed
// region [0x7001'0000'0000, 0x7fff'ffff'0000) (which on x86-64 Linux also covers libc, so its rt_sigreturn restorer
// stays allowed), moves rip back by 2 and returns: the same syscall is retried and now runs as a Linux syscall.
//
// The test does exactly that, ITERS times: libc is a page at LIBC_PAGE (inside the re-armed region) holding the syscall
// gadget the handler uses and the signal restorer; EAC's code is a stub at NATIVE_PAGE whose `syscall` sits at +0xf, as
// in the crash dump of start_protected_game.exe under FEX (rip 0x70010000000f, rax 0x13f). Checked on every trap:
//   - siginfo: SIGSYS, si_code SYS_USER_DISPATCH (2), si_errno 0, si_call_addr just past the syscall, si_syscall 319,
//     si_arch AUDIT_ARCH_X86_64
//   - ucontext: rip just past the syscall, rax 319, rdi/rsi the arguments, rcx/r11 as `syscall` left them
//   - %gs:0x30 inside the handler is the "TEB" set with ARCH_SET_GS (Wine's handler finds its thread data through it)
// and on every iteration: exactly one trap, the retried syscall returns a descriptor, and that descriptor is the memfd
// created with the stub's name (/proc/self/fd/N -> "/memfd:<name> (deleted)"), i.e. the retry ran with the original
// arguments.
// Expected: passes on a Linux x86-64 kernel >= 5.11 (Syscall User Dispatch).
// Build: eac-tests/sud-native-retry/build.sh [clang] [output]
// Run:   ./sud_native_retry_test   (exit status = number of failed checks)

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

enum { SYS_read = 0, SYS_write = 1, SYS_close = 3, SYS_mmap = 9, SYS_rt_sigaction = 13, SYS_prctl = 157,
       SYS_arch_prctl = 158, SYS_exit_group = 231, SYS_readlinkat = 267, SYS_memfd_create = 319 };
enum { SIGSYS = 31, SA_SIGINFO = 4, SA_RESTORER = 0x04000000 };
enum { PR_SET_SYSCALL_USER_DISPATCH = 59, PR_SYS_DISPATCH_ON = 1, PR_SYS_DISPATCH_OFF = 0 };
enum { ARCH_SET_GS = 0x1001, MFD_ALLOW_SEALING = 2, AT_FDCWD = -100 };
enum { AUDIT_ARCH_X86_64 = 0xC000003Eu };
enum { R8 = 0, R9, R10, R11, R12, R13, R14, R15, RDI, RSI, RBP, RBX, RDX, RAX, RCX, RSP, RIP, EFL };
#define GREG(uc, r) (((u64*)((char*)(uc) + 40))[r])

#define NATIVE_PAGE 0x700100000000UL   // EAC's code (Wine: re-armed region starts here)
#define NATIVE_END 0x7fffffff0000UL    // Wine: end of the re-armed region
#define LIBC_PAGE 0x7ffe00000000UL     // stands in for libc: allowed before the re-arm, inside the region after it
#define ITERS 2000

static u64 slen(const char* s) { u64 n = 0; while (s[n]) ++n; return n; }
static void out(const char* s) { sc3(SYS_write, 1, s, slen(s)); }
static void outhex(u64 v) {
  char b[19]; b[0] = '0'; b[1] = 'x';
  for (int i = 0; i < 16; ++i) { int d = (v >> (60 - 4 * i)) & 15; b[2 + i] = d < 10 ? '0' + d : 'a' + d - 10; }
  b[18] = 0; out(b);
}
static int failures;
static void check(int ok, const char* what) { out(ok ? "PASS: " : "FAIL: "); out(what); out("\n"); if (!ok) ++failures; }
static void kv(const char* k, u64 v) { out("  "); out(k); out("="); outhex(v); out("\n"); }

// "libc": a syscall gadget (SysV arguments: nr, a, b, c, d, e) and the rt_sigreturn restorer.
__asm__(".section .rodata\n.globl libc_start\nlibc_start:\n"
        ".globl libc_syscall\nlibc_syscall:\n"
        "  mov %rdi, %rax\n  mov %rsi, %rdi\n  mov %rdx, %rsi\n  mov %rcx, %rdx\n  mov %r8, %r10\n  mov %r9, %r8\n"
        "  syscall\n  ret\n"
        ".globl libc_restore_rt\nlibc_restore_rt:\n  mov $15, %eax\n  syscall\n  ud2\n"
        ".globl libc_end\nlibc_end:\n"
        // EAC's code: memfd_create(rdi = name, rsi = flags) with the `syscall` at +0xf
        ".globl native_start\nnative_start:\n  .fill 10, 1, 0x90\n  mov $0x13f, %eax\n"
        ".globl native_syscall\nnative_syscall:\n  syscall\n  ret\n"
        ".globl native_end\nnative_end:\n.text\n");
extern const unsigned char libc_start[], libc_syscall[], libc_restore_rt[], libc_end[];
extern const unsigned char native_start[], native_syscall[], native_end[];
#define LP(sym) (LIBC_PAGE + (u64)((sym) - libc_start))
#define NP(sym) (NATIVE_PAGE + (u64)((sym) - native_start))

typedef i64 (*libc_syscall_fn)(i64 nr, i64 a, i64 b, i64 c, i64 d, i64 e);
typedef i64 (*native_fn)(const char* name, i64 flags);
#define LIBC_SYSCALL ((libc_syscall_fn)LP(libc_syscall))

static unsigned char selector;      // Wine: amd64_thread_data.syscall_dispatch in the TEB
static u64 teb[16];                 // fake TEB: teb[6] (%gs:0x30) points to itself, like NtCurrentTeb()
static const char name[] = "2c6e4827-dc19-43a5-sud-native-retry";
static u64 traps, bad, first_bad, snap[16];

static void mark(u64 bit) { if (!bad) first_bad = bit; bad |= bit; }

// Wine's sigsys_handler, native-syscall branch. Runs with the selector still BLOCK: every syscall it makes goes
// through "libc", the region SUD allows.
__attribute__((used)) static void handler(int sig, void* info, void* uc) {
  u32* si = (u32*)info;
  const u64 after = NP(native_syscall) + 2;
  traps++;
  u64 gs_self;
  __asm__ volatile("mov %%gs:0x30, %0" : "=r"(gs_self));
  if (si[0] != SIGSYS) mark(1);
  if (si[2] != 2 /* SYS_USER_DISPATCH */) mark(2);
  if (si[1] != 0) mark(4);
  if (*(u64*)((char*)info + 16) != after) mark(8);
  if (si[6] != SYS_memfd_create) mark(0x10);
  if (si[7] != AUDIT_ARCH_X86_64) mark(0x20);
  if (GREG(uc, RIP) != after) mark(0x40);
  if (GREG(uc, RAX) != SYS_memfd_create) mark(0x80);
  if (GREG(uc, RDI) != (u64)name || GREG(uc, RSI) != MFD_ALLOW_SEALING) mark(0x100);
  if (GREG(uc, RCX) != after || GREG(uc, R11) != GREG(uc, EFL)) mark(0x200);
  if (gs_self != (u64)teb) mark(0x400);
  if (traps == 1) {
    snap[0] = si[0]; snap[1] = si[1]; snap[2] = si[2]; snap[3] = *(u64*)((char*)info + 16); snap[4] = si[6];
    snap[5] = si[7]; snap[6] = GREG(uc, RIP); snap[7] = GREG(uc, RAX); snap[8] = GREG(uc, RCX); snap[9] = gs_self;
  }
  if ((GREG(uc, RIP) >> 32) > 0x7000) {
    if (LIBC_SYSCALL(SYS_prctl, PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, NATIVE_PAGE, NATIVE_END - NATIVE_PAGE,
                     (i64)&selector) != 0) mark(0x800);
    GREG(uc, RIP) -= 2;   // retry the syscall
    return;
  }
  mark(0x1000);           // a trap from anywhere else (the handler's own syscalls, the restorer) is a failure
}

struct ksigaction { void* handler; u64 flags; void* restorer; u64 mask; };

// Decimal for /proc/self/fd/N.
static char* utoa(u64 v, char* end) { *--end = 0; do { *--end = '0' + v % 10; v /= 10; } while (v); return end; }

__attribute__((used)) void entry_c(void) {
  i64 m = sc6(SYS_mmap, LIBC_PAGE, 4096, 7, 0x22 | 0x100000 /* MAP_FIXED_NOREPLACE */, -1, 0);
  i64 n = sc6(SYS_mmap, NATIVE_PAGE, 4096, 7, 0x22 | 0x100000, -1, 0);
  if (m != (i64)LIBC_PAGE || n != (i64)NATIVE_PAGE) { out("mmap failed\nRESULT: FAIL\n"); sc2(SYS_exit_group, 1, 0); }
  for (u64 i = 0; i < (u64)(libc_end - libc_start); ++i) ((unsigned char*)LIBC_PAGE)[i] = libc_start[i];
  for (u64 i = 0; i < (u64)(native_end - native_start); ++i) ((unsigned char*)NATIVE_PAGE)[i] = native_start[i];

  teb[6] = (u64)teb;
  check(sc2(SYS_arch_prctl, ARCH_SET_GS, teb) == 0, "ARCH_SET_GS (Wine's TEB)");
  struct ksigaction a = {(void*)handler, SA_SIGINFO | SA_RESTORER, (void*)LP(libc_restore_rt), 0};
  check(sc4(SYS_rt_sigaction, SIGSYS, &a, 0, 8) == 0, "SIGSYS handler with the restorer in \"libc\"");

  u64 bad_iter = 0, first_bad_iter = 0, bad_fd = 0, bad_name = 0;
  for (u64 it = 0; it < ITERS; ++it) {
    // Wine's thread setup: SUD on with only libc allowed (issued while the selector says ALLOW).
    selector = 0;
    i64 r = sc6(SYS_prctl, PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, LIBC_PAGE, 4096, (i64)&selector, 0);
    if (r != 0) {
      out("prctl(PR_SET_SYSCALL_USER_DISPATCH) = "); outhex(r); out("\n");
      check(0, "Syscall User Dispatch can be enabled");
      break;
    }
    const u64 before = traps;
    selector = 1;   // back in "Windows" code
    i64 fd = ((native_fn)NP(native_start))(name, MFD_ALLOW_SEALING);
    selector = 0;   // Wine's dispatcher on the way into the Unix side
    if (traps - before != 1) { if (!bad_iter) first_bad_iter = it + 1; ++bad_iter; }
    if (fd < 0) { ++bad_fd; continue; }
    char path[64] = "/proc/self/fd/", num[24], link[128];
    char* d = utoa((u64)fd, num + sizeof num);
    u64 p = slen(path);
    while (*d) path[p++] = *d++;
    path[p] = 0;
    i64 len = sc6(SYS_readlinkat, AT_FDCWD, (i64)path, (i64)link, sizeof link - 1, 0, 0);
    // expected: "/memfd:" + name + " (deleted)"
    int ok = len > 7 && link[0] == '/' && link[1] == 'm' && link[6] == ':';
    for (u64 i = 0; ok && name[i]; ++i) ok = 7 + (i64)i < len && link[7 + i] == name[i];
    if (!ok) ++bad_name;
    sc2(SYS_close, fd, 0);
  }
  sc6(SYS_prctl, PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_OFF, 0, 0, 0, 0);

  out("traps="); outhex(traps); out(" bad="); outhex(bad); out(" first_bad="); outhex(first_bad); out("\n");
  static const char* const names[] = {"si_signo", "si_errno", "si_code", "si_call_addr", "si_syscall", "si_arch",
                                      "uc.rip", "uc.rax", "uc.rcx", "gs:0x30"};
  for (int i = 0; i < 10; ++i) kv(names[i], snap[i]);
  kv("teb", (u64)teb);
  check(traps == ITERS && !bad,
        "every trap from EAC's code: siginfo/ucontext exact, %gs is the TEB, the handler's own syscalls are not trapped");
  out("  iterations_without_exactly_one_trap="); outhex(bad_iter); out(" first="); outhex(first_bad_iter); out("\n");
  check(!bad_iter, "each native syscall traps exactly once, then the retry is allowed by the re-armed region");
  out("  bad_fd="); outhex(bad_fd); out(" bad_name="); outhex(bad_name); out("\n");
  check(!bad_fd && !bad_name, "the retried syscall runs as memfd_create with the original arguments");

  out(failures ? "RESULT: FAIL\n" : "RESULT: PASS\n");
  sc2(SYS_exit_group, failures, 0);
}
__attribute__((naked, used)) void _start(void) { __asm__ volatile("and $-16, %rsp\n call entry_c\n"); }
