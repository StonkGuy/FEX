// SPDX-License-Identifier: MIT
//
// Regression test for loading FS and GS with MOV in 64-bit mode.
//
// A 64-bit program can load a selector into FS or GS. The CPU checks it against the GDT/LDT like any data segment
// load: a null selector (0-3) loads and clears the base (Intel; AMD since Zen 2), a present data or readable code
// descriptor the program may use loads its selector and its 32-bit base, anything else raises #GP with the selector as
// the error code (Intel SDM, MOV: "IF segment selector index is outside descriptor table limits OR segment is not a
// data or readable code segment OR (RPL > DPL or CPL > DPL) THEN #GP(selector)"). Linux's x86-64 GDT gives user mode
// four such descriptors (0x23 32-bit code, 0x2b data, 0x33 64-bit code, 0x7b CPU/node data, all base 0); there is no
// LDT unless the program creates one, so every LDT selector faults. The kernel delivers #GP as SIGSEGV, si_code
// SI_KERNEL, trapno 13, the error code in the context; Wine reports an LDT selector's #GP as an access violation with
// information 0/0. THE FINALS' and ARC Raiders' anti-cheat load FS like this; FEX refused the instruction as
// undecodable (a different exception).
//
// For FS and GS and each selector: the fault (signal, si_code, trapno, error code) or none, then the selector and the
// base the program reads back (MOV from the register, arch_prctl), against the rules above.
// The binary is x86-64 only. Run it under FEX, and run the same binary on a real x86-64 Linux kernel for the reference.
// Build: eac-tests/seg-load64/build.sh [clang]
// Run:   ./seg_load64_test   (exit status = number of failed checks)

#if !defined(__x86_64__)
#error "x86-64 only: the test loads x86 segment registers"
#endif

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
enum { SYS_write = 1, SYS_rt_sigaction = 13, SYS_alarm = 37, SYS_arch_prctl = 158, SYS_exit_group = 231 };
enum { ARCH_SET_GS = 0x1001, ARCH_SET_FS = 0x1002, ARCH_GET_FS = 0x1003, ARCH_GET_GS = 0x1004 };
enum { SIGILL = 4, SIGBUS = 7, SIGSEGV = 11, SA_SIGINFO = 4, SA_RESTORER = 0x04000000, SI_KERNEL = 0x80 };
enum { REG_RIP = 16, REG_ERR = 19, REG_TRAPNO = 20 };
#define MARKER 0x123456780000UL

struct ksigaction { void* handler; u64 flags; void* restorer; u64 mask; };
__attribute__((naked, used)) static void restore_rt(void) { __asm__ volatile("mov $15, %eax\n syscall\n"); }

// load selector rdi into FS / GS (a two-byte MOV at the site; a fault handler resumes after it), read it back
u64 load_fs(u64 sel);
u64 load_gs(u64 sel);
extern char fs_site[], gs_site[];
__asm__(".text\n"
        ".globl load_fs\nload_fs:\n mov %rdi, %rax\n"
        ".globl fs_site\nfs_site:\n mov %ax, %fs\n"
        " xor %eax, %eax\n mov %fs, %ax\n ret\n"
        ".globl load_gs\nload_gs:\n mov %rdi, %rax\n"
        ".globl gs_site\ngs_site:\n mov %ax, %gs\n"
        " xor %eax, %eax\n mov %gs, %ax\n ret\n");

static volatile u64 faults, f_sig, f_code, f_trapno, f_err;
static void fault(int sig, void* info, void* uc) {
  u64* g = (u64*)((char*)uc + 40);
  if (g[REG_RIP] != (u64)fs_site && g[REG_RIP] != (u64)gs_site) sc1(SYS_exit_group, 99);
  ++faults;
  f_sig = (u64)sig;
  f_code = (u64)((int*)info)[2];
  f_trapno = g[REG_TRAPNO];
  f_err = g[REG_ERR];
  g[REG_RIP] += 2;
}

static int failures;
static void out(const char* s) { u64 n = 0; while (s[n]) ++n; sc3(SYS_write, 1, s, n); }
static void outhex(u64 v) { char b[19]; int i = 18; b[i] = 0; do { int d = v & 15; b[--i] = d < 10 ? '0' + d : 'a' + d - 10; v >>= 4; } while (v); b[--i] = 'x'; b[--i] = '0'; out(b + i); }
static void outdec(u64 v) { char b[21]; int i = 20; b[i] = 0; do { b[--i] = '0' + v % 10; v /= 10; } while (v); out(b + i); }

// Linux x86-64: which selectors a user-mode data segment load accepts (index 4 32-bit user code, 5 user data,
// 6 64-bit user code, 15 CPU/node; all DPL 3, base 0)
static int loads(u64 sel) {
  if ((sel & ~3UL) == 0) return 1;
  if (sel & 4) return 0;
  u64 index = sel >> 3;
  return index == 4 || index == 5 || index == 6 || index == 15;
}

static void one(int gs, u64 sel) {
  u64 base = 0, after;
  // start from a null selector with a known base
  if (gs) { load_gs(0); sc2(SYS_arch_prctl, ARCH_SET_GS, MARKER); } else { load_fs(0); sc2(SYS_arch_prctl, ARCH_SET_FS, MARKER); }
  u64 before = faults;
  after = gs ? load_gs(sel) : load_fs(sel);
  sc2(SYS_arch_prctl, gs ? ARCH_GET_GS : ARCH_GET_FS, &base);
  int faulted = faults != before;
  out(gs ? "  gs " : "  fs "); outhex(sel); out(": ");
  if (faulted) { out("signal "); outdec(f_sig); out(" code "); outhex(f_code); out(" trapno "); outdec(f_trapno); out(" err "); outhex(f_err); }
  else out("loaded");
  out(", selector "); outhex(after); out(", base "); out(base == MARKER ? "unchanged" : base == 0 ? "0" : "other"); out("\n");
  int ok;
  if (loads(sel)) ok = !faulted && after == sel && base == 0;
  else ok = faulted && f_sig == SIGSEGV && f_code == SI_KERNEL && f_trapno == 13 && f_err == (sel & 0xfffc) && after == 0 && base == MARKER;
  if (!ok) { out("    expected "); out(loads(sel) ? "a load with base 0" : "#GP(selector & 0xfffc), selector and base unchanged"); out("\n"); ++failures; }
}

__attribute__((used)) void entry_c(void) {
  struct ksigaction sa = {(void*)fault, SA_SIGINFO | SA_RESTORER, (void*)restore_rt, 0};
  sc6(SYS_rt_sigaction, SIGSEGV, (i64)&sa, 0, 8, 0, 0);
  sc6(SYS_rt_sigaction, SIGILL, (i64)&sa, 0, 8, 0, 0);
  sc6(SYS_rt_sigaction, SIGBUS, (i64)&sa, 0, 8, 0, 0);
  sc1(SYS_alarm, 60);
  static const u64 sels[] = {0, 1, 2, 3, 4, 6, 7, 0x8, 0xb, 0x10, 0x13, 0x18, 0x1b, 0x20, 0x23, 0x2b, 0x33, 0x38,
                             0x3b, 0x40, 0x43, 0x50, 0x53, 0x63, 0x6b, 0x73, 0x7b, 0x80, 0x83, 0xfffc, 0xffff};
  for (int gs = 0; gs < 2; ++gs)
    for (u64 i = 0; i < sizeof sels / sizeof sels[0]; ++i) one(gs, sels[i]);
  // leave both null with base 0 (nothing here uses them, but a runtime after exit_group might)
  load_fs(0); load_gs(0); sc2(SYS_arch_prctl, ARCH_SET_FS, 0); sc2(SYS_arch_prctl, ARCH_SET_GS, 0);
  out(failures ? "RESULT: FAIL (" : "RESULT: PASS ("); outdec((u64)failures); out(" unexpected)\n");
  sc1(SYS_exit_group, failures);
}

__attribute__((naked, used)) void _start(void) { __asm__ volatile("and $-16, %rsp\n call entry_c\n"); }
