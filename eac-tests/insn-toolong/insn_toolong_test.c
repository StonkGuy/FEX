// SPDX-License-Identifier: MIT
//
// Regression test for instructions longer than 15 bytes.
//
// An x86 instruction may be at most 15 bytes long. A longer one (here: redundant 0x66 prefixes before NOP) raises
// #GP(0) on hardware, before it executes (Intel SDM 2.3.11, AMD APM 1.2.2). The kernel delivers SIGSEGV, si_code
// SI_KERNEL, trapno 13, error code 0, RIP at the instruction; Wine reports it as an access violation with information
// 0 / 0xffffffffffffffff. Anti-tamper code can execute such instructions to tell hardware from a translator.
//
// Cases, each placed well inside an executable page, with redundant CS segment prefixes (2e) in front: NOP (90),
// NOP r/m (0f 1f 00) and MOV RAX, imm64 (48 b8 + 8 bytes), each at 15 bytes (executes) and 16 bytes (#GP(0)), and NOP
// at 21 bytes. The 16th byte is a prefix, the ModRM byte or part of the immediate: a decoder may stop at each in a
// different way. Printed per case: signal, si_code, RIP relative to the instruction, trapno, error code, address.
// The binary is x86-64 only. Run it under FEX, and run the same binary on a real x86-64 Linux kernel for the reference.
// Build: eac-tests/insn-toolong/build.sh [clang]
// Run:   ./insn_toolong_test   (exit status = number of failed checks)

#if !defined(__x86_64__)
#error "x86-64 only: the test executes x86 instructions"
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
#define sc3(n, a, b, c) sc6(n, (i64)(a), (i64)(b), (i64)(c), 0, 0, 0)
enum { SYS_write = 1, SYS_mmap = 9, SYS_mprotect = 10, SYS_rt_sigaction = 13, SYS_alarm = 37, SYS_exit_group = 231 };
enum { PROT_NONE = 0, PROT_READ = 1, PROT_WRITE = 2, PROT_EXEC = 4, MAP_PRIVATE = 2, MAP_ANONYMOUS = 0x20 };
enum { SIGILL = 4, SIGBUS = 7, SIGSEGV = 11, SA_SIGINFO = 4, SA_RESTORER = 0x04000000, SI_KERNEL = 0x80 };
enum { REG_RSP = 15, REG_RIP = 16, REG_ERR = 19, REG_TRAPNO = 20 };
#define PAGE 4096UL

struct ksigaction { void* handler; u64 flags; void* restorer; u64 mask; };
__attribute__((naked, used)) static void restore_rt(void) { __asm__ volatile("mov $15, %eax\n syscall\n"); }

// call the code at rdi; a fault handler returns here as if it had returned
void run_at(u64 target);
__asm__(".text\n.globl run_at\nrun_at:\n push %rbx\n call *%rdi\n pop %rbx\n ret\n");

static volatile u64 faults, f_sig, f_code, f_addr, f_rip, f_trapno, f_err;
static void fault(int sig, void* info, void* uc) {
  u64* g = (u64*)((char*)uc + 40);
  ++faults;
  f_sig = (u64)sig;
  f_code = (u64)((int*)info)[2];
  f_addr = *(u64*)((char*)info + 16);
  f_rip = g[REG_RIP];
  f_trapno = g[REG_TRAPNO];
  f_err = g[REG_ERR];
  // return to run_at as the called code would have
  u64 rsp = g[REG_RSP];
  g[REG_RIP] = *(u64*)rsp;
  g[REG_RSP] = rsp + 8;
}

static int failures;
static void out(const char* s) { u64 n = 0; while (s[n]) ++n; sc3(SYS_write, 1, s, n); }
static void outhex(u64 v) { char b[19]; int i = 18; b[i] = 0; do { int d = v & 15; b[--i] = d < 10 ? '0' + d : 'a' + d - 10; v >>= 4; } while (v); b[--i] = 'x'; b[--i] = '0'; out(b + i); }
static void outdec(u64 v) { char b[21]; int i = 20; b[i] = 0; do { b[--i] = '0' + v % 10; v /= 10; } while (v); out(b + i); }
static void outrel(u64 v, u64 base) { if (v >= base) { out("+"); outdec(v - base); } else { out("-"); outdec(base - v); } }

static void one(u64 mem, const char* what, const unsigned char* insn, int insn_size, int prefixes) {
  sc3(SYS_mprotect, mem, 2 * PAGE, PROT_READ | PROT_WRITE | PROT_EXEC);
  unsigned char* s = (unsigned char*)(mem + 0x100);
  for (int i = 0; i < prefixes; ++i) s[i] = 0x2e; // cs:, ignored in 64-bit mode
  for (int i = 0; i < insn_size; ++i) s[prefixes + i] = insn[i];
  s[prefixes + insn_size] = 0xc3; // ret
  const int size = prefixes + insn_size;
  u64 start = (u64)s;
  u64 before = faults;
  run_at(start);
  int faulted = faults != before;
  out("  "); out(what); out(", "); outdec((u64)size); out(" bytes: ");
  if (faulted) {
    out("signal "); outdec(f_sig); out(" code "); outhex(f_code); out(" rip "); outrel(f_rip, start); out(" trapno ");
    outdec(f_trapno); out(" err "); outhex(f_err); out(" addr "); outhex(f_addr);
  } else out("executed");
  out("\n");
  // hardware: up to 15 bytes execute; a longer instruction raises #GP(0) at its first byte
  int ok;
  if (size <= 15) ok = !faulted;
  else ok = faulted && f_sig == SIGSEGV && f_code == SI_KERNEL && f_rip == start && f_trapno == 13 && f_err == 0;
  if (!ok) { out(size <= 15 ? "    expected: executes\n" : "    expected SIGSEGV SI_KERNEL, rip = instruction, trapno 13, err 0\n"); ++failures; }
}

__attribute__((used)) void entry_c(void) {
  struct ksigaction sa = {(void*)fault, SA_SIGINFO | SA_RESTORER, (void*)restore_rt, 0};
  sc6(SYS_rt_sigaction, SIGSEGV, (i64)&sa, 0, 8, 0, 0);
  sc6(SYS_rt_sigaction, SIGILL, (i64)&sa, 0, 8, 0, 0);
  sc6(SYS_rt_sigaction, SIGBUS, (i64)&sa, 0, 8, 0, 0);
  sc1(SYS_alarm, 60);
  u64 mem = (u64)sc6(SYS_mmap, 0, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if ((i64)mem < 0) { out("mmap failed\n"); sc1(SYS_exit_group, 99); }
  static const unsigned char nop[] = {0x90}, nop_rm[] = {0x0f, 0x1f, 0x00}, mov_imm64[] = {0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8};
  one(mem, "nop", nop, sizeof(nop), 14);
  one(mem, "nop", nop, sizeof(nop), 15);
  one(mem, "nop", nop, sizeof(nop), 20);
  one(mem, "nop r/m", nop_rm, sizeof(nop_rm), 12);
  one(mem, "nop r/m", nop_rm, sizeof(nop_rm), 13);
  one(mem, "mov rax, imm64", mov_imm64, sizeof(mov_imm64), 5);
  one(mem, "mov rax, imm64", mov_imm64, sizeof(mov_imm64), 6);
  out(failures ? "RESULT: FAIL (" : "RESULT: PASS ("); outdec((u64)failures); out(" unexpected)\n");
  sc1(SYS_exit_group, failures);
}

__attribute__((naked, used)) void _start(void) { __asm__ volatile("and $-16, %rsp\n call entry_c\n"); }
