// SPDX-License-Identifier: MIT
//
// Regression test for the integer divide error (#DE) of DIV and IDIV under FEX.
//
// x86 raises #DE when the divisor is zero and when the quotient does not fit the destination (DIV: the upper half
// of the dividend is not below the divisor; IDIV: e.g. INT_MIN / -1). Linux delivers both as SIGFPE with si_code
// FPE_INTDIV and trapno 0 (arch/x86/kernel/traps.c exc_divide_error), at the divide instruction itself and with
// every register unchanged; Wine turns it into EXCEPTION_INT_DIVIDE_BY_ZERO for structured exception handlers.
//
// Arm64 divides never trap, and FEX used to return a zero/truncated quotient and carry on, so a program that relies
// on the exception (an SEH-based control flow, a self-check that divides by a computed zero) took a different path.
// This test runs every DIV/IDIV width with register and memory divisors through three kinds of inputs:
//   zero divisor -> SIGFPE/FPE_INTDIV, trapno 0, RIP = the divide, RAX/RDX unchanged in the frame and afterwards;
//   quotient overflow -> the same;
//   boundary inputs that do not fault (largest quotient that fits, negative results) -> the exact x86 result.
//
// Build: eac-tests/div-fault/build.sh [clang]   (x86-64 binary: run it under FEX, and unchanged on x86-64 Linux)
// Run:   ./div_fault_test   (exit status = number of failed checks)

typedef unsigned long u64;
typedef long i64;

#if defined(__x86_64__)
static inline i64 sc6(i64 nr, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f) {
  i64 ret;
  register i64 r10 __asm__("r10") = d;
  register i64 r8 __asm__("r8") = e;
  register i64 r9 __asm__("r9") = f;
  __asm__ volatile("syscall" : "=a"(ret) : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
  return ret;
}
enum { SYS_write = 1, SYS_rt_sigaction = 13, SYS_exit_group = 231 };
struct ksigaction { void* handler; u64 flags; void* restorer; u64 mask; };
__attribute__((naked, used)) static void restore_rt(void) { __asm__ volatile("mov $15, %eax\n syscall\n"); }
#define SA_SIGINFO 0x4
#define SA_RESTORER 0x04000000
#elif defined(__aarch64__)
static inline i64 sc6(i64 nr, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f) {
  register i64 x8 __asm__("x8") = nr;
  register i64 x0 __asm__("x0") = a;
  register i64 x1 __asm__("x1") = b;
  register i64 x2 __asm__("x2") = c;
  __asm__ volatile("svc 0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
  (void)d; (void)e; (void)f;
  return x0;
}
enum { SYS_write = 64, SYS_exit_group = 94 };
#else
#error "x86-64 and aarch64 only"
#endif

static u64 slen(const char* s) { u64 n = 0; while (s[n]) ++n; return n; }
static void out(const char* s) { sc6(SYS_write, 1, (i64)s, slen(s), 0, 0, 0); }
static void outhex(u64 v) {
  char b[19]; b[0] = '0'; b[1] = 'x';
  for (int i = 0; i < 16; i++) b[2 + i] = "0123456789abcdef"[(v >> (60 - 4 * i)) & 15];
  b[18] = 0; out(b);
}

static int failures;
static void check(int ok, const char* name, const char* what) {
  out(ok ? "PASS: " : "FAIL: "); out(name); out(": "); out(what); out("\n"); if (!ok) ++failures;
}

#if defined(__x86_64__)
// One stub per form: rdi = RAX in, rsi = RDX in, rdx = divisor (placed in RCX and in div_mem). The divide sits
// between the labels <name>_at and <name>_after; the stub stores RAX/RDX after it.
#define FORM(name, insn)                                                                      \
  ".globl " #name "\n" #name ":\n"                                                            \
  "  mov rax, rdi\n  mov rcx, rdx\n  mov qword ptr [rip+div_mem], rdx\n  mov rdx, rsi\n"   \
  ".globl " #name "_at\n" #name "_at:\n  " insn "\n"                                          \
  ".globl " #name "_after\n" #name "_after:\n"                                                \
  "  mov qword ptr [rip+res_rax], rax\n  mov qword ptr [rip+res_rdx], rdx\n  ret\n"
__asm__(".intel_syntax noprefix\n.text\n"
        FORM(f_div8, "div cl") FORM(f_div16, "div cx") FORM(f_div32, "div ecx") FORM(f_div64, "div rcx")
        FORM(f_idiv8, "idiv cl") FORM(f_idiv16, "idiv cx") FORM(f_idiv32, "idiv ecx") FORM(f_idiv64, "idiv rcx")
        FORM(f_div8m, "div byte ptr [rip+div_mem]") FORM(f_div64m, "div qword ptr [rip+div_mem]")
        FORM(f_idiv32m, "idiv dword ptr [rip+div_mem]") FORM(f_idiv64m, "idiv qword ptr [rip+div_mem]")
        FORM(f_div8h, "div ch")
        // SIGFPE handler: rdi = signo, rsi = siginfo (si_code @8), rdx = ucontext (gregs @40: RDX 12, RAX 13,
        // RIP 16, TRAPNO 20). It records them and resumes at resume_at.
        ".globl hfpe\nhfpe:\n"
        "  mov qword ptr [rip+seen_sig], rdi\n"
        "  movsxd rax, dword ptr [rsi+8]\n  mov qword ptr [rip+seen_code], rax\n"
        "  mov rax, qword ptr [rdx+40+16*8]\n  mov qword ptr [rip+seen_rip], rax\n"
        "  mov rax, qword ptr [rdx+40+13*8]\n  mov qword ptr [rip+seen_rax], rax\n"
        "  mov rax, qword ptr [rdx+40+12*8]\n  mov qword ptr [rip+seen_rdx], rax\n"
        "  mov rax, qword ptr [rdx+40+20*8]\n  mov qword ptr [rip+seen_trapno], rax\n"
        "  mov rax, qword ptr [rip+resume_at]\n  mov qword ptr [rdx+40+16*8], rax\n"
        "  inc qword ptr [rip+faults]\n  ret\n"
        ".data\n.balign 8\n"
        ".globl div_mem\ndiv_mem: .quad 0\n.globl res_rax\nres_rax: .quad 0\n.globl res_rdx\nres_rdx: .quad 0\n"
        ".globl seen_sig\nseen_sig: .quad 0\n.globl seen_code\nseen_code: .quad 0\n.globl seen_rip\nseen_rip: .quad 0\n"
        ".globl seen_rax\nseen_rax: .quad 0\n.globl seen_rdx\nseen_rdx: .quad 0\n.globl seen_trapno\nseen_trapno: .quad 0\n"
        ".globl resume_at\nresume_at: .quad 0\n.globl faults\nfaults: .quad 0\n"
        ".text\n.att_syntax\n");

#define DECL(n) extern void n(u64, u64, u64); extern char n##_at[], n##_after[];
DECL(f_div8) DECL(f_div16) DECL(f_div32) DECL(f_div64) DECL(f_idiv8) DECL(f_idiv16) DECL(f_idiv32) DECL(f_idiv64)
DECL(f_div8m) DECL(f_div64m) DECL(f_idiv32m) DECL(f_idiv64m) DECL(f_div8h)
extern void hfpe(void);
extern volatile u64 res_rax, res_rdx, seen_sig, seen_code, seen_rip, seen_rax, seen_rdx, seen_trapno, resume_at, faults;

struct form { const char* name; void (*fn)(u64, u64, u64); char* at; char* after; };
#define F(n) { #n, n, n##_at, n##_after }
enum { DIV8, DIV16, DIV32, DIV64, IDIV8, IDIV16, IDIV32, IDIV64, DIV8M, DIV64M, IDIV32M, IDIV64M, DIV8H };
static const struct form forms[] = { F(f_div8), F(f_div16), F(f_div32), F(f_div64), F(f_idiv8), F(f_idiv16),
                                     F(f_idiv32), F(f_idiv64), F(f_div8m), F(f_div64m), F(f_idiv32m), F(f_idiv64m),
                                     F(f_div8h) };

// The upper bits of RAX/RDX above the operand size carry a marker, so a fault that clobbers them is visible.
static void expect_fault(int f, const char* name, u64 rax, u64 rdx, u64 divisor) {
  faults = 0; seen_sig = seen_code = seen_trapno = ~0ul;
  resume_at = (u64)forms[f].after;
  forms[f].fn(rax, rdx, divisor);
  check(faults == 1, name, "raises exactly one SIGFPE");
  check(seen_sig == 8 && seen_code == 1, name, "the signal is SIGFPE with si_code FPE_INTDIV");
  check(seen_trapno == 0, name, "uc_mcontext trapno is 0 (#DE)");
  check(seen_rip == (u64)forms[f].at, name, "the fault RIP is the divide instruction");
  check(seen_rax == rax && seen_rdx == rdx, name, "RAX/RDX in the signal frame are the unchanged inputs");
  check(res_rax == rax && res_rdx == rdx, name, "RAX/RDX are unchanged after resuming past the divide");
  if (faults != 1 || seen_rax != rax || res_rax != rax) {
    out("    faults "); outhex(faults); out(" rax "); outhex(res_rax); out(" rdx "); outhex(res_rdx); out("\n");
  }
}

static void expect_result(int f, const char* name, u64 rax, u64 rdx, u64 divisor, u64 want_rax, u64 want_rdx) {
  faults = 0;
  resume_at = (u64)forms[f].after;
  forms[f].fn(rax, rdx, divisor);
  check(faults == 0 && res_rax == want_rax && res_rdx == want_rdx, name, "no fault and the exact quotient/remainder");
  if (faults || res_rax != want_rax || res_rdx != want_rdx) {
    out("    got rax "); outhex(res_rax); out(" rdx "); outhex(res_rdx); out(" want "); outhex(want_rax); out(" ");
    outhex(want_rdx); out("\n");
  }
}

static void run(void) {
  struct ksigaction a = { (void*)hfpe, SA_SIGINFO | SA_RESTORER, (void*)restore_rt, 0 };
  check(sc6(SYS_rt_sigaction, 8, (i64)&a, 0, 8, 0, 0) == 0, "setup", "install the SIGFPE handler (SA_SIGINFO)");
  const u64 M = 0x5a5a5a5a5a5a0000ul; // marker in bits the narrow forms must not touch

  // zero divisor, every width; the divisor register's upper bits are non-zero so only the operand-size part counts
  expect_fault(DIV8, "div r8 by 0", M | 0x1234, 0x77, 0xff00);
  expect_fault(DIV16, "div r16 by 0", M | 0x1234, M | 0x1, 0xffff0000ul);
  expect_fault(DIV32, "div r32 by 0", 0xaaaaaaaa12345678ul, 0xbbbbbbbb00000001ul, 0xffffffff00000000ul);
  expect_fault(DIV64, "div r64 by 0", 0x1234, 0, 0);
  expect_fault(IDIV8, "idiv r8 by 0", M | 0x1234, 0x77, 0xff00);
  expect_fault(IDIV16, "idiv r16 by 0", M | 0x1234, M | 0x1, 0xffff0000ul);
  expect_fault(IDIV32, "idiv r32 by 0", 0xaaaaaaaa12345678ul, 0xbbbbbbbb00000001ul, 0xffffffff00000000ul);
  expect_fault(IDIV64, "idiv r64 by 0", 0x1234, 0, 0);
  expect_fault(IDIV64, "idiv r64 by 0, long dividend", 0x1234, 0x99, 0);
  expect_fault(DIV64M, "div m64 by 0", 0x1234, 0, 0);
  expect_fault(IDIV64M, "idiv m64 by 0", 0x1234, 0, 0);
  expect_fault(DIV8H, "div ch (high byte) by 0", M | 0x1234, 0x77, 0x00ff);

  // quotient overflow
  expect_fault(DIV8, "div r8 overflow (AH == divisor)", M | 0x1000, 0, 0x10);
  expect_fault(DIV8M, "div m8 overflow", M | 0xff00, 0, 0x01);
  expect_fault(DIV16, "div r16 overflow", M | 0x0000, M | 0x8000, 0x8000);
  expect_fault(DIV32, "div r32 overflow", 0xaaaaaaaa00000000ul, 0xbbbbbbbb00000002ul, 0x2);
  expect_fault(DIV64, "div r64 overflow (RDX == divisor)", 0, 7, 7);
  expect_fault(DIV64, "div r64 overflow (RDX > divisor)", 0, ~0ul, 3);
  expect_fault(IDIV8, "idiv r8 -128 / -1", M | 0xff80, 0, 0xff);
  expect_fault(IDIV8, "idiv r8 128 / 1", M | 0x0080, 0, 0x01);
  expect_fault(IDIV16, "idiv r16 -32768 / -1", M | 0x8000, M | 0xffff, 0xffff);
  expect_fault(IDIV32, "idiv r32 INT32_MIN / -1", 0xaaaaaaaa80000000ul, 0xbbbbbbbbfffffffful, 0xffffffff);
  expect_fault(IDIV32M, "idiv m32 2^32 / 2", 0, 1, 2);
  expect_fault(IDIV64, "idiv r64 INT64_MIN / -1", 0x8000000000000000ul, ~0ul, ~0ul);
  expect_fault(IDIV64, "idiv r64 2^64 / 2 (long dividend)", 0, 1, 2);
  expect_fault(IDIV64, "idiv r64 -2^64 / 1", 0, ~0ul, 1);
  expect_fault(IDIV64, "idiv r64 2^63 / 1", 0x8000000000000000ul, 0, 1);
  expect_fault(IDIV64M, "idiv m64 (2^126) / 3", 0, 0x4000000000000000ul, 3);

  // boundary inputs that must not fault
  expect_result(DIV8, "div r8 255 r 0", M | 0xfeff, 0x99, 0xff, M | 0xfeff, 0x99);
  expect_result(DIV16, "div r16 largest quotient", M | 0xffff, M | 0x7fff, 0x8000, M | 0xffff, M | 0x7fff);
  expect_result(DIV32, "div r32 largest quotient", 0xaaaaaaaa00000000ul, 0xbbbbbbbb00000001ul, 0x2, 0x80000000ul, 0);
  expect_result(DIV64, "div r64 largest quotient", ~0ul, 2, 3, ~0ul, 2);
  expect_result(DIV64M, "div m64 RDX = divisor - 1", 5, 6, 7, 0xdb6db6db6db6db6eul, 3);
  expect_result(IDIV8, "idiv r8 -128 / 1", M | 0xff80, 0, 0x01, M | 0x0080, 0);
  expect_result(IDIV8, "idiv r8 127 / 1", M | 0x007f, 0, 0x01, M | 0x007f, 0);
  expect_result(IDIV16, "idiv r16 -32768 / 1", M | 0x8000, M | 0xffff, 1, M | 0x8000, M | 0x0000);
  expect_result(IDIV32, "idiv r32 INT32_MIN / 1", 0xaaaaaaaa80000000ul, 0xbbbbbbbbfffffffful, 1, 0x80000000ul, 0);
  expect_result(IDIV8, "idiv r8 256 / 4 (dividend not sign-extended)", M | 0x0100, 0, 0x04, M | 0x0040, 0);
  expect_result(IDIV16, "idiv r16 2^16 / 4 (dividend not sign-extended)", M | 0x0000, M | 0x0001, 4, M | 0x4000, M | 0x0000);
  expect_result(IDIV32, "idiv r32 2^32 / 4 (dividend not sign-extended)", 0, 1, 4, 0x40000000ul, 0);
  expect_result(IDIV32, "idiv r32 -2^32 / 4 (dividend not sign-extended)", 0, 0xfffffffful, 4, 0xc0000000ul, 0);
  expect_result(IDIV32, "idiv r32 -7 / 2", 0xfffffff9ul, 0xfffffffful, 2, 0xfffffffdul, 0xfffffffful);
  expect_result(IDIV64, "idiv r64 INT64_MIN / 1", 0x8000000000000000ul, ~0ul, 1, 0x8000000000000000ul, 0);
  expect_result(IDIV64, "idiv r64 -2^63 = -2^64 / 2 (long dividend)", 0, ~0ul, 2, 0x8000000000000000ul, 0);
  expect_result(IDIV64, "idiv r64 (2^64 + 5) / 3 (long dividend)", 5, 1, 3, 0x5555555555555557ul, 0);
  expect_result(IDIV64, "idiv r64 -(2^64 + 5) / 3", (u64) - 5, (u64)-2, 3, (u64)-0x5555555555555557l, (u64)-0l);
  expect_result(IDIV64M, "idiv m64 largest positive quotient (long dividend)", 6, 0x3ffffffffffffffful,
                0x7ffffffffffffffful, 0x7ffffffffffffffful, 5);
  expect_fault(IDIV64M, "idiv m64 2^126 / (2^63 - 1)", 0, 0x4000000000000000ul, 0x7ffffffffffffffful);

  out(failures ? "RESULT: FAIL\n" : "RESULT: PASS\n");
  sc6(SYS_exit_group, failures, 0, 0, 0, 0, 0);
}
#else
static void run(void) {
  out("SKIP: DIV/IDIV #DE is an x86-64 test\nRESULT: PASS\n");
  sc6(SYS_exit_group, 0, 0, 0, 0, 0, 0);
}
#endif

__attribute__((used)) static void entry_c(u64* sp) { (void)sp; (void)check; (void)outhex; run(); }
#if defined(__x86_64__)
__attribute__((naked, used)) void _start(void) { __asm__ volatile("mov %rsp, %rdi\n and $-16, %rsp\n call entry_c\n"); }
#else
__asm__(".text\n.globl _start\n_start:\n mov x0, sp\n and sp, x0, #-16\n bl entry_c\n");
#endif
