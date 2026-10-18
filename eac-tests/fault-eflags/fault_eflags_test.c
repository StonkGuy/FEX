// SPDX-License-Identifier: MIT
//
// Regression test for EFLAGS and the general registers in the signal frame of a synchronous fault.
//
// For a fault-class exception (#DE, #UD, #GP, #PF, ...) the CPU pushes an EFLAGS image with RF (bit 16, resume flag)
// set, so that returning to the faulting instruction does not hit an instruction breakpoint on it again (Intel SDM
// vol. 3, "Resume Flag"); trap-class exceptions (#BP from int3, single-step #DB) and interrupts push RF = 0. Linux
// copies that image into uc_mcontext.gregs[REG_EFL] unchanged (and accepts RF back on rt_sigreturn, FIX_EFLAGS), so a
// SIGSEGV/SIGILL/SIGFPE handler on real hardware sees RF = 1 and a SIGTRAP from int3 sees RF = 0. Wine copies the value
// into CONTEXT.EFlags, so Windows exception handlers see it too (an execute fault caught by a PE exception handler shows
// EFlags 0x10202 on an x86-64 host).
//
// Each case loads every general register with a known value, records EFLAGS just before the faulting instruction and
// then faults; the handler copies uc_mcontext.gregs and resumes at a recovery label. Checked per case:
//   EFLAGS in the frame == EFLAGS before the instruction | (RF if the exception is a fault), and the 16 GPRs and RIP.
//   After the handler returns (the frame still holds RF = 1 for a fault), PUSHF at the resume point shows RF = 0: PUSHF
//   never stores RF, and RF does not outlive the next instruction.
// Cases: read from an unmapped page, execute a non-executable page (call), ud2, hlt (#GP), int3 (trap: RF = 0),
// and two execute faults right after a syscall (r11 = RFLAGS from the syscall, and r11 reloaded afterwards).
// (#DE is not covered: FEX does not raise it for a division by zero, an upstream limit.)
//
// The binary is x86-64 only. Run it under FEX, and run the same binary on a real x86-64 Linux kernel for the
// reference result.
// Build: eac-tests/fault-eflags/build.sh [clang]
// Run:   ./fault_eflags_test   (exit status = number of failed checks)

#if !defined(__x86_64__)
#error "x86-64 only: the test checks x86 EFLAGS"
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
#define sc4(nr, a, b, c, d) sc6(nr, a, b, c, d, 0, 0)
enum { SYS_write = 1, SYS_mmap = 9, SYS_munmap = 11, SYS_rt_sigaction = 13, SYS_getpid = 39, SYS_exit_group = 231 };
enum { SIGILL = 4, SIGTRAP = 5, SIGFPE = 8, SIGSEGV = 11 };
#define SA_SIGINFO 0x4
#define SA_RESTORER 0x04000000
#define SA_NODEFER 0x40000000
#define EFL_RF 0x10000UL
struct ksigaction { void* handler; u64 flags; void* restorer; u64 mask; };

__attribute__((naked, used)) static void restore_rt(void) { __asm__ volatile("mov $15, %eax\n syscall\n"); }

// uc_mcontext.gregs order (sys/ucontext.h): R8 R9 R10 R11 R12 R13 R14 R15 RDI RSI RBP RBX RDX RAX RCX RSP RIP EFL CSGSFS ERR TRAPNO
enum { G_R8, G_R9, G_R10, G_R11, G_R12, G_R13, G_R14, G_R15, G_RDI, G_RSI, G_RBP, G_RBX, G_RDX, G_RAX, G_RCX, G_RSP, G_RIP, G_EFL,
       G_CSGSFS, G_ERR, G_TRAPNO, G_NUM = 23 };
static const char* const gname[16] = {"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                                      "rdi", "rsi", "rbp", "rbx", "rdx", "rax", "rcx", "rsp"};

extern volatile u64 g_magic[16], g_target, g_saved_rsp, g_resume, g_fault_rip, g_flags_before, g_flags_after, g_regs[G_NUM], g_hits, g_sig;
extern void hcopy(void);
extern void c_pf_read(void), c_pf_exec(void), c_ud2(void), c_hlt(void), c_int3(void), c_sys_exec(void),
  c_sys_exec_r11(void);

// Prologue: save callee-saved registers and the stack pointer, publish the resume label and the faulting RIP.
#define PRO(n)                                                                                                     \
  ".balign 16\n.globl " n "\n" n ":\n push %rbx\n push %rbp\n push %r12\n push %r13\n push %r14\n push %r15\n"     \
  " mov %rsp, g_saved_rsp(%rip)\n lea " n "_resume(%rip), %rax\n mov %rax, g_resume(%rip)\n"                        \
  " lea " n "_fault(%rip), %rax\n mov %rax, g_fault_rip(%rip)\n"
// Every GPR from g_magic (indexed like gregs), r10 = g_target. Plain moves: no flag changes.
#define LOADREGS                                                                                                   \
  " mov g_magic+0(%rip), %r8\n mov g_magic+8(%rip), %r9\n mov g_target(%rip), %r10\n mov g_magic+24(%rip), %r11\n" \
  " mov g_magic+32(%rip), %r12\n mov g_magic+40(%rip), %r13\n mov g_magic+48(%rip), %r14\n"                        \
  " mov g_magic+56(%rip), %r15\n mov g_magic+64(%rip), %rdi\n mov g_magic+72(%rip), %rsi\n"                        \
  " mov g_magic+80(%rip), %rbp\n mov g_magic+88(%rip), %rbx\n mov g_magic+96(%rip), %rdx\n"                        \
  " mov g_magic+104(%rip), %rax\n mov g_magic+112(%rip), %rcx\n"
#define FLAGS " pushfq\n popq g_flags_before(%rip)\n"
#define EPI(n) n "_resume:\n pushfq\n popq g_flags_after(%rip)\n cld\n mov g_saved_rsp(%rip), %rsp\n pop %r15\n pop %r14\n pop %r13\n pop %r12\n pop %rbp\n pop %rbx\n ret\n"

__asm__(".text\n"
        PRO("c_pf_read") " stc\n" FLAGS LOADREGS "c_pf_read_fault:\n mov (%r10), %al\n" EPI("c_pf_read")
        PRO("c_pf_exec") " std\n" FLAGS LOADREGS "c_pf_exec_fault:\n call *%r10\n cld\n" EPI("c_pf_exec")
        PRO("c_ud2") FLAGS LOADREGS "c_ud2_fault:\n ud2\n" EPI("c_ud2")
        PRO("c_hlt") " stc\n" FLAGS LOADREGS "c_hlt_fault:\n hlt\n" EPI("c_hlt")
        PRO("c_int3") FLAGS LOADREGS "c_int3_fault:\n int3\n nop\n" EPI("c_int3")
        // syscall then execute fault: r11 must still hold the RFLAGS the syscall instruction saved, rcx its return RIP
        PRO("c_sys_exec") LOADREGS FLAGS " mov $39, %eax\n syscall\nc_sys_exec_after:\nc_sys_exec_fault:\n call *%r10\n"
        EPI("c_sys_exec")
        // syscall, then rax/rcx/r11 reloaded with known values before the execute fault
        PRO("c_sys_exec_r11") LOADREGS " mov $39, %eax\n syscall\n mov g_magic+104(%rip), %rax\n mov g_magic+112(%rip), %rcx\n"
        " mov g_magic+24(%rip), %r11\n" FLAGS "c_sys_exec_r11_fault:\n call *%r10\n" EPI("c_sys_exec_r11")
        ".globl c_sys_exec_after\n"
        // Handler: copy gregs (ucontext_t + 40), resume at g_resume.
        ".balign 16\n.globl hcopy\nhcopy:\n"
        " mov %edi, g_sig(%rip)\n incq g_hits(%rip)\n lea 40(%rdx), %rsi\n lea g_regs(%rip), %rdi\n mov $23, %ecx\n rep movsq\n"
        " mov g_resume(%rip), %rax\n mov %rax, 168(%rdx)\n ret\n"
        ".data\n.balign 16\n"
        ".globl g_magic\ng_magic: .zero 128\n.globl g_target\ng_target: .quad 0\n.globl g_saved_rsp\ng_saved_rsp: .quad 0\n"
        ".globl g_resume\ng_resume: .quad 0\n.globl g_fault_rip\ng_fault_rip: .quad 0\n.globl g_flags_before\ng_flags_before: .quad 0\n"
        ".globl g_flags_after\ng_flags_after: .quad 0\n.globl g_regs\ng_regs: .zero 184\n.globl g_hits\ng_hits: .quad 0\n.globl g_sig\ng_sig: .quad 0\n"
        ".text\n");
extern char c_sys_exec_after[];

static u64 slen(const char* s) { u64 n = 0; while (s[n]) ++n; return n; }
static void out(const char* s) { sc4(SYS_write, 1, (i64)s, slen(s), 0); }
static void outhex(u64 v) {
  char b[19]; b[0] = '0'; b[1] = 'x';
  for (int i = 0; i < 16; i++) b[2 + i] = "0123456789abcdef"[(v >> (60 - 4 * i)) & 15];
  b[18] = 0; out(b);
}

static int failures;
static void check(const char* what, int ok) {
  out(ok ? "PASS: " : "FAIL: "); out(what); out("\n");
  if (!ok) ++failures;
}

enum { RIP_FAULT, RIP_AFTER1, RIP_TARGET };
struct tcase {
  const char* name;
  void (*fn)(void);
  int sig;
  int fault;       // 1: fault-class exception (RF expected), 0: trap
  int rip_kind;    // where the frame RIP must point
  int rsp_pushed;  // call pushed a return address
  int after_sys;   // rax/rcx/r11 come from the syscall
};

static void run(const struct tcase* t, u64 target, u64 pid) {
  g_target = target; g_hits = 0; g_sig = 0;
  for (int i = 0; i < G_NUM; ++i) g_regs[i] = 0;
  t->fn();
  u64 exp[16];
  for (int i = 0; i < 16; ++i) exp[i] = g_magic[i];
  exp[G_R10] = target;
  exp[G_RSP] = g_saved_rsp - (t->rsp_pushed ? 8 : 0);
  if (t->after_sys) { exp[G_RAX] = pid; exp[G_RCX] = (u64)c_sys_exec_after; exp[G_R11] = g_flags_before; }
  u64 exp_rip = t->rip_kind == RIP_TARGET ? target : g_fault_rip + (t->rip_kind == RIP_AFTER1 ? 1 : 0);
  u64 exp_efl = (g_flags_before & ~EFL_RF) | (t->fault ? EFL_RF : 0);

  out("RAW "); out(t->name); out(": sig="); outhex(g_sig); out(" hits="); outhex(g_hits); out(" efl="); outhex(g_regs[G_EFL]);
  out(" before="); outhex(g_flags_before); out(" trapno="); outhex(g_regs[G_TRAPNO]); out(" err="); outhex(g_regs[G_ERR]);
  out(" r11="); outhex(g_regs[G_R11]); out("\n");

  char buf[160];
  int ok = g_hits == 1 && g_sig == (u64)t->sig;
  #define MSG(s) do { const char* p_ = t->name; int n_ = 0; while (*p_) buf[n_++] = *p_++; p_ = (s); while (*p_) buf[n_++] = *p_++; buf[n_] = 0; } while (0)
  MSG(": one signal of the expected number"); check(buf, ok);
  if (!ok) return;
  MSG(t->fault ? ": EFLAGS in the frame = flags before the instruction | RF" : ": EFLAGS in the frame = flags before the instruction (RF clear)");
  check(buf, g_regs[G_EFL] == exp_efl);
  if (g_regs[G_EFL] != exp_efl) { out("      expected "); outhex(exp_efl); out(" got "); outhex(g_regs[G_EFL]); out("\n"); }
  MSG(": RIP in the frame"); check(buf, g_regs[G_RIP] == exp_rip);
  int gpr_ok = 1;
  for (int i = 0; i < 16; ++i) {
    if (g_regs[i] == exp[i]) continue;
    gpr_ok = 0;
    out("      "); out(gname[i]); out(" expected "); outhex(exp[i]); out(" got "); outhex(g_regs[i]); out("\n");
  }
  MSG(": all 16 general registers in the frame"); check(buf, gpr_ok);
  MSG(": PUSHF after rt_sigreturn shows RF clear"); check(buf, !(g_flags_after & EFL_RF));
}

static void install(int sig) {
  struct ksigaction a = {(void*)hcopy, SA_SIGINFO | SA_RESTORER | SA_NODEFER, (void*)restore_rt, 0};
  sc4(SYS_rt_sigaction, sig, (i64)&a, 0, 8);
}

__attribute__((used)) static void entry_c(void) {
  install(SIGSEGV); install(SIGILL); install(SIGFPE); install(SIGTRAP);
  for (int i = 0; i < 16; ++i) g_magic[i] = 0x5a5a000000000000UL | ((u64)(i + 1) << 32) | (0x01010101UL * (u64)(i + 1));
  // a read-write page (never executable) and an unmapped page
  u64 rw = (u64)sc6(SYS_mmap, 0, 0x2000, 3, 0x22, -1, 0);
  if (rw > (u64)-4096) { out("FAIL: mmap\nRESULT: FAIL\n"); sc4(SYS_exit_group, 1, 0, 0, 0); }
  sc4(SYS_munmap, (i64)(rw + 0x1000), 0x1000, 0, 0);
  const u64 nx = rw + 0x10, unmapped = rw + 0x1080;
  const u64 pid = (u64)sc4(SYS_getpid, 0, 0, 0, 0);

  static const struct tcase cases[] = {
    {"read-unmapped (#PF)", c_pf_read, SIGSEGV, 1, RIP_FAULT, 0, 0},
    {"exec-nonexec (#PF)", c_pf_exec, SIGSEGV, 1, RIP_TARGET, 1, 0},
    {"ud2 (#UD)", c_ud2, SIGILL, 1, RIP_FAULT, 0, 0},
    {"hlt (#GP)", c_hlt, SIGSEGV, 1, RIP_FAULT, 0, 0},
    {"int3 (#BP, trap)", c_int3, SIGTRAP, 0, RIP_AFTER1, 0, 0},
    {"exec-nonexec after syscall", c_sys_exec, SIGSEGV, 1, RIP_TARGET, 1, 1},
    {"exec-nonexec after syscall, r11 reloaded", c_sys_exec_r11, SIGSEGV, 1, RIP_TARGET, 1, 0},
  };
  for (int pass = 1; pass <= 2; ++pass) {  // second pass: every block already translated
    out(pass == 1 ? "# pass 1\n" : "# pass 2\n");
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
      const struct tcase* t = &cases[i];
      u64 target = t->fn == c_pf_read ? unmapped : nx;
      run(t, target, pid);
    }
  }
  out(failures ? "RESULT: FAIL\n" : "RESULT: PASS\n");
  sc4(SYS_exit_group, failures, 0, 0, 0);
}
__attribute__((naked, used)) void _start(void) { __asm__ volatile("and $-16, %rsp\n call entry_c\n"); }
