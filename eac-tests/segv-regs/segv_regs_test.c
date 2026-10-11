// SPDX-License-Identifier: MIT
//
// Checks the SIGSEGV fields a process sees for six kinds of memory fault: si_signo, si_code, si_addr, and the
// ucontext gregs REG_ERR and REG_TRAPNO, plus RIP for the execute faults. Each fault is taken by a SA_SIGINFO handler
// that records those values and resumes the program at a recovery label (RIP and RSP are rewritten in the frame).
//
// Who observes this: Wine maps the x86 page-fault error code (REG_ERR) into EXCEPTION_RECORD.ExceptionInformation[0]
// (read / write / execute) and si_addr into ExceptionInformation[1]. The title's anti-tamper fault scan reads those two
// fields to decide what memory is mapped and how it may be used, so a wrong bit or a wrong si_code changes its answer.
// Nothing else in the process depends on the exact bits, so the test checks only the bits the kernel defines.
//
// Expected values, from the Linux x86 page-fault path (mainline arch/x86/mm/fault.c; not checked against a local tree):
//   * trapno 14 = X86_TRAP_PF (arch/x86/include/asm/trapnr.h).
//   * error code bits (enum x86_pf_error_code, arch/x86/include/asm/traps.h): PROT=1<<0, WRITE=1<<1, USER=1<<2,
//     INSTR=1<<4 (instruction fetch). A user-mode fault always has USER set; WRITE is set for a write; INSTR is set for
//     a fetch on an NX page. PROT (bit 0) means "page present" and is NOT checked: it depends on whether the page was
//     already populated, and on x86 a PROT_NONE page has a not-present PTE, so the CPU reports bit 0 clear there.
//   * si_code (fault.c, access_error() and its callers): SEGV_MAPERR (1) when no VMA covers the address,
//     SEGV_ACCERR (2) when a VMA exists but does not permit the access (PROT_READ-only write, PROT_NONE read,
//     non-exec fetch).
//   * si_addr is the faulting linear address (CR2), exact, not page-rounded (force_sig_fault in fault.c).
//   * For a fetch fault RIP is the fetched address itself, because no instruction at that address has executed.
//   * Signal numbers and si_code values: include/uapi/asm-generic/siginfo.h. REG_* indices:
//     arch/x86/include/uapi/asm/sigcontext.h (REG_RSP 15, REG_RIP 16, REG_ERR 19, REG_TRAPNO 20).
//
// Cases (each prints one RAW line, always, so native and FEX outputs can be diffed; then PASS or FAIL):
//   1. read an unmapped page                     -> SEGV_MAPERR, addr exact, err: USER set, WRITE and INSTR clear
//   2. write a PROT_READ page                    -> SEGV_ACCERR, err: WRITE set, INSTR clear
//   3. read a PROT_NONE page                     -> SEGV_ACCERR, err: WRITE and INSTR clear
//   4. jump/call into a PROT_READ|PROT_WRITE page -> SEGV_ACCERR, err: INSTR set, WRITE clear, RIP = target
//   5. jump/call into an unmapped page            -> SEGV_MAPERR, err: INSTR set, WRITE clear, RIP = target
//   6. 8-byte read straddling into an unmapped page -> SEGV_MAPERR, addr = the page boundary (first faulting byte)
//
// Native x86-64 Linux is the reference. The binary is x86-64 only: it issues x86 syscalls and checks x86 registers.
// Build: tests/segv-regs/build.sh [clang]
// Run:   ./segv_regs_test   (exit status = number of failed checks)

#if !defined(__x86_64__)
#error "x86-64 only: the test checks x86 page-fault error codes and ucontext layout"
#endif

typedef unsigned long u64;
typedef unsigned int u32;
typedef long i64;

static inline i64 sc6(i64 nr, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f) {
  i64 ret;
  register i64 r10 __asm__("r10") = d;
  register i64 r8 __asm__("r8") = e;
  register i64 r9 __asm__("r9") = f;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                   : "rcx", "r11", "memory");
  return ret;
}
enum { SYS_write = 1, SYS_mmap = 9, SYS_munmap = 11, SYS_rt_sigaction = 13, SYS_exit_group = 231 };
enum { SIGSEGV = 11 };
enum { SEGV_MAPERR = 1, SEGV_ACCERR = 2 };
enum { PROT_READ = 1, PROT_WRITE = 2, PROT_EXEC = 4, MAP_PRIVATE = 2, MAP_ANONYMOUS = 0x20 };
enum { REG_RSP = 15, REG_RIP = 16, REG_ERR = 19, REG_TRAPNO = 20 };
enum { X86_PF_PROT = 1, X86_PF_WRITE = 2, X86_PF_USER = 4, X86_PF_INSTR = 16 };
enum { X86_TRAP_PF = 14 };
enum { PAGE = 4096 };
#define SA_SIGINFO 0x4
#define SA_RESTORER 0x04000000
struct ksigaction { void* handler; u64 flags; void* restorer; u64 mask; };

// Kernel ucontext_t as the signal frame lays it out: uc_flags, uc_link, uc_stack (stack_t, 24 bytes), then
// uc_mcontext.gregs[23] at offset 40.
struct uctx {
  u64 flags;
  u64 link;
  void* ss_sp;
  u32 ss_flags;
  u32 ss_pad;
  u64 ss_size;
  u64 gregs[23];
};
_Static_assert(__builtin_offsetof(struct uctx, gregs) == 40, "gregs must sit at offset 40 of ucontext_t");

// siginfo_t header: si_signo, si_errno, si_code, then the union whose first member for SIGSEGV is si_addr at offset 16.
struct sinfo {
  int signo;
  int errno_;
  int code;
  int pad;
  void* addr;
};
_Static_assert(__builtin_offsetof(struct sinfo, addr) == 16, "si_addr must sit at offset 16 of siginfo_t");

__attribute__((naked, used)) static void restore_rt(void) { __asm__ volatile("mov $15, %eax\n syscall\n"); }

// What the handler saw for the current case.
struct rec { u64 signo, code, addr, err, trapno, rip, hits; };
static struct rec g_rec;
// Where the handler resumes: set by each case right before the faulting instruction.
u64 g_recover_rip, g_recover_rsp;

static void on_segv(int sig, struct sinfo* si, struct uctx* uc) {
  g_rec.signo = (u64)sig;
  g_rec.code = (u64)(i64)si->code;
  g_rec.addr = (u64)si->addr;
  g_rec.err = uc->gregs[REG_ERR];
  g_rec.trapno = uc->gregs[REG_TRAPNO];
  g_rec.rip = uc->gregs[REG_RIP];
  g_rec.hits++;
  uc->gregs[REG_RIP] = g_recover_rip;
  uc->gregs[REG_RSP] = g_recover_rsp;
}

static u64 slen(const char* s) { u64 n = 0; while (s[n]) ++n; return n; }
static void out(const char* s) { sc6(SYS_write, 1, (i64)s, (i64)slen(s), 0, 0, 0); }
static void outdec(u64 v) { char b[24]; int i = 23; b[i] = 0; do { b[--i] = '0' + v % 10; v /= 10; } while (v); out(b + i); }
static void outhex(u64 v) {
  char b[19]; int i = 18; b[i] = 0;
  do { b[--i] = "0123456789abcdef"[v & 15]; v >>= 4; } while (v);
  b[--i] = 'x'; b[--i] = '0';
  out(b + i);
}

static int failures;
static void check(int ok, const char* what) { out(ok ? "PASS: " : "FAIL: "); out(what); out("\n"); if (!ok) failures++; }

// Recovery setup shared by the fault cases: the recovery label is the instruction after the faulting one, and RSP is
// saved so the handler can restore it (the call case pushes a return address before it faults).
#define RECOVER_SETUP                                   \
  "leaq 1f(%%rip), %%rcx\n"                             \
  "movq %%rcx, g_recover_rip(%%rip)\n"                  \
  "movq %%rsp, g_recover_rsp(%%rip)\n"

static void touch_read(volatile unsigned char* p) {  // one-byte load
  __asm__ volatile(RECOVER_SETUP "movb (%[p]), %%al\n"
                   "1:\n"
                   :
                   : [p] "r"(p)
                   : "rax", "rcx", "memory", "cc");
}
static void touch_read8(volatile unsigned char* p) {  // eight-byte load (may straddle a page boundary)
  __asm__ volatile(RECOVER_SETUP "movq (%[p]), %%rax\n"
                   "1:\n"
                   :
                   : [p] "r"(p)
                   : "rax", "rcx", "memory", "cc");
}
static void touch_write(volatile unsigned char* p) {
  __asm__ volatile(RECOVER_SETUP "movb $0x5a, (%[p])\n"
                   "1:\n"
                   :
                   : [p] "r"(p)
                   : "rcx", "memory", "cc");
}
static void jump_to(u64 target) {  // call, so the fault is a fetch with the return address already pushed
  __asm__ volatile(RECOVER_SETUP "call *%[t]\n"
                   "1:\n"
                   :
                   : [t] "r"(target)
                   : "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "memory", "cc");
}

static void reset_rec(void) {
  g_rec.signo = g_rec.code = g_rec.addr = g_rec.err = g_rec.trapno = g_rec.rip = 0;
  g_rec.hits = 0;
}

static void print_raw(int n, const char* name) {
  out("RAW case "); outdec((u64)n); out(" "); out(name);
  out(": signo="); outdec(g_rec.signo);
  out(" code="); outdec(g_rec.code);
  out(" addr="); outhex(g_rec.addr);
  out(" err="); outhex(g_rec.err);
  out(" trapno="); outdec(g_rec.trapno);
  out(" rip="); outhex(g_rec.rip);
  out(" hits="); outdec(g_rec.hits);
  out("\n");
}

// want_fetch / want_write: the err bits the kernel sets for this access (checked both ways).
// want_rip: RIP must equal the faulting address (fetch faults only).
static void verify(int n, const char* name, u64 want_code, u64 want_addr, int want_write, int want_fetch, int want_rip) {
  print_raw(n, name);
  u64 e = g_rec.err;
  int ok_hits = g_rec.hits == 1;
  int ok_sig = g_rec.signo == SIGSEGV;
  int ok_code = g_rec.code == want_code;
  int ok_addr = g_rec.addr == want_addr;
  int ok_trap = g_rec.trapno == X86_TRAP_PF;
  int ok_user = (e & X86_PF_USER) != 0;
  int ok_w = ((e & X86_PF_WRITE) != 0) == (want_write != 0);
  int ok_i = ((e & X86_PF_INSTR) != 0) == (want_fetch != 0);
  int ok_rip = !want_rip || g_rec.rip == want_addr;
  // The FAIL line names each expectation that did not hold; the RAW line above carries the values.
  out(ok_hits && ok_sig && ok_code && ok_addr && ok_trap && ok_user && ok_w && ok_i && ok_rip ? "PASS: " : "FAIL: ");
  out("case "); outdec((u64)n); out(" "); out(name);
  out(ok_hits ? "" : " [hits]");
  out(ok_sig ? "" : " [signo]");
  out(ok_code ? "" : " [si_code]");
  out(ok_addr ? "" : " [si_addr]");
  out(ok_trap ? "" : " [trapno]");
  out(ok_user ? "" : " [err.user]");
  out(ok_w ? "" : " [err.write]");
  out(ok_i ? "" : " [err.fetch]");
  out(ok_rip ? "" : " [rip]");
  out("\n");
  if (!(ok_hits && ok_sig && ok_code && ok_addr && ok_trap && ok_user && ok_w && ok_i && ok_rip)) failures++;
}

static u64 map_pages(u64 len, i64 prot) {
  i64 r = sc6(SYS_mmap, 0, (i64)len, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  return (r < 0 && r > -4096) ? 0 : (u64)r;
}

__attribute__((used)) static void entry_c(void) {
  struct ksigaction segv = { (void*)on_segv, SA_SIGINFO | SA_RESTORER, (void*)restore_rt, 0 };
  check(sc6(SYS_rt_sigaction, SIGSEGV, (i64)&segv, 0, 8, 0, 0) == 0, "install the SIGSEGV handler");

  u64 rw = map_pages(PAGE, PROT_READ | PROT_WRITE);
  u64 ro = map_pages(PAGE, PROT_READ);
  u64 none = map_pages(PAGE, 0);
  u64 pair = map_pages(2 * PAGE, PROT_READ | PROT_WRITE);
  u64 unm1 = map_pages(PAGE, PROT_READ | PROT_WRITE);
  u64 unm2 = map_pages(PAGE, PROT_READ | PROT_WRITE);
  u64 unm3 = map_pages(PAGE, PROT_READ | PROT_WRITE);
  if (!rw || !ro || !none || !pair || !unm1 || !unm2 || !unm3) {
    out("FAIL: mmap\n");
    sc6(SYS_exit_group, 1, 0, 0, 0, 0, 0);
  }
  // Make the unmapped pages unmapped again (their addresses stay meaningful: no mapping covers them).
  sc6(SYS_munmap, (i64)unm1, PAGE, 0, 0, 0, 0);
  sc6(SYS_munmap, (i64)unm2, PAGE, 0, 0, 0, 0);
  sc6(SYS_munmap, (i64)unm3, PAGE, 0, 0, 0, 0);
  sc6(SYS_munmap, (i64)(pair + PAGE), PAGE, 0, 0, 0, 0);  // second page of the pair is now unmapped

  // Plant ud2 at the start of the executable-target page. The test never runs it: if a fetch wrongly succeeded, the
  // process would die with SIGILL instead of silently running on.
  volatile unsigned char* code = (volatile unsigned char*)(rw + 0x10);
  code[0] = 0x0f;
  code[1] = 0x0b;

  // (1) read an unmapped page, exact address inside the page
  reset_rec();
  touch_read((volatile unsigned char*)(unm1 + 0x123));
  verify(1, "read-unmapped", SEGV_MAPERR, unm1 + 0x123, 0, 0, 0);

  // (2) write to a PROT_READ page
  reset_rec();
  touch_write((volatile unsigned char*)(ro + 0x80));
  verify(2, "write-readonly", SEGV_ACCERR, ro + 0x80, 1, 0, 0);

  // (3) read from a PROT_NONE page
  reset_rec();
  touch_read((volatile unsigned char*)(none + 0x40));
  verify(3, "read-protnone", SEGV_ACCERR, none + 0x40, 0, 0, 0);

  // (4) fetch from a PROT_READ|PROT_WRITE page (no PROT_EXEC)
  reset_rec();
  jump_to(rw + 0x10);
  verify(4, "exec-nonexec-page", SEGV_ACCERR, rw + 0x10, 0, 1, 1);

  // (5) fetch from an unmapped page
  reset_rec();
  jump_to(unm2 + 0x20);
  verify(5, "exec-unmapped", SEGV_MAPERR, unm2 + 0x20, 0, 1, 1);

  // (6) 8-byte read starting 4 bytes before the end of a mapped page; the second page is unmapped.
  reset_rec();
  touch_read8((volatile unsigned char*)(pair + PAGE - 4));
  verify(6, "read-straddle-unmapped", SEGV_MAPERR, pair + PAGE, 0, 0, 0);

  out(failures ? "RESULT: FAIL\n" : "RESULT: PASS\n");
  sc6(SYS_exit_group, failures, 0, 0, 0, 0, 0);
}

__attribute__((naked, used)) void _start(void) { __asm__ volatile("and $-16, %rsp\n call entry_c\n"); }
