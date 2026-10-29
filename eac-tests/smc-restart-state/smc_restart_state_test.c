// SPDX-License-Identifier: MIT
//
// Regression test: a store to data that shares a page with the code writing it gives the instruction's result exactly
// once, with the registers and flags the instruction had before it ran.
//
// x86 rule (Intel SDM Vol. 3A 6.5): a fault is reported with the machine state as it was before the faulting
// instruction, so the instruction can be restarted. An instruction that completes has all of its effects exactly once.
//
// Under FEX with SMCChecks=mtrack the host page of translated guest code is write-protected. A guest store to it
// faults; FEX invalidates the page's translations and, when the store could hit the block that is executing, re-runs
// the storing instruction as a single-instruction block. The restart starts from the host state at the fault, which is
// in the middle of the instruction: for a read-modify-write the flags are already the new ones, for a stack or string
// instruction RSP/RSI/RDI already moved, for an x87 store-and-pop TOP already moved. Before the change the check used
// the whole page, so every data store to a code page took this restart, also when it cannot touch the running block's
// code. Self-decrypting code keeps its keys and counters next to the code (EAC's client, StonkGuy/FEX#35).
//
// Every case is a position-independent snippet copied to the start of a fresh 2-page RWX mapping and called with a
// loop count. Each iteration does the operation on a data word 0x600 bytes after the code (same page, not in the block)
// and the same operation on a register copy, and counts the iterations whose results differ. The page is translated
// again on every iteration (the loop re-enters the invalidated block), so with FEX_SMCHOTPAGEFAULTS=0 every iteration
// faults; with the default the first ones do before the page turns hot. The snippet runs in a forked child under alarm().
// Cases (1000 iterations each):
//   adc, sbb       `adc/sbb %ecx, mem` with CF from bit 17 of the value: a restart sees the new CF
//   rcl, rcr       `rcl/rcr $1, mem`, same
//   xadd           `xadd %esi, mem`: memory and the register
//   pop            `push %rcx; pop mem`: the value and RSP afterwards
//   stos, movs     `stosl` / `movsl` to the data word: the value and RDI (and RSI)
//   fstp           `fildl; fstpl mem`: the value and x87 TOP afterwards
//   cmpxchg        `cmpxchg %ecx, mem` that succeeds: ZF and the value
//   add            `add %ecx, mem` (control: a restart recomputes everything it writes, passes either way)
//
// Expected: passes on x86-64 Linux and with the change; results before it are in eac-tests/README.md.
// Run under FEX both with the default SMCHotPageFaults and with FEX_SMCHOTPAGEFAULTS=0.
// Build: eac-tests/smc-restart-state/build.sh [clang]   (x86-64 binary, run it under FEX)
// Run:   ./smc_restart_state_test   (exit status = number of failed checks)

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
enum { SYS_write = 1, SYS_mmap = 9, SYS_alarm = 37, SYS_fork = 57, SYS_exit = 60, SYS_wait4 = 61, SYS_exit_group = 231 };
enum { PROT_READ = 1, PROT_WRITE = 2, PROT_EXEC = 4, MAP_PRIVATE = 2, MAP_ANONYMOUS = 0x20 };
enum { ITERATIONS = 1000, TIMEOUT_SECONDS = 20, PAGE = 4096 };

static u64 slen(const char* s) { u64 n = 0; while (s[n]) n++; return n; }
static void out(const char* s) { sc3(SYS_write, 1, (i64)s, slen(s)); }
static void out_dec(i64 v) {
  char b[24]; int i = 23; b[i] = 0; int neg = v < 0; u64 u = neg ? -v : v;
  do { b[--i] = '0' + u % 10; u /= 10; } while (u);
  if (neg) b[--i] = '-';
  out(b + i);
}

static int failures;

// Each snippet: int snippet(int n /* edi */); returns the number of iterations with a wrong result in eax. Position
// independent, copied to offset 0 of the RWX mapping; its data word `9:` is 0x600 bytes after the code, on the same
// page. Clobbers only caller-saved registers. r11d = n, edx = iteration, ecx = this iteration's value, r8d = count.
#define SNIPPET(name) ".p2align 4, 0xcc\n.globl " #name "_begin, " #name "_end\n" #name "_begin:\n" \
  "  mov %edi, %r11d\n  xor %r8d, %r8d\n  xor %edx, %edx\n"
#define VALUE "1: imul $0x9e3779b9, %edx, %ecx\n"
#define COUNT_AL_AND_LOOP "  movzbl %al, %eax\n  add %eax, %r8d\n  inc %edx\n  cmp %r11d, %edx\n  jb 1b\n  mov %r8d, %eax\n"
#define DATA(name) "  .skip 0x600, 0xcc\n  .p2align 3\n9: .quad 0, 0\n" #name "_end:\n"
__asm__(
  ".text\n"

  // adc/sbb/rcl/rcr: the register copy r9d runs first with the same CF; resynchronised from memory after each check.
#define CF_RMW(name, insn_reg, insn_mem) \
  SNIPPET(name) "  xor %r9d, %r9d\n  movl $0, 9f(%rip)\n" VALUE \
  "  bt $17, %ecx\n  " insn_reg "\n" \
  "  bt $17, %ecx\n  " insn_mem "\n" \
  "  cmp 9f(%rip), %r9d\n  setne %al\n  mov 9f(%rip), %r9d\n" \
  COUNT_AL_AND_LOOP "  ret\n" DATA(name)
  CF_RMW(adc_mem, "adc %ecx, %r9d", "adc %ecx, 9f(%rip)")
  CF_RMW(sbb_mem, "sbb %ecx, %r9d", "sbb %ecx, 9f(%rip)")
  CF_RMW(rcl_mem, "rcl $1, %r9d", "rcll $1, 9f(%rip)")
  CF_RMW(rcr_mem, "rcr $1, %r9d", "rcrl $1, 9f(%rip)")
  CF_RMW(add_mem, "add %ecx, %r9d", "add %ecx, 9f(%rip)")

  // xadd: memory gets the sum, the register the old memory value.
  SNIPPET(xadd_mem) "  xor %r9d, %r9d\n  movl $0, 9f(%rip)\n" VALUE
  "  mov %ecx, %r10d\n  xadd %r10d, %r9d\n"
  "  mov %ecx, %esi\n  xadd %esi, 9f(%rip)\n"
  "  cmp 9f(%rip), %r9d\n  setne %al\n  cmp %esi, %r10d\n  setne %cl\n  or %cl, %al\n  mov 9f(%rip), %r9d\n"
  COUNT_AL_AND_LOOP "  ret\n" DATA(xadd_mem)

  // pop: the popped value lands in memory and RSP is back where it was before the push.
  SNIPPET(pop_mem) VALUE
  "  mov %rsp, %r10\n  push %rcx\n  popq 9f(%rip)\n"
  "  cmp 9f(%rip), %rcx\n  setne %al\n  cmp %rsp, %r10\n  setne %cl\n  or %cl, %al\n  mov %r10, %rsp\n"
  COUNT_AL_AND_LOOP "  ret\n" DATA(pop_mem)

  // stos: one dword stored, RDI advanced by 4.
  SNIPPET(stos_mem) VALUE
  "  lea 9f(%rip), %rdi\n  mov %ecx, %eax\n  stosl\n"
  "  lea 9f+4(%rip), %rsi\n  cmp %rsi, %rdi\n  setne %al\n  cmp 9f(%rip), %ecx\n  setne %sil\n  or %sil, %al\n"
  COUNT_AL_AND_LOOP "  ret\n" DATA(stos_mem)

  // movs: one dword copied from the stack, RSI and RDI advanced by 4.
  SNIPPET(movs_mem) VALUE
  "  push %rcx\n  mov %rsp, %rsi\n  lea 9f(%rip), %rdi\n  movsl\n  lea 4(%rsp), %r10\n  pop %r9\n"
  "  cmp %r10, %rsi\n  setne %al\n  lea 9f+4(%rip), %r10\n  cmp %r10, %rdi\n  setne %r9b\n  or %r9b, %al\n"
  "  cmp 9f(%rip), %ecx\n  setne %r9b\n  or %r9b, %al\n"
  COUNT_AL_AND_LOOP "  ret\n" DATA(movs_mem)

  // fstp: the iteration number as a double, and the x87 stack empty again (TOP as before the FILD).
  SNIPPET(fstp_mem) "  fninit\n" VALUE
  "  fnstsw %ax\n  and $0x3800, %eax\n  mov %eax, %r10d\n"
  "  push %rdx\n  fildl (%rsp)\n  pop %r9\n  fstpl 9f(%rip)\n"
  "  fnstsw %ax\n  and $0x3800, %eax\n  cmp %eax, %r10d\n  setne %r9b\n"
  "  cvtsi2sd %edx, %xmm0\n  movq %xmm0, %rsi\n  cmp 9f(%rip), %rsi\n  setne %al\n  or %r9b, %al\n"
  "  test %al, %al\n  jz 2f\n  fninit\n2:\n"
  COUNT_AL_AND_LOOP "  fninit\n  ret\n" DATA(fstp_mem)

  // cmpxchg that succeeds: ZF set, the new value in memory.
  SNIPPET(cmpxchg_mem) "  movl $0, 9f(%rip)\n" VALUE
  "  mov 9f(%rip), %eax\n  cmpxchg %ecx, 9f(%rip)\n"
  "  setne %al\n  cmp 9f(%rip), %ecx\n  setne %cl\n  or %cl, %al\n"
  COUNT_AL_AND_LOOP "  ret\n" DATA(cmpxchg_mem)
);

#define DECL(name) extern const unsigned char name##_begin[], name##_end[];
DECL(adc_mem) DECL(sbb_mem) DECL(rcl_mem) DECL(rcr_mem) DECL(add_mem) DECL(xadd_mem) DECL(pop_mem) DECL(stos_mem)
DECL(movs_mem) DECL(fstp_mem) DECL(cmpxchg_mem)

struct Case { const char* name; const unsigned char* begin; const unsigned char* end; };

static void run_case(const struct Case* c) {
  i64 pid = sc1(SYS_fork, 0);
  if (pid == 0) {
    unsigned char* page = (unsigned char*)sc6(SYS_mmap, 0, 2 * PAGE, PROT_READ | PROT_WRITE | PROT_EXEC,
                                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((i64)page < 0) sc1(SYS_exit_group, 255);
    u64 len = c->end - c->begin;
    if (len > PAGE) sc1(SYS_exit_group, 254);
    for (u64 i = 0; i < len; i++) page[i] = c->begin[i];
    sc1(SYS_alarm, TIMEOUT_SECONDS);
    int wrong = ((int (*)(int))page)(ITERATIONS);
    sc1(SYS_exit_group, wrong > 250 ? 250 : wrong);
  }
  int status = -1;
  sc4(SYS_wait4, pid, (i64)&status, 0, 0);
  int sig = status & 0x7f, code = (status >> 8) & 0xff;
  int ok = pid > 0 && sig == 0 && code == 0;
  out(ok ? "  ok   " : "  FAIL "); out(c->name);
  if (sig == 14) out(": timed out");
  else if (sig) { out(": killed by signal "); out_dec(sig); }
  else if (code) { out(": "); out_dec(code); out(" wrong results of "); out_dec(ITERATIONS); }
  out("\n");
  if (!ok) failures++;
}

void _start_c(void) {
  static const struct Case cases[] = {
    {"adc", adc_mem_begin, adc_mem_end},
    {"sbb", sbb_mem_begin, sbb_mem_end},
    {"rcl", rcl_mem_begin, rcl_mem_end},
    {"rcr", rcr_mem_begin, rcr_mem_end},
    {"xadd", xadd_mem_begin, xadd_mem_end},
    {"pop", pop_mem_begin, pop_mem_end},
    {"stos", stos_mem_begin, stos_mem_end},
    {"movs", movs_mem_begin, movs_mem_end},
    {"fstp", fstp_mem_begin, fstp_mem_end},
    {"cmpxchg", cmpxchg_mem_begin, cmpxchg_mem_end},
    {"add (control)", add_mem_begin, add_mem_end},
  };
  for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) run_case(&cases[i]);
  out(failures ? "RESULT: FAIL\n" : "RESULT: PASS\n");
  sc1(SYS_exit_group, failures);
  __builtin_unreachable();
}

__asm__(".globl _start\n_start:\n  andq $-16, %rsp\n  call _start_c\n  hlt\n");
