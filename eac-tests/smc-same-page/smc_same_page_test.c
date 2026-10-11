// SPDX-License-Identifier: MIT
//
// Regression test: code that rewrites instructions on its own page sees every change and makes progress.
//
// x86 rule (Intel SDM Vol. 3A 9.1.3/11.6, AMD APM Vol. 2 7.6.1): on P6 and later a store to a code address is
// detected by the processor, including a store to an instruction that is already prefetched or decoded, and the
// modified instruction executes from then on. A jump (or a serialising instruction) between the store and the modified
// code is only required for compatibility with the 486. So a single thread that patches the next instruction runs the
// new bytes even without a jump.
//
// Under FEX with SMCChecks=mtrack the host page of translated guest code is write-protected. A guest store to it
// faults; FEX invalidates the page's translations and, when the store hit the block that is executing, re-runs the
// storing instruction as a single-instruction block so the following code is translated again. When the writer and
// the written code share one page this fault -> invalidate -> retranslate -> re-protect cycle repeats for every
// store, and must still make forward progress and run the new code.
//
// Every case is a position-independent snippet that is copied to the start of a fresh 2-page RWX mapping and called
// with a loop count; it returns the number of iterations that executed stale code. The snippet runs in a forked child
// under alarm(), so a hang is reported as a failure instead of hanging the test.
// Cases (each iterates 1000 times, 20000 with the second thread; every iteration writes a new value):
//   ahead-next      1-byte store into the immediate of the very next instruction (same block, no jump)
//   ahead-jmp       4-byte store ahead, then a jmp to the modified instruction
//   ahead-cpuid     4-byte store ahead, then CPUID (serialising) before the modified instruction
//   behind          4-byte store into an instruction earlier in the loop (executed on the next iteration)
//   other-block     store into a function 0x600 bytes further on the same page, then call it
//   replace-8       8-byte store replacing whole instructions (different opcodes and lengths), same block
//   rep-movsb       REP MOVSB copies 8 bytes of new instructions ahead, same block
//   lock-add        LOCK ADD on the immediate of the next instruction
//   sse-16          16-byte MOVUPS replacing four instructions ahead
//   cross-page      8-byte store straddling the page boundary into an instruction that straddles it too
//   stack-on-page   RSP inside the code page: CALL/PUSH write the page as well as an explicit 1-byte patch
//   *+thread        the same snippets while a second thread keeps calling a function on the same page. Every SMC fault
//                   invalidates that function too, so the thread keeps retranslating code from the page.
//
// Expected: passes on x86-64 Linux (kernel 6.19, 10 of 10 runs) and with the change. Before it (eac-2610 0d13aba)
// the four +thread cases fail on every run with FEX_SMCHOTPAGEFAULTS=0 and on some runs with the default (hot pages
// usually take over before the race hits); the single-thread cases pass. Run under FEX both with the default
// SMCHotPageFaults and with FEX_SMCHOTPAGEFAULTS=0 (pages stay write-protected and keep faulting).
// Build: eac-tests/smc-same-page/build.sh [clang]   (x86-64 binary, run it under FEX)
// Run:   ./smc_same_page_test   (exit status = number of failed checks)

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
enum { ITERATIONS = 1000, THREAD_ITERATIONS = 20000, TIMEOUT_SECONDS = 20, PAGE = 4096 };

static u64 slen(const char* s) { u64 n = 0; while (s[n]) n++; return n; }
static void out(const char* s) { sc3(SYS_write, 1, (i64)s, slen(s)); }
static void out_dec(i64 v) {
  char b[24]; int i = 23; b[i] = 0; int neg = v < 0; u64 u = neg ? -v : v;
  do { b[--i] = '0' + u % 10; u /= 10; } while (u);
  if (neg) b[--i] = '-';
  out(b + i);
}

static int failures;

// Each snippet: int snippet(int n /* edi */); returns the number of stale iterations in eax. Position independent,
// copied to offset 0 of the RWX mapping. Clobbers only caller-saved registers (rbx is saved where CPUID is used).
#define SNIPPET(name) ".p2align 4, 0xcc\n.globl " #name "_begin, " #name "_end\n" #name "_begin:\n"
#define END(name) #name "_end:\n"
__asm__(
  ".text\n"

  // ahead-next: the store's target is the next instruction. imm8 of `mov $0, %eax` <- i & 0x7f.
  SNIPPET(ahead_next)
  "  xor %r8d, %r8d\n  xor %edx, %edx\n"
  "1: mov %edx, %ecx\n  and $0x7f, %ecx\n"
  "  movb %cl, 2f+1(%rip)\n"
  "2: mov $0, %eax\n"
  "  cmp %ecx, %eax\n  setne %al\n  movzbl %al, %eax\n  add %eax, %r8d\n"
  "  inc %edx\n  cmp %edi, %edx\n  jb 1b\n"
  "  mov %r8d, %eax\n  ret\n"
  END(ahead_next)

  // ahead-jmp: 4-byte store, jmp, then the modified instruction.
  SNIPPET(ahead_jmp)
  "  xor %r8d, %r8d\n  xor %edx, %edx\n"
  "1: lea 0x1000(%rdx), %ecx\n"
  "  movl %ecx, 2f+1(%rip)\n"
  "  jmp 2f\n"
  "2: mov $0, %eax\n"
  "  cmp %ecx, %eax\n  setne %al\n  movzbl %al, %eax\n  add %eax, %r8d\n"
  "  inc %edx\n  cmp %edi, %edx\n  jb 1b\n"
  "  mov %r8d, %eax\n  ret\n"
  END(ahead_jmp)

  // ahead-cpuid: 4-byte store, CPUID (serialising), then the modified instruction.
  SNIPPET(ahead_cpuid)
  "  push %rbx\n  xor %r8d, %r8d\n  xor %r9d, %r9d\n"
  "1: lea 0x2000(%r9), %r10d\n"
  "  movl %r10d, 2f+2(%rip)\n"
  "  xor %eax, %eax\n  xor %ecx, %ecx\n  cpuid\n"
  "2: mov $0, %r11d\n" // 41 bb imm32
  "  cmp %r10d, %r11d\n  setne %al\n  movzbl %al, %eax\n  add %eax, %r8d\n"
  "  inc %r9d\n  cmp %edi, %r9d\n  jb 1b\n"
  "  mov %r8d, %eax\n  pop %rbx\n  ret\n"
  END(ahead_cpuid)

  // behind: the modified instruction is at the loop top, before the store.
  SNIPPET(behind)
  "  xor %r8d, %r8d\n  xor %edx, %edx\n  movl $0, 1f+1(%rip)\n"
  "1: mov $0x55555555, %eax\n"
  "  cmp %edx, %eax\n  setne %al\n  movzbl %al, %eax\n  add %eax, %r8d\n"
  "  inc %edx\n"
  "  movl %edx, 1b+1(%rip)\n"
  "  cmp %edi, %edx\n  jb 1b\n"
  "  mov %r8d, %eax\n  ret\n"
  END(behind)

  // other-block: patch a function further on the same page, then call it.
  SNIPPET(other_block)
  "  xor %r8d, %r8d\n  xor %edx, %edx\n"
  "1: lea 0x3000(%rdx), %ecx\n"
  "  movl %ecx, 3f+1(%rip)\n"
  "  call 3f\n"
  "  cmp %ecx, %eax\n  setne %al\n  movzbl %al, %eax\n  add %eax, %r8d\n"
  "  inc %edx\n  cmp %edi, %edx\n  jb 1b\n"
  "  mov %r8d, %eax\n  ret\n"
  "  .skip 0x600, 0xcc\n"
  "3: mov $0, %eax\n  ret\n"
  END(other_block)

  // replace-8: an 8-byte store alternates the next 8 bytes between
  //   b8 imm32 90 90 90      mov $imm32, %eax; nop x3            (eax = i)
  //   31 c0 04 imm8 90 90 90 90  xor %eax,%eax; add $imm8,%al; nop x4  (eax = i & 0x7f)
  SNIPPET(replace_8)
  "  xor %r8d, %r8d\n  xor %edx, %edx\n"
  "1: test $1, %dl\n  jnz 4f\n"
  "  mov %rdx, %rcx\n  shl $8, %rcx\n  or $0xb8, %rcx\n  mov $0x9090900000000000, %rsi\n  or %rsi, %rcx\n"
  "  mov %edx, %r9d\n  jmp 5f\n"
  "4: mov %edx, %r9d\n  and $0x7f, %r9d\n  mov %r9, %rcx\n  shl $24, %rcx\n  or $0x04c031, %rcx\n"
  "  mov $0x9090909000000000, %rsi\n  or %rsi, %rcx\n"
  "5: movq %rcx, 2f(%rip)\n"
  "2: .byte 0xb8, 0xff, 0xff, 0xff, 0xff, 0x90, 0x90, 0x90\n"
  "  cmp %r9d, %eax\n  setne %al\n  movzbl %al, %eax\n  add %eax, %r8d\n"
  "  inc %edx\n  cmp %edi, %edx\n  jb 1b\n"
  "  mov %r8d, %eax\n  ret\n"
  END(replace_8)

  // rep-movsb: build the 8 bytes `b8 imm32 90 90 90` on the stack and REP MOVSB them over the next instruction.
  SNIPPET(rep_movsb)
  "  xor %r8d, %r8d\n  xor %edx, %edx\n  sub $24, %rsp\n"
  "1: lea 0x4000(%rdx), %r9d\n"
  "  mov %r9, %rax\n  shl $8, %rax\n  or $0xb8, %rax\n  mov $0x9090900000000000, %rsi\n  or %rsi, %rax\n"
  "  mov %rax, (%rsp)\n"
  "  mov %rsp, %rsi\n  lea 2f(%rip), %r10\n  mov %r10, %r11\n  xchg %r11, %rdi\n  mov $8, %ecx\n  rep movsb\n  mov %r11, %rdi\n"
  "2: .byte 0xb8, 0xff, 0xff, 0xff, 0xff, 0x90, 0x90, 0x90\n"
  "  cmp %r9d, %eax\n  setne %al\n  movzbl %al, %eax\n  add %eax, %r8d\n"
  "  inc %edx\n  cmp %edi, %edx\n  jb 1b\n"
  "  add $24, %rsp\n  mov %r8d, %eax\n  ret\n"
  END(rep_movsb)

  // lock-add: LOCK ADD $1 to the immediate of the next instruction (aligned), so it counts iterations.
  SNIPPET(lock_add)
  "  xor %r8d, %r8d\n  xor %edx, %edx\n  movl $0, 2f+1(%rip)\n"
  "1: lock addl $1, 2f+1(%rip)\n"
  "  .p2align 2, 0x90\n  .byte 0x90, 0x90, 0x90\n" // pad so the immediate of 2f is 4-byte aligned
  "2: mov $0, %eax\n"
  "  inc %edx\n"
  "  cmp %edx, %eax\n  setne %al\n  movzbl %al, %eax\n  add %eax, %r8d\n"
  "  cmp %edi, %edx\n  jb 1b\n"
  "  mov %r8d, %eax\n  ret\n"
  END(lock_add)

  // sse-16: MOVUPS 16 bytes over four 4-byte instructions `83 c0 imm8 90` (add $imm8,%eax; nop) ahead.
  SNIPPET(sse_16)
  "  xor %r8d, %r8d\n  xor %edx, %edx\n  sub $24, %rsp\n"
  "1: mov %edx, %ecx\n  and $0x1f, %ecx\n" // each add gets imm8 = (i & 0x1f); sum = 4 * that
  "  mov %ecx, %eax\n  shl $16, %eax\n  or $0x9000c083, %eax\n"
  "  mov %eax, (%rsp)\n  mov %eax, 4(%rsp)\n  mov %eax, 8(%rsp)\n  mov %eax, 12(%rsp)\n"
  "  movups (%rsp), %xmm0\n"
  "  xor %eax, %eax\n"
  "  movups %xmm0, 2f(%rip)\n"
  "2: .byte 0x83, 0xc0, 0x7f, 0x90, 0x83, 0xc0, 0x7f, 0x90, 0x83, 0xc0, 0x7f, 0x90, 0x83, 0xc0, 0x7f, 0x90\n"
  "  shl $2, %ecx\n"
  "  cmp %ecx, %eax\n  setne %al\n  movzbl %al, %eax\n  add %eax, %r8d\n"
  "  inc %edx\n  cmp %edi, %edx\n  jb 1b\n"
  "  add $24, %rsp\n  mov %r8d, %eax\n  ret\n"
  END(sse_16)

  // cross-page: the modified 8 bytes start 4 bytes before the end of the first page (offset 0xffc).
  SNIPPET(cross_page)
  "  jmp 1f\n"
  "  .skip 0xfa0 - 2, 0xcc\n"
  "1: xor %r8d, %r8d\n  xor %edx, %edx\n"
  "6: lea 0x5000(%rdx), %r9d\n"
  "  mov %r9, %rcx\n  shl $8, %rcx\n  or $0xb8, %rcx\n  mov $0x9090900000000000, %rsi\n  or %rsi, %rcx\n"
  "  movq %rcx, 2f(%rip)\n"
  "  jmp 2f\n"
  "  .skip (cross_page_begin + 0xffc) - ., 0xcc\n"
  "2: .byte 0xb8, 0xff, 0xff, 0xff, 0xff, 0x90, 0x90, 0x90\n"
  "  cmp %r9d, %eax\n  setne %al\n  movzbl %al, %eax\n  add %eax, %r8d\n"
  "  inc %edx\n  cmp %edi, %edx\n  jb 6b\n"
  "  mov %r8d, %eax\n  ret\n"
  END(cross_page)

  // stack-on-page: RSP points into the code page itself, every iteration CALLs and PUSHes there and also
  // patches the next instruction (1 byte).
  SNIPPET(stack_on_page)
  "  mov %rsp, %r11\n  lea 0xf00+stack_on_page_begin(%rip), %rsp\n" // rip-relative: inside the mapping
  "  xor %r8d, %r8d\n  xor %edx, %edx\n"
  "1: push %rdx\n  call 3f\n  pop %rcx\n"
  "  and $0x7f, %ecx\n  movb %cl, 2f+1(%rip)\n"
  "2: mov $0, %eax\n"
  "  cmp %ecx, %eax\n  setne %al\n  movzbl %al, %eax\n  add %eax, %r8d\n"
  "  inc %edx\n  cmp %edi, %edx\n  jb 1b\n"
  "  mov %r11, %rsp\n  mov %r8d, %eax\n  ret\n"
  "3: ret\n"
  END(stack_on_page)

  // spawn_spinner(stack_top, fn): a CLONE_THREAD thread that calls fn forever. fn is on the code page, so the thread
  // keeps translating code from the page the main thread is rewriting (and write-protects it again each time).
  ".globl spawn_spinner\n"
  "spawn_spinner:\n"
  "  mov %rsi, -8(%rdi)\n  lea -8(%rdi), %rsi\n"
  "  mov $0x50f00, %edi\n" // CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM
  "  xor %edx, %edx\n  xor %r10d, %r10d\n  xor %r8d, %r8d\n  mov $56, %eax\n  syscall\n"
  "  test %rax, %rax\n  jnz 1f\n"
  "  pop %rbx\n"
  "2: call *%rbx\n  jmp 2b\n"
  "1: ret\n"
);
void spawn_spinner(void* stack_top, const void* fn);

#define DECL(name) extern const unsigned char name##_begin[], name##_end[];
DECL(ahead_next) DECL(ahead_jmp) DECL(ahead_cpuid) DECL(behind) DECL(other_block) DECL(replace_8) DECL(rep_movsb)
DECL(lock_add) DECL(sse_16) DECL(cross_page) DECL(stack_on_page)

struct Case { const char* name; const unsigned char* begin; const unsigned char* end; int spinner; };

static void run_case(const struct Case* c) {
  i64 pid = sc1(SYS_fork, 0);
  if (pid == 0) {
    unsigned char* page = (unsigned char*)sc6(SYS_mmap, 0, 2 * PAGE, PROT_READ | PROT_WRITE | PROT_EXEC,
                                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((i64)page < 0) sc1(SYS_exit_group, 255);
    u64 len = c->end - c->begin;
    if (len > 2 * PAGE) sc1(SYS_exit_group, 254);
    for (u64 i = 0; i < len; i++) page[i] = c->begin[i];
    if (c->spinner) {
      // `mov $1, %eax; ret` at the end of the first page, run by a second thread.
      static const unsigned char Stub[6] = {0xb8, 1, 0, 0, 0, 0xc3};
      for (int i = 0; i < 6; i++) page[0xe00 + i] = Stub[i];
      unsigned char* stack = (unsigned char*)sc6(SYS_mmap, 0, 16 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if ((i64)stack < 0) sc1(SYS_exit_group, 253);
      spawn_spinner(stack + 16 * PAGE, page + 0xe00);
    }
    sc1(SYS_alarm, TIMEOUT_SECONDS);
    int stale = ((int (*)(int))page)(c->spinner ? THREAD_ITERATIONS : ITERATIONS);
    sc1(SYS_exit_group, stale > 250 ? 250 : stale);
  }
  int status = -1;
  sc4(SYS_wait4, pid, (i64)&status, 0, 0);
  int sig = status & 0x7f, code = (status >> 8) & 0xff;
  int ok = pid > 0 && sig == 0 && code == 0;
  out(ok ? "  ok   " : "  FAIL "); out(c->name);
  if (sig == 14) out(": timed out (no forward progress)");
  else if (sig) { out(": killed by signal "); out_dec(sig); }
  else if (code) { out(": "); out_dec(code); out(" stale iterations of "); out_dec(c->spinner ? THREAD_ITERATIONS : ITERATIONS); }
  out("\n");
  if (!ok) failures++;
}

void _start_c(void) {
  static const struct Case cases[] = {
    {"ahead-next", ahead_next_begin, ahead_next_end},
    {"ahead-jmp", ahead_jmp_begin, ahead_jmp_end},
    {"ahead-cpuid", ahead_cpuid_begin, ahead_cpuid_end},
    {"behind", behind_begin, behind_end},
    {"other-block", other_block_begin, other_block_end},
    {"replace-8", replace_8_begin, replace_8_end},
    {"rep-movsb", rep_movsb_begin, rep_movsb_end},
    {"lock-add", lock_add_begin, lock_add_end},
    {"sse-16", sse_16_begin, sse_16_end},
    {"cross-page", cross_page_begin, cross_page_end},
    {"stack-on-page", stack_on_page_begin, stack_on_page_end},
    {"ahead-next+thread", ahead_next_begin, ahead_next_end, 1},
    {"behind+thread", behind_begin, behind_end, 1},
    {"replace-8+thread", replace_8_begin, replace_8_end, 1},
    {"other-block+thread", other_block_begin, other_block_end, 1},
  };
  for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) run_case(&cases[i]);
  out(failures ? "RESULT: FAIL\n" : "RESULT: PASS\n");
  sc1(SYS_exit_group, failures);
  __builtin_unreachable();
}

__asm__(".globl _start\n_start:\n  andq $-16, %rsp\n  call _start_c\n  hlt\n");
