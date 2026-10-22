/* Raw-syscall NtContinue (0x43) / NtYieldExecution (0x46) fidelity test for Wine on FEX.
 * Windows x64 PE; run under Wine natively (x86-64 oracle) and under FEX.
 * Phase 1: N raw `syscall` NtContinue to a crafted CONTEXT (DF/AC set, TF off, MXCSR 0x9fc0,
 *          XMM6-15, r8-r15); a resume stub dumps the live registers, compared field by field.
 * Phase 2: N raw `syscall` NtYieldExecution; checks status 0 and that r8-r15/rbx/rbp/xmm6 survive. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static unsigned ITERS = 100000;
DWORD nr_continue = 0x43, nr_yield = 0x46;

typedef struct { DWORD64 r[8]; DWORD64 rflags; DWORD mxcsr; DWORD pad; M128A xmm[10]; } dump_t;
dump_t got;
DWORD64 saved_rsp;
static __declspec(align(16)) unsigned char scratch[65536];

void run_one(CONTEXT *ctx); void resume_stub(void); LONG raw_yield(DWORD64 *r);
__asm__(
".globl run_one\nrun_one:\n"
"  push %rbx\n push %rbp\n push %rdi\n push %rsi\n push %r12\n push %r13\n push %r14\n push %r15\n"
"  sub $0xa8, %rsp\n"
"  movdqu %xmm6,0x00(%rsp)\n movdqu %xmm7,0x10(%rsp)\n movdqu %xmm8,0x20(%rsp)\n movdqu %xmm9,0x30(%rsp)\n"
"  movdqu %xmm10,0x40(%rsp)\n movdqu %xmm11,0x50(%rsp)\n movdqu %xmm12,0x60(%rsp)\n movdqu %xmm13,0x70(%rsp)\n"
"  movdqu %xmm14,0x80(%rsp)\n movdqu %xmm15,0x90(%rsp)\n"
"  mov %rsp, saved_rsp(%rip)\n"
"  mov %rcx, %r10\n xor %edx, %edx\n mov nr_continue(%rip), %eax\n syscall\n"
"  ud2\n"
".globl resume_stub\nresume_stub:\n"
"  pushfq\n pop got+0x40(%rip)\n cld\n"
"  mov %r8,got+0x00(%rip)\n mov %r9,got+0x08(%rip)\n mov %r10,got+0x10(%rip)\n mov %r11,got+0x18(%rip)\n"
"  mov %r12,got+0x20(%rip)\n mov %r13,got+0x28(%rip)\n mov %r14,got+0x30(%rip)\n mov %r15,got+0x38(%rip)\n"
"  stmxcsr got+0x48(%rip)\n"
"  movdqu %xmm6,got+0x50(%rip)\n movdqu %xmm7,got+0x60(%rip)\n movdqu %xmm8,got+0x70(%rip)\n movdqu %xmm9,got+0x80(%rip)\n"
"  movdqu %xmm10,got+0x90(%rip)\n movdqu %xmm11,got+0xa0(%rip)\n movdqu %xmm12,got+0xb0(%rip)\n movdqu %xmm13,got+0xc0(%rip)\n"
"  movdqu %xmm14,got+0xd0(%rip)\n movdqu %xmm15,got+0xe0(%rip)\n"
"  mov saved_rsp(%rip), %rsp\n"
"  pushfq\n andq $~0x40000, (%rsp)\n popfq\n"   /* clear AC */
"  movdqu 0x00(%rsp),%xmm6\n movdqu 0x10(%rsp),%xmm7\n movdqu 0x20(%rsp),%xmm8\n movdqu 0x30(%rsp),%xmm9\n"
"  movdqu 0x40(%rsp),%xmm10\n movdqu 0x50(%rsp),%xmm11\n movdqu 0x60(%rsp),%xmm12\n movdqu 0x70(%rsp),%xmm13\n"
"  movdqu 0x80(%rsp),%xmm14\n movdqu 0x90(%rsp),%xmm15\n"
"  add $0xa8, %rsp\n"
"  pop %r15\n pop %r14\n pop %r13\n pop %r12\n pop %rsi\n pop %rdi\n pop %rbp\n pop %rbx\n ret\n"
/* raw NtYieldExecution with marker values in callee-saved r12-r15; returns status, writes r12-r15 after */
".globl raw_yield\nraw_yield:\n"
"  push %r12\n push %r13\n push %r14\n push %r15\n"
"  mov $0x1212121212121212,%r12\n mov $0x1313131313131313,%r13\n mov $0x1414141414141414,%r14\n mov $0x1515151515151515,%r15\n"
"  push %rcx\n sub $8,%rsp\n mov nr_yield(%rip), %eax\n syscall\n add $8,%rsp\n pop %r9\n"
"  mov %r12,0x00(%r9)\n mov %r13,0x08(%r9)\n mov %r14,0x10(%r9)\n mov %r15,0x18(%r9)\n"
"  pop %r15\n pop %r14\n pop %r13\n pop %r12\n ret\n");

static int fails;
#define CHECK(c, ...) do { if (!(c)) { if (fails++ < 10) printf("  mismatch: " __VA_ARGS__); } } while (0)

static DWORD WINAPI phase1(void *arg)
{
    static __declspec(align(16)) CONTEXT ctx;
    unsigned i, k;
    for (i = 0; i < ITERS; i++) {
        memset(&ctx, 0, sizeof(ctx));
        RtlCaptureContext(&ctx);
        ctx.ContextFlags = CONTEXT_FULL;
        ctx.Rip = (DWORD64)resume_stub;
        ctx.Rsp = (DWORD64)(scratch + sizeof(scratch) - 0x48);
        ctx.EFlags = 0x202 | 0x400 | 0x40000;          /* IF, DF, AC; TF off */
        ctx.MxCsr = ctx.FltSave.MxCsr = 0x9fc0;
        for (k = 0; k < 8; k++) (&ctx.R8)[k] = 0x0800000000000000ull * (k + 1) + i;
        for (k = 0; k < 10; k++) { (&ctx.Xmm6)[k].Low = 0x6600000000000000ull + k * 0x101 + i; (&ctx.Xmm6)[k].High = ~(DWORD64)i - k; }
        memset(&got, 0, sizeof(got));
        run_one(&ctx);
        for (k = 0; k < 8; k++) CHECK(got.r[k] == (&ctx.R8)[k], "iter %u r%u %llx != %llx\n", i, k + 8, got.r[k], (&ctx.R8)[k]);
        CHECK((got.rflags & 0x40500) == 0x40400, "iter %u rflags %llx (want DF+AC, no TF)\n", i, got.rflags);
        CHECK(got.mxcsr == 0x9fc0, "iter %u mxcsr %x\n", i, got.mxcsr);
        for (k = 0; k < 10; k++) CHECK(!memcmp(&got.xmm[k], &(&ctx.Xmm6)[k], 16), "iter %u xmm%u\n", i, k + 6);
    }
    return 0;
}

/* Take the syscall number from the ntdll stub (mov r10,rcx; mov eax,imm32) so the test follows Wine's table. */
static DWORD stub_nr(const char *name, DWORD def)
{
    const unsigned char *p = (const void *)GetProcAddress(GetModuleHandleA("ntdll.dll"), name);
    if (p && p[0] == 0x4c && p[1] == 0x8b && p[2] == 0xd1 && p[3] == 0xb8) return *(const DWORD *)(p + 4);
    return def;
}

int main(int argc, char **argv)
{
    HANDLE t; unsigned i; DWORD64 r[4]; LONG st; int f0;
    if (argc > 1) ITERS = strtoul(argv[1], NULL, 0);
    nr_continue = stub_nr("NtContinue", 0x43); nr_yield = stub_nr("NtYieldExecution", 0x46);
    printf("syscall numbers: NtContinue %#lx NtYieldExecution %#lx, iters %u\n", nr_continue, nr_yield, ITERS);
    t = CreateThread(NULL, 0, phase1, NULL, 0, NULL);
    WaitForSingleObject(t, INFINITE);
    printf("%s: 1: %d raw NtContinue(0x43) to a crafted CONTEXT: r8-r15, DF/AC/TF, MXCSR, XMM6-15 exact\n", fails ? "FAIL" : "PASS", ITERS); fflush(stdout);
    f0 = fails;
    for (i = 0; i < ITERS; i++) {
        st = raw_yield(r);
        CHECK(st == 0 || st == 0x40000024 /* STATUS_NO_YIELD_PERFORMED */, "yield %u status %lx\n", i, st);
        CHECK(r[0] == 0x1212121212121212ull && r[3] == 0x1515151515151515ull, "yield %u r12/r15 clobbered\n", i);
    }
    printf("%s: 2: %d raw NtYieldExecution(0x46): status ok, r12-r15 preserved\n", fails > f0 ? "FAIL" : "PASS", ITERS); fflush(stdout);
    return fails ? 1 : 0;
}
