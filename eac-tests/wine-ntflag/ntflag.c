/* EFLAGS.NT (bit 14) under Wine: native x86-64 is the oracle, FEX must match it.
 * User mode can read and write NT, and anti-tamper code checks that it behaves as on hardware (THE FINALS and
 * ARC Raiders run under another translator only once its NT handling is exact).
 * 1: popfq sets NT, pushfq reads it back (main thread and a second thread).
 * 2: a raw `syscall` with an invalid number (eax = -1, as protection code issues) returns with NT in R11.
 * 3: an exception (ud2) reports the live NT in CONTEXT.EFlags, and the NT a vectored handler writes there is live
 *    after it continues (0->0, 0->1, 1->0, 1->1).
 * 4: iretq while NT=1 faults (#GP: IRET with RFLAGS.NT=1 in IA-32e mode) at the iretq, frame untouched, NT=1 in the
 *    exception context.
 * 5: iretq while NT=0 takes NT from the RFLAGS in its frame (NT 0 and 1).
 * 6: a child process can set NT too.
 * Each line PASS/FAIL; the exit code is the number of failed phases. Build: build.sh (mingw). */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define NT 0x4000ull

uint64_t nt_set_read(void);
void nt_raw_syscall(uint64_t *out);
uint64_t nt_ud2(uint64_t nt);
uint64_t nt_iret_fault(void);
uint64_t nt_iret_load(uint64_t frame_nt);
extern char nt_ud2_site[], nt_iret_fault_site[], nt_iret_fault_resume[];

__asm__(
/* popfq NT=1, pushfq -> rax; the caller's flags are restored */
".globl nt_set_read\nnt_set_read:\n"
"  pushfq\n pushfq\n orq $0x4000,(%rsp)\n popfq\n pushfq\n pop %rax\n popfq\n ret\n"
/* NT=1, raw syscall eax=-1: out[0] = R11, out[1] = RAX (status), out[2] = flags after the return */
".globl nt_raw_syscall\nnt_raw_syscall:\n"
"  push %rbx\n mov %rcx,%rbx\n pushfq\n pushfq\n orq $0x4000,(%rsp)\n popfq\n"
"  mov %rcx,%r10\n mov $-1,%eax\n syscall\n"
"  mov %r11,(%rbx)\n mov %rax,8(%rbx)\n pushfq\n pop %rax\n mov %rax,16(%rbx)\n popfq\n pop %rbx\n ret\n"
/* NT = rcx, ud2 (the handler skips it), returns the flags after the handler */
".globl nt_ud2\nnt_ud2:\n"
"  pushfq\n mov (%rsp),%rax\n and $~0x4000,%rax\n or %rcx,%rax\n push %rax\n popfq\n"
".globl nt_ud2_site\nnt_ud2_site:\n  ud2\n"
"  pushfq\n pop %rax\n popfq\n ret\n"
/* NT=1, iretq to nt_iret_fault_resume with RSP = rbx (where the caller's flags are saved); the handler of the
 * expected #GP moves there itself. Returns the flags at the resume point. */
".globl nt_iret_fault\nnt_iret_fault:\n"
"  push %rbx\n pushfq\n mov %rsp,%rbx\n pushfq\n orq $0x4000,(%rsp)\n popfq\n"
"  xor %eax,%eax\n mov %ss,%ax\n push %rax\n push %rbx\n pushfq\n xor %eax,%eax\n mov %cs,%ax\n push %rax\n"
"  lea nt_iret_fault_resume(%rip),%rax\n push %rax\n"
".globl nt_iret_fault_site\nnt_iret_fault_site:\n  iretq\n"
".globl nt_iret_fault_resume\nnt_iret_fault_resume:\n"
"  pushfq\n pop %rax\n mov %rbx,%rsp\n popfq\n pop %rbx\n ret\n"
/* NT=0, iretq whose frame RFLAGS has NT = rcx; returns the flags after it */
".globl nt_iret_load\nnt_iret_load:\n"
"  push %rbx\n pushfq\n mov %rsp,%rbx\n mov (%rsp),%rax\n and $~0x4000,%rax\n push %rax\n popfq\n or %rcx,%rax\n"
"  xor %edx,%edx\n mov %ss,%dx\n push %rdx\n push %rbx\n push %rax\n xor %edx,%edx\n mov %cs,%dx\n push %rdx\n"
"  lea 1f(%rip),%rdx\n push %rdx\n iretq\n"
"1:\n pushfq\n pop %rax\n mov %rbx,%rsp\n popfq\n pop %rbx\n ret\n");

static volatile LONG ud2_expect_in, ud2_out, ud2_seen_ok, ud2_count;
static volatile DWORD iret_code;
static volatile ULONG_PTR iret_info[2];
static volatile LONG iret_frame_ok, iret_nt_in_ctx, iret_count;

static LONG CALLBACK handler(EXCEPTION_POINTERS *e)
{
    CONTEXT *c = e->ContextRecord;
    if (c->Rip == (DWORD64)nt_ud2_site && e->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
        ud2_count++;
        ud2_seen_ok = ((c->EFlags & NT) != 0) == ud2_expect_in;
        c->EFlags = (c->EFlags & ~(DWORD)NT) | (ud2_out ? (DWORD)NT : 0);
        c->Rip += 2;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (c->Rip == (DWORD64)nt_iret_fault_site) {
        iret_count++;
        iret_code = e->ExceptionRecord->ExceptionCode;
        iret_info[0] = e->ExceptionRecord->NumberParameters > 0 ? e->ExceptionRecord->ExceptionInformation[0] : 0;
        iret_info[1] = e->ExceptionRecord->NumberParameters > 1 ? e->ExceptionRecord->ExceptionInformation[1] : 0;
        iret_frame_ok = c->Rsp == c->Rbx - 40 && *(DWORD64 *)c->Rsp == (DWORD64)nt_iret_fault_resume;
        iret_nt_in_ctx = (c->EFlags & NT) != 0;
        c->Rsp = c->Rbx;
        c->Rip = (DWORD64)nt_iret_fault_resume;
        c->EFlags &= ~(DWORD)NT;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static int phase1_one(void)
{
    int bad = 0;
    for (int i = 0; i < 1000; i++) bad += !(nt_set_read() & NT);
    return bad;
}

static DWORD WINAPI phase12_thread(void *arg)
{
    uint64_t r[3];
    int bad = phase1_one() << 16;
    for (int i = 0; i < 1000; i++) {
        nt_raw_syscall(r);
        bad += !(r[0] & NT);
    }
    (void)arg;
    return bad;
}

int main(int argc, char **argv)
{
    int failed = 0;
    setbuf(stdout, NULL);
    if (argc > 1 && !strcmp(argv[1], "child"))
        return phase1_one() != 0;

    /* 1 + 2 on this thread and on a second one */
    uint64_t r[3];
    int bad1 = phase1_one(), bad2 = 0;
    for (int i = 0; i < 1000; i++) {
        nt_raw_syscall(r);
        bad2 += !(r[0] & NT);
    }
    HANDLE t = CreateThread(NULL, 0, phase12_thread, NULL, 0, NULL);
    DWORD tb = 0;
    WaitForSingleObject(t, INFINITE);
    GetExitCodeThread(t, &tb);
    CloseHandle(t);
    bad1 += tb >> 16;
    bad2 += tb & 0xffff;
    printf("%s: 1: popfq NT=1 read back by pushfq, 2 threads x 1000: %d wrong\n", bad1 ? "FAIL" : "PASS", bad1);
    printf("%s: 2: raw syscall eax=-1 with NT=1, 2 threads x 1000: R11 without NT %d; last R11 %llx status %llx flags after %llx\n",
           bad2 ? "FAIL" : "PASS", bad2, (unsigned long long)r[0], (unsigned long long)r[1], (unsigned long long)r[2]);
    failed += !!bad1 + !!bad2;

    PVOID h = AddVectoredExceptionHandler(1, handler);
    if (!h) { printf("FAIL: no vectored handler\n"); return 99; }

    /* 3 */
    int bad3 = 0;
    for (int in = 0; in < 2; in++)
        for (int out = 0; out < 2; out++)
            for (int i = 0; i < 200; i++) {
                ud2_expect_in = in; ud2_out = out; ud2_seen_ok = 0;
                LONG before = ud2_count;
                uint64_t f = nt_ud2(in ? NT : 0);
                if (ud2_count != before + 1 || !ud2_seen_ok || ((f & NT) != 0) != out) {
                    if (bad3++ < 4) printf("  3: NT %d->%d: handled %ld, context NT ok %ld, flags after %llx\n", in, out,
                                           ud2_count - before, ud2_seen_ok, (unsigned long long)f);
                }
            }
    printf("%s: 3: ud2 exception context NT in/out (4 x 200): %d wrong\n", bad3 ? "FAIL" : "PASS", bad3);
    failed += !!bad3;

    /* 4 */
    uint64_t f4 = nt_iret_fault();
    int ok4 = iret_count == 1 && iret_frame_ok && iret_nt_in_ctx && !(f4 & NT);
    printf("%s: 4: iretq with NT=1: faults %ld, code %08lx info %llx %llx, frame untouched %ld, NT in context %ld, flags after %llx\n",
           ok4 ? "PASS" : "FAIL", iret_count, iret_code, (unsigned long long)iret_info[0], (unsigned long long)iret_info[1],
           iret_frame_ok, iret_nt_in_ctx, (unsigned long long)f4);
    failed += !ok4;

    /* 5 */
    int bad5 = 0;
    for (int nt = 0; nt < 2; nt++)
        for (int i = 0; i < 200; i++) {
            uint64_t f = nt_iret_load(nt ? NT : 0);
            if (((f & NT) != 0) != nt && bad5++ < 4) printf("  5: frame NT %d: flags after %llx\n", nt, (unsigned long long)f);
        }
    printf("%s: 5: iretq with NT=0 loads NT from its frame (2 x 200): %d wrong\n", bad5 ? "FAIL" : "PASS", bad5);
    failed += !!bad5;
    RemoveVectoredExceptionHandler(h);

    /* 6 */
    char path[MAX_PATH], cmd[2 * MAX_PATH + 16];
    GetModuleFileNameA(NULL, path, sizeof path);
    snprintf(cmd, sizeof cmd, "\"%s\" child", path);
    int bad6 = 0;
    for (int i = 0; i < 2; i++) {
        STARTUPINFOA si = {.cb = sizeof si};
        PROCESS_INFORMATION pi;
        DWORD rc = 2;
        if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) { bad6++; continue; }
        if (WaitForSingleObject(pi.hProcess, 60000) == WAIT_OBJECT_0) GetExitCodeProcess(pi.hProcess, &rc);
        bad6 += rc != 0;
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    printf("%s: 6: child processes set and read NT (2 children): %d failed\n", bad6 ? "FAIL" : "PASS", bad6);
    failed += !!bad6;
    printf("phases failed: %d\n", failed);
    return failed;
}
