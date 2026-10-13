// SPDX-License-Identifier: MIT
//
// Regression test: a page that holds code and is written all the time keeps working, and stops faulting.
//
// On x86 a store to a page that also holds code costs nothing special unless it hits an instruction the CPU has
// already fetched, and a store to an instruction that is executed later always takes effect (Intel SDM Vol. 3A
// 9.1.3/11.6). Programs rely on both: trampoline pools and JIT heaps keep data next to code, hook installers rewrite
// instructions in place, and JITs write code through one mapping of a memfd and run it through another.
//
// Under FEX with SMCChecks=mtrack the host page of translated guest code is write-protected, so every store to such a
// page is a SIGSEGV, an invalidation and a re-translation. Patch 0002 counts those faults per page (and per mirror of a
// shared mapping); after FEX_SMCHOTPAGEFAULTS of them (default 32) the page is left writable and the JIT verifies the
// bytes of each instruction it translated from the page before running it.
//
// Three loops on freshly mapped pages, each iteration checked for the value the code must return:
//   A. data next to code:  store to a word on the page, call `mov eax, 7; ret` on the same page;
//   B. code rewritten:     call a function on the page that stores its argument into the immediate of its own next
//                          instruction (must return the argument), then patch the first function's immediate from
//                          outside and call it (must return the patched value);
//   C. two mappings:       write `mov eax, i; ret` through the writable mapping of a memfd, call it through the
//                          executable mapping.
// Checks:
//   1-3. every iteration of A, B and C returns the right value (this is all a real x86-64 Linux can show);
//   4.   under FEX: the SMC write faults FEX counted for the whole run stay within the hot-page budget. FEX publishes
//        the count per thread in /dev/shm/fex-<pid>-stats (AccumulatedSMCCount, a stock FEX_PROFILESTATS counter); the
//        budget is FEX_SMCHOTPAGEFAULTS faults for each of the three pages written plus a margin, against the 45000
//        stores the loops make.
// The test re-execs itself with FEX_PROFILESTATS=1 so the counter exists. FEX is recognised by its CPUID hypervisor leaf
// ("FEXIFEXIEMU"); when that says FEX but the counter cannot be read, check 4 fails rather than being skipped.
//
// Expected: passes on x86-64 Linux (checks 1-3; check 4 is reported as not applicable) and on eac-2610. Check 4 fails
// without patch 0002, which is also what FEX_SMCHOTPAGEFAULTS=0 gives on eac-2610: one fault per store.
// Build: eac-tests/smc-hot-page/build.sh [clang]   (x86-64 binary, run it under FEX)
// Run:   ./smc_hot_page_test   (exit status = number of failed checks)

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef unsigned char u8;

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
#define sc4(n, a, b, c, d) sc6(n, (i64)(a), (i64)(b), (i64)(c), (i64)(d), 0, 0)
enum { SYS_write = 1, SYS_open = 2, SYS_close = 3, SYS_mmap = 9, SYS_pread64 = 17, SYS_getpid = 39, SYS_execve = 59,
       SYS_ftruncate = 77, SYS_clock_gettime = 228, SYS_exit_group = 231, SYS_memfd_create = 319 };
enum { PROT_READ = 1, PROT_WRITE = 2, PROT_EXEC = 4, MAP_SHARED = 1, MAP_PRIVATE = 2, MAP_ANONYMOUS = 0x20 };
enum { CLOCK_MONOTONIC = 1 };

enum { LoopA = 20000, LoopB = 5000, LoopC = 15000, Stores = LoopA + 2 * LoopB + LoopC };
enum { DefaultHotPageFaults = 32, PagesWritten = 3, Margin = 32 };

struct timespec { i64 sec, nsec; };

static u64 slen(const char* s) { u64 n = 0; while (s[n]) n++; return n; }
static void out(const char* s) { sc3(SYS_write, 1, (i64)s, slen(s)); }
static void out_dec(i64 v) {
  char b[24]; int i = 23; b[i] = 0; int neg = v < 0; u64 u = neg ? -v : v;
  do { b[--i] = '0' + u % 10; u /= 10; } while (u);
  if (neg) b[--i] = '-';
  out(b + i);
}
static int starts(const char* s, const char* prefix) {
  while (*prefix) { if (*s++ != *prefix++) return 0; }
  return 1;
}
static i64 now_ms(void) {
  struct timespec ts = {0, 0};
  sc2(SYS_clock_gettime, CLOCK_MONOTONIC, &ts);
  return ts.sec * 1000 + ts.nsec / 1000000;
}

static int failures;
static void check(int ok, const char* what) { out(ok ? "  ok   " : "  FAIL "); out(what); out("\n"); if (!ok) failures++; }

static void put32(volatile u8* p, u32 v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }

// FEX answers CPUID leaf 0x40000000 with "FEXIFEXIEMU" in ebx:ecx:edx.
static int under_fex(void) {
  u32 a = 0x40000000, b = 0, c = 0, d = 0;
  __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d));
  return b == 0x49584546 /* FEXI */ && c == 0x49584546 /* FEXI */ && (d & 0xffffff) == 0x554d45 /* EMU */;
}

// Sum of AccumulatedSMCCount over the thread slots of /dev/shm/fex-<pid>-stats, or -1 when the file is not there.
// Layout (FEXCore/include/FEXCore/Utils/SHMStats.h): a 64-byte ThreadStatsHeader with the offset of the first slot at
// byte 52 (Head) and the slot size at byte 2; each slot starts with the offset of the next one (0 ends the list) and
// keeps AccumulatedSMCCount at byte 32.
static i64 smc_faults(void) {
  char path[64] = "/dev/shm/fex-";
  char digits[24]; int n = 0; u64 len = slen(path);
  for (i64 pid = sc1(SYS_getpid, 0); pid; pid /= 10) digits[n++] = '0' + pid % 10;
  while (n) path[len++] = digits[--n];
  for (const char* s = "-stats"; *s; ++s) path[len++] = *s;
  path[len] = 0;

  i64 fd = sc3(SYS_open, path, 0 /* O_RDONLY */, 0);
  if (fd < 0) return -1;
  static u8 buf[1 << 16];
  i64 got = sc4(SYS_pread64, fd, buf, sizeof(buf), 0);
  sc1(SYS_close, fd);
  if (got < 64) return -1;

  i64 total = 0;
  u32 slot = *(u32*)(buf + 52);
  for (int guard = 0; slot && slot + 40 <= (u64)got && guard < 4096; ++guard) {
    total += *(u64*)(buf + slot + 32);
    slot = *(u32*)(buf + slot);
  }
  return total;
}

static int call0(volatile u8* code) { return ((int (*)(void))code)(); }
static int call1(volatile u8* code, int arg) { return ((int (*)(int))code)(arg); }

static i64 HotPageFaults = DefaultHotPageFaults;

__attribute__((noreturn)) static void run(void) {
  const int fex = under_fex();
  const i64 before = smc_faults();
  i64 t0 = now_ms();

  // A and B share one anonymous RWX page: `mov eax, 7; ret` at 0, the self-rewriting function at 16, data at 0x800.
  volatile u8* page = (volatile u8*)sc6(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if ((i64)page < 0 && (i64)page > -4096) { check(0, "mmap"); goto done; }
  static const u8 Get[6] = {0xb8, 7, 0, 0, 0, 0xc3};         // mov eax, 7; ret
  static const u8 Self[12] = {0x89, 0x3d, 1, 0, 0, 0,        // mov [rip + 1], edi   (the immediate of the next mov)
                              0xb8, 0, 0, 0, 0, 0xc3};       // mov eax, imm32; ret
  for (int i = 0; i < 6; i++) page[i] = Get[i];
  for (int i = 0; i < 12; i++) page[16 + i] = Self[i];

  int bad = 0;
  for (int i = 0; i < LoopA; i++) {
    put32(page + 0x800, i);
    bad += call0(page) != 7;
  }
  check(bad == 0, "A: code next to data that is stored to on every iteration keeps returning its value");
  i64 t1 = now_ms();
  const i64 afterA = smc_faults();

  bad = 0;
  for (int i = 0; i < LoopB; i++) {
    bad += call1(page + 16, i + 1) != i + 1;
    put32(page + 1, i ^ 0x5a5a);
    bad += call0(page) != (i ^ 0x5a5a);
  }
  check(bad == 0, "B: code rewritten by itself and from outside runs the new instruction every time");
  i64 t2 = now_ms();
  const i64 afterB = smc_faults();

  // C: one memfd page mapped twice, written through `wr` and executed through `ex`.
  {
    i64 fd = sc2(SYS_memfd_create, "smc-hot-page", 0);
    volatile u8* wr = (volatile u8*)-1;
    volatile u8* ex = (volatile u8*)-1;
    if (fd >= 0 && sc2(SYS_ftruncate, fd, 4096) == 0) {
      wr = (volatile u8*)sc6(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
      ex = (volatile u8*)sc6(SYS_mmap, 0, 4096, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
    }
    if ((i64)wr < 0 && (i64)wr > -4096) wr = (volatile u8*)-1;
    if ((i64)ex < 0 && (i64)ex > -4096) ex = (volatile u8*)-1;
    if (wr == (volatile u8*)-1 || ex == (volatile u8*)-1) {
      check(0, "C: memfd mapped writable and executable");
    } else {
      for (int i = 0; i < 6; i++) wr[i] = Get[i];
      bad = 0;
      for (int i = 0; i < LoopC; i++) {
        put32(wr + 1, i);
        bad += call0(ex) != i;
      }
      check(bad == 0, "C: code written through one mapping runs through the other every time");
    }
  }
  i64 t3 = now_ms();

  out("  time: A "); out_dec(t1 - t0); out(" ms, B "); out_dec(t2 - t1); out(" ms, C "); out_dec(t3 - t2); out(" ms\n");

  {
    const i64 after = smc_faults();
    const i64 budget = HotPageFaults * PagesWritten + Margin;
    if (before < 0 || after < 0 || afterA < 0 || afterB < 0) {
      if (fex) {
        check(0, "FEX: the SMC fault counter is readable (/dev/shm/fex-<pid>-stats, FEX_PROFILESTATS=1)");
      } else {
        out("  n/a  not FEX: no SMC fault counter, only the results are checked\n");
      }
    } else {
      // Per case: each loop may fault at most the hot-page threshold once per page it writes (A: 1 page, B: the same
      // page again, C: one memfd page), plus the margin; without hot-page handling every case faults ~once per store.
      const i64 Case[3] = {afterA - before, afterB - afterA, after - afterB};
      const char* Name[3] = {"A", "B", "C"};
      for (int c = 0; c < 3; c++) {
        out("  SMC write faults in "); out(Name[c]); out(": "); out_dec(Case[c]); out(", budget ");
        out_dec(HotPageFaults + Margin); out("\n");
      }
      check(Case[0] <= HotPageFaults + Margin, "FEX: A stops faulting once its page is hot");
      check(Case[1] <= HotPageFaults + Margin, "FEX: B stops faulting once its page is hot");
      check(Case[2] <= HotPageFaults + Margin, "FEX: C stops faulting once its page is hot");
      out("  SMC write faults: "); out_dec(after - before); out(" for "); out_dec(Stores); out(" stores, budget ");
      out_dec(budget); out("\n");
      check(after - before > 0, "FEX: the pages were write-protected at first (SMCChecks=mtrack counted faults)");
      check(after - before <= budget, "FEX: the faults stop once the pages are hot");
    }
  }

done:
  out(failures ? "RESULT: FAIL\n" : "RESULT: PASS\n");
  sc1(SYS_exit_group, failures);
  __builtin_unreachable();
}

// Entry: re-exec with FEX_PROFILESTATS=1 so that FEX publishes its counters, and pick up FEX_SMCHOTPAGEFAULTS.
static char envbuf[160][256];
static char* newenv[164];
__attribute__((used)) static void entry_c(u64* sp) {
  u64 argc = sp[0]; char** argv = (char**)(sp + 1); char** envp = argv + argc + 1;
  int have = 0, n = 0, fits = 1;
  for (char** e = envp; *e; ++e) {
    if (starts(*e, "FEX_PROFILESTATS=")) have = 1;
    if (starts(*e, "FEX_SMCHOTPAGEFAULTS=")) {
      HotPageFaults = 0;
      for (const char* p = *e + 21; *p >= '0' && *p <= '9'; ++p) HotPageFaults = HotPageFaults * 10 + (*p - '0');
    }
    if (n >= 158 || slen(*e) >= sizeof(envbuf[0])) { fits = 0; continue; }
    u64 i = 0;
    for (; (*e)[i]; ++i) envbuf[n][i] = (*e)[i];
    envbuf[n][i] = 0; newenv[n] = envbuf[n]; ++n;
  }
  if (!have && fits) {
    static char Stats[] = "FEX_PROFILESTATS=1";
    newenv[n++] = Stats;
    newenv[n] = 0;
    sc3(SYS_execve, (i64)"/proc/self/exe", (i64)argv, (i64)newenv);
    // execve returned: carry on, check 4 reports what this environment supports
  }
  run();
}
__attribute__((naked, used)) void _start(void) { __asm__ volatile("mov %rsp, %rdi\n and $-16, %rsp\n call entry_c\n"); }
