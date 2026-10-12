// SPDX-License-Identifier: MIT
//
// Regression test: x86-64 munmap of a range that starts below 4GB and ends above it.
//
// Linux rule (mm/mmap.c, do_vmi_munmap): the address must be page aligned, the length non-zero and, rounded up to a
// page, inside the task's address space. Everything mapped in the range goes away; pages that are not mapped are
// skipped and the call still returns 0. Nothing on x86-64 treats 4GB as a boundary.
// Chromium's PartitionAlloc unmaps such ranges and aborts when munmap fails (upstream FEX issue #5847:
// `munmap(0x10000, 0x1000ff000)` returned EOVERFLOW).
//
// Under FEX, 64-bit guests share the 32-bit address-space allocator for MAP_32BIT mappings. Every munmap that started
// below 4GB went through that allocator, which rejects a range that does not fit in 32 bits (EOVERFLOW) and a length
// that is not page aligned (EINVAL), and unmaps one page per host system call.
//
// Cases (mappings are placed with MAP_FIXED_NOREPLACE; "gone" is checked with mincore = ENOMEM):
//   cross-4g          16 pages below 4GB and 16 above, one munmap over both
//   cross-4g-holes    one page at 0x90000000 and one at 0x140000000, munmap(0x80000000, 4GB)
//   low               a mapping below 4GB only
//   low-unaligned-len two pages below 4GB, munmap(addr, PAGE + 1) removes both
//   low-not-mapped    a hole below 4GB: 0
//   high              a mapping above 4GB only
//   map-32bit         a MAP_32BIT mapping, unmapped by a 4GB range starting at it; the same address can then be
//                     mapped again with MAP_32BIT, and 64 more MAP_32BIT mappings and unmappings succeed
//   einval            unaligned address, zero length
//
// Expected: passes on x86-64 Linux and with the change. Before it cross-4g, cross-4g-holes, low-unaligned-len and
// map-32bit fail.
// Build: eac-tests/munmap-4g/build.sh [clang]   (x86-64 binary, run it under FEX)
// Run:   ./munmap_4g_test   (exit status = number of failed checks)

typedef unsigned long u64;
typedef long i64;
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
enum { SYS_write = 1, SYS_mmap = 9, SYS_munmap = 11, SYS_mincore = 27, SYS_alarm = 37, SYS_exit_group = 231 };
enum { PROT_READ = 1, PROT_WRITE = 2, MAP_PRIVATE = 2, MAP_ANONYMOUS = 0x20, MAP_32BIT = 0x40, MAP_FIXED_NOREPLACE = 0x100000 };
enum { EINVAL = 22, ENOMEM = 12, PAGE = 4096, TIMEOUT_SECONDS = 30 };
#define GB4 0x100000000UL

static u64 slen(const char* s) { u64 n = 0; while (s[n]) n++; return n; }
static void out(const char* s) { sc3(SYS_write, 1, (i64)s, slen(s)); }
static void out_dec(i64 v) {
  char b[24]; int i = 23; b[i] = 0; int neg = v < 0; u64 u = neg ? -v : v;
  do { b[--i] = '0' + u % 10; u /= 10; } while (u);
  if (neg) b[--i] = '-';
  out(b + i);
}

static int failures;
static const char* current;
static int case_failed;

static void check(const char* what, i64 got, i64 want) {
  if (got == want) return;
  if (!case_failed) { out("  FAIL "); out(current); out(":"); }
  out(" "); out(what); out(" = "); out_dec(got); out(", expected "); out_dec(want); out(";");
  case_failed = 1;
}
static void begin(const char* name) { current = name; case_failed = 0; }
static void end(void) {
  if (case_failed) { out("\n"); failures++; }
  else { out("  ok   "); out(current); out("\n"); }
}

static i64 map_at(u64 addr, u64 len, int flags) {
  return sc6(SYS_mmap, addr, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | flags, -1, 0);
}
// 1 when the page is mapped, 0 when it is not.
static int mapped(u64 addr) {
  u8 vec;
  return sc3(SYS_mincore, addr, PAGE, &vec) != -ENOMEM;
}

void _start_c(void) {
  sc1(SYS_alarm, TIMEOUT_SECONDS);

  begin("cross-4g");
  check("map low", map_at(GB4 - 16 * PAGE, 16 * PAGE, MAP_FIXED_NOREPLACE), GB4 - 16 * PAGE);
  check("map high", map_at(GB4, 16 * PAGE, MAP_FIXED_NOREPLACE), GB4);
  check("munmap", sc2(SYS_munmap, GB4 - 16 * PAGE, 32 * PAGE), 0);
  check("first low page mapped", mapped(GB4 - 16 * PAGE), 0);
  check("last low page mapped", mapped(GB4 - PAGE), 0);
  check("first high page mapped", mapped(GB4), 0);
  check("last high page mapped", mapped(GB4 + 15 * PAGE), 0);
  end();

  begin("cross-4g-holes");
  check("map low", map_at(0x90000000UL, PAGE, MAP_FIXED_NOREPLACE), 0x90000000UL);
  check("map high", map_at(0x140000000UL, PAGE, MAP_FIXED_NOREPLACE), 0x140000000UL);
  check("map above", map_at(0x180000000UL, PAGE, MAP_FIXED_NOREPLACE), 0x180000000UL);
  check("munmap", sc2(SYS_munmap, 0x80000000UL, GB4), 0);
  check("low page mapped", mapped(0x90000000UL), 0);
  check("high page mapped", mapped(0x140000000UL), 0);
  check("page past the range mapped", mapped(0x180000000UL), 1);
  check("munmap above", sc2(SYS_munmap, 0x180000000UL, PAGE), 0);
  end();

  begin("low");
  check("map", map_at(0x70000000UL, 4 * PAGE, MAP_FIXED_NOREPLACE), 0x70000000UL);
  check("munmap", sc2(SYS_munmap, 0x70000000UL + PAGE, 2 * PAGE), 0);
  check("page 0 mapped", mapped(0x70000000UL), 1);
  check("page 1 mapped", mapped(0x70000000UL + PAGE), 0);
  check("page 2 mapped", mapped(0x70000000UL + 2 * PAGE), 0);
  check("page 3 mapped", mapped(0x70000000UL + 3 * PAGE), 1);
  check("munmap rest", sc2(SYS_munmap, 0x70000000UL, 4 * PAGE), 0);
  check("page 3 mapped after", mapped(0x70000000UL + 3 * PAGE), 0);
  end();

  begin("low-unaligned-len");
  check("map", map_at(0x70000000UL, 2 * PAGE, MAP_FIXED_NOREPLACE), 0x70000000UL);
  check("munmap", sc2(SYS_munmap, 0x70000000UL, PAGE + 1), 0);
  check("page 0 mapped", mapped(0x70000000UL), 0);
  check("page 1 mapped", mapped(0x70000000UL + PAGE), 0);
  end();

  begin("low-not-mapped");
  check("munmap", sc2(SYS_munmap, 0x70000000UL, 16 * PAGE), 0);
  end();

  begin("high");
  check("map", map_at(0x200000000UL, 2 * PAGE, MAP_FIXED_NOREPLACE), 0x200000000UL);
  check("munmap", sc2(SYS_munmap, 0x200000000UL, 2 * PAGE), 0);
  check("page 0 mapped", mapped(0x200000000UL), 0);
  check("page 1 mapped", mapped(0x200000000UL + PAGE), 0);
  end();

  begin("map-32bit");
  {
    u64 p = map_at(0, 2 * PAGE, MAP_32BIT);
    check("below 4GB", p >= 0x10000 && p < GB4, 1);
    check("munmap", sc2(SYS_munmap, p, GB4), 0);
    check("page 0 mapped", mapped(p), 0);
    check("page 1 mapped", mapped(p + PAGE), 0);
    check("map again", map_at(p, 2 * PAGE, MAP_32BIT | MAP_FIXED_NOREPLACE), p);
    check("munmap again", sc2(SYS_munmap, p, 2 * PAGE), 0);
    int bad = 0;
    for (int i = 0; i < 64; i++) {
      u64 q = map_at(0, 2 * PAGE, MAP_32BIT);
      if (q >= GB4 || sc2(SYS_munmap, q, PAGE + 1) != 0 || mapped(q + PAGE)) bad++;
    }
    check("failed MAP_32BIT rounds", bad, 0);
  }
  end();

  // Boundaries of the 32-bit allocator's page range: a range ending exactly at 4GB, one whose unaligned length ends
  // one byte past it, and lengths whose end overflows.
  begin("end-at-4g");
  check("map low", map_at(GB4 - 2 * PAGE, 2 * PAGE, MAP_FIXED_NOREPLACE), GB4 - 2 * PAGE);
  check("map high", map_at(GB4, PAGE, MAP_FIXED_NOREPLACE), GB4);
  check("munmap", sc2(SYS_munmap, GB4 - 2 * PAGE, 2 * PAGE), 0);
  check("last low page mapped", mapped(GB4 - PAGE), 0);
  check("first high page mapped", mapped(GB4), 1);
  check("munmap high", sc2(SYS_munmap, GB4, PAGE), 0);
  end();

  begin("cross-4g-one-byte");
  check("map low", map_at(GB4 - PAGE, PAGE, MAP_FIXED_NOREPLACE), GB4 - PAGE);
  check("map high", map_at(GB4, 2 * PAGE, MAP_FIXED_NOREPLACE), GB4);
  check("munmap", sc2(SYS_munmap, GB4 - PAGE, PAGE + 1), 0);
  check("low page mapped", mapped(GB4 - PAGE), 0);
  check("first high page mapped", mapped(GB4), 0);
  check("second high page mapped", mapped(GB4 + PAGE), 1);
  check("munmap rest", sc2(SYS_munmap, GB4 + PAGE, PAGE), 0);
  end();

  begin("overflow");
  check("map", map_at(0x70000000UL, PAGE, MAP_FIXED_NOREPLACE), 0x70000000UL);
  check("end wraps", sc2(SYS_munmap, 0x70000000UL, -0x70000000L), -EINVAL);
  check("end past the address space", sc2(SYS_munmap, 0x70000000UL, 0x800000000000UL), -EINVAL);
  check("still mapped", mapped(0x70000000UL), 1);
  check("munmap", sc2(SYS_munmap, 0x70000000UL, PAGE), 0);
  end();

  begin("einval");
  check("map", map_at(0x70000000UL, PAGE, MAP_FIXED_NOREPLACE), 0x70000000UL);
  check("unaligned address", sc2(SYS_munmap, 0x70000001UL, PAGE), -EINVAL);
  check("zero length", sc2(SYS_munmap, 0x70000000UL, 0), -EINVAL);
  check("still mapped", mapped(0x70000000UL), 1);
  check("unaligned address above 4GB", sc2(SYS_munmap, 0x200000001UL, PAGE), -EINVAL);
  check("munmap", sc2(SYS_munmap, 0x70000000UL, PAGE), 0);
  end();

  out(failures ? "RESULT: FAIL\n" : "RESULT: PASS\n");
  sc1(SYS_exit_group, failures);
  __builtin_unreachable();
}

__asm__(".globl _start\n_start:\n  andq $-16, %rsp\n  call _start_c\n  hlt\n");
