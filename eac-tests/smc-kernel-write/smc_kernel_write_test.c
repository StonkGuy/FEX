// SPDX-License-Identifier: MIT
//
// Regression test: a system call that fills a buffer can store into a page of executed code, and the new code runs.
//
// Linux rule: read, pread64 and recv copy into any memory the caller may write. A writable+executable page is
// ordinary writable memory to the kernel, whether code on it has been executed or not; the call returns the full
// count and the processor runs the new bytes afterwards. Language runtimes load code this way (Chez Scheme reads
// code objects from its boot files straight into recycled code segments, upstream FEX issue #5874).
//
// Under FEX with SMCChecks=mtrack the host page of translated guest code is write-protected and a guest store is
// noticed through SIGSEGV. A store by the host kernel raises no signal: the system call fails with EFAULT, or returns
// a short count that ends at the protected page.
//
// Every case uses fresh mappings. `code(v)` is `mov $v, %eax; ret`; a page is "executed" by calling it once, which
// makes FEX translate and write-protect it.
// Cases:
//   read-file, pread-file      6 bytes from a memfd onto an executed page
//   read-pipe, recv-stream     the same from a pipe and from an AF_UNIX stream socket
//   recv-dgram                 the same from an AF_UNIX datagram socket
//   *-straddle                 0x2000 bytes starting in the middle of a data page and covering two executed pages
//                              (file read, pread, pipe, stream socket)
//   read-mirror                a shared memfd mapped twice; code runs from one view, read() fills the other view
//   store-after-read           after read-file, an ordinary guest store to the page is still picked up
//   pipe-short-no-block        the pipe holds exactly the bytes up to the executed page: read returns them and does
//                              not wait for more (the code on the page is unchanged)
//   file-eof-at-page           the same with a file that ends there
//   efault-readonly            read onto an executed page the guest mapped without PROT_WRITE: EFAULT, code unchanged
//   efault-unmapped            read into an unmapped page: EFAULT
//   short-then-unmapped        read that starts in a mapped page and runs into an unmapped one: the mapped part
//
// Expected: passes on x86-64 Linux and with the change. Before it every case above "store-after-read" fails
// (EFAULT or a short count); the rest pass.
// Build: eac-tests/smc-kernel-write/build.sh [clang]   (x86-64 binary, run it under FEX)
// Run:   ./smc_kernel_write_test   (exit status = number of failed checks)

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
#define sc4(n, a, b, c, d) sc6(n, (i64)(a), (i64)(b), (i64)(c), (i64)(d), 0, 0)
enum {
  SYS_read = 0, SYS_write = 1, SYS_close = 3, SYS_lseek = 8, SYS_mmap = 9, SYS_mprotect = 10, SYS_munmap = 11, SYS_pread64 = 17, SYS_alarm = 37,
  SYS_recvfrom = 45, SYS_socketpair = 53, SYS_exit_group = 231, SYS_pipe2 = 293, SYS_memfd_create = 319,
};
enum { PROT_READ = 1, PROT_WRITE = 2, PROT_EXEC = 4, MAP_SHARED = 1, MAP_PRIVATE = 2, MAP_FIXED = 0x10, MAP_ANONYMOUS = 0x20 };
enum { AF_UNIX = 1, SOCK_STREAM = 1, SOCK_DGRAM = 2, EFAULT = 14, PAGE = 4096, TIMEOUT_SECONDS = 30 };
enum { RWX = PROT_READ | PROT_WRITE | PROT_EXEC };

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

// mov $v, %eax; ret
static void code(u8* p, int v) {
  p[0] = 0xb8; p[1] = v; p[2] = v >> 8; p[3] = v >> 16; p[4] = v >> 24; p[5] = 0xc3;
}
static int call(u8* p) { return ((int (*)(void))p)(); }
static u8* map(u64 pages, int prot) {
  return (u8*)sc6(SYS_mmap, 0, pages * PAGE, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

static u8 payload[2 * PAGE];

// The sources hand out `len` bytes of `payload`.
enum Source { FILE_READ, FILE_PREAD, PIPE, STREAM, DGRAM };
static i64 fill_from(enum Source src, u8* dst, u64 want, u64 have) {
  int fds[2] = {-1, -1};
  i64 ret;
  switch (src) {
  case FILE_READ:
  case FILE_PREAD:
    fds[0] = sc2(SYS_memfd_create, "smc-kernel-write", 0);
    sc3(SYS_write, fds[0], payload, have);
    if (src == FILE_READ) {
      sc3(SYS_lseek, fds[0], 0, 0);
      ret = sc3(SYS_read, fds[0], dst, want);
    } else {
      ret = sc4(SYS_pread64, fds[0], dst, want, 0);
    }
    break;
  case PIPE:
    sc2(SYS_pipe2, fds, 0);
    sc3(SYS_write, fds[1], payload, have);
    ret = sc3(SYS_read, fds[0], dst, want);
    break;
  default:
    sc4(SYS_socketpair, AF_UNIX, src == STREAM ? SOCK_STREAM : SOCK_DGRAM, 0, fds);
    sc3(SYS_write, fds[1], payload, have);
    ret = sc6(SYS_recvfrom, fds[0], (i64)dst, want, 0, 0, 0);
    break;
  }
  sc1(SYS_close, fds[0]);
  if (fds[1] >= 0) sc1(SYS_close, fds[1]);
  return ret;
}

// 6 bytes onto an executed page.
static u8* simple(const char* name, enum Source src) {
  begin(name);
  u8* p = map(1, RWX);
  code(p, 1);
  check("first call", call(p), 1);
  code(payload, 2);
  check("count", fill_from(src, p, 6, 6), 6);
  check("second call", call(p), 2);
  end();
  return p;
}

// 0x2000 bytes from the middle of a data page over two executed pages.
static void straddle(const char* name, enum Source src) {
  begin(name);
  u8* m = map(4, RWX);
  code(m + PAGE, 1);
  code(m + 2 * PAGE, 2);
  code(m + 3 * PAGE, 3);
  check("page 1", call(m + PAGE), 1);
  check("page 2", call(m + 2 * PAGE), 2);
  check("page 3", call(m + 3 * PAGE), 3);
  for (unsigned i = 0; i < sizeof(payload); i++) payload[i] = 0xcc;
  code(payload + 0x800, 11);
  code(payload + 0x1800, 12);
  check("count", fill_from(src, m + 0x800, 0x2000, 0x2000), 0x2000);
  check("page 1 after", call(m + PAGE), 11);
  check("page 2 after", call(m + 2 * PAGE), 12);
  check("page 3 after", call(m + 3 * PAGE), 3);
  check("last byte", m[0x27ff], 0xcc);
  end();
}

// The source runs dry exactly at the boundary of an executed page.
static void short_at_page(const char* name, enum Source src) {
  begin(name);
  u8* m = map(2, RWX);
  code(m + PAGE, 1);
  check("first call", call(m + PAGE), 1);
  for (unsigned i = 0; i < sizeof(payload); i++) payload[i] = 0xcc;
  check("count", fill_from(src, m + 0x800, 0x1000, 0x800), 0x800);
  check("second call", call(m + PAGE), 1);
  end();
}

void _start_c(void) {
  sc1(SYS_alarm, TIMEOUT_SECONDS);

  u8* p = simple("read-file", FILE_READ);
  simple("pread-file", FILE_PREAD);
  simple("read-pipe", PIPE);
  simple("recv-stream", STREAM);
  simple("recv-dgram", DGRAM);
  straddle("read-file-straddle", FILE_READ);
  straddle("pread-file-straddle", FILE_PREAD);
  straddle("read-pipe-straddle", PIPE);
  straddle("recv-stream-straddle", STREAM);

  {
    begin("read-mirror");
    int fd = sc2(SYS_memfd_create, "smc-kernel-write-mirror", 0);
    sc3(SYS_write, fd, payload, PAGE);
    u8* x = (u8*)sc6(SYS_mmap, 0, PAGE, RWX, MAP_SHARED, fd, 0);
    u8* w = (u8*)sc6(SYS_mmap, 0, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    code(w, 1);
    check("first call", call(x), 1);
    code(payload, 2);
    check("count", fill_from(FILE_READ, w, 6, 6), 6);
    check("second call", call(x), 2);
    sc1(SYS_close, fd);
    end();
  }

  begin("store-after-read");
  check("before", call(p), 2);
  p[1] = 7;
  check("after", call(p), 7);
  end();

  short_at_page("pipe-short-no-block", PIPE);
  short_at_page("file-eof-at-page", FILE_READ);

  {
    begin("efault-readonly");
    u8* x = map(1, RWX);
    code(x, 1);
    sc3(SYS_mprotect, x, PAGE, PROT_READ | PROT_EXEC);
    check("first call", call(x), 1);
    code(payload, 2);
    check("count", fill_from(FILE_READ, x, 6, 6), -EFAULT);
    check("second call", call(x), 1);
    end();
  }

  {
    begin("efault-unmapped");
    u8* m = map(2, RWX);
    sc2(SYS_munmap, m + PAGE, PAGE);
    check("count", fill_from(FILE_READ, m + PAGE, 6, 6), -EFAULT);
    check("pread count", fill_from(FILE_PREAD, m + PAGE, 6, 6), -EFAULT);
    check("recv count", fill_from(STREAM, m + PAGE, 6, 6), -EFAULT);
    end();

    begin("short-then-unmapped");
    check("count", fill_from(FILE_READ, m + 0x800, 0x1000, 0x1000), 0x800);
    check("pread count", fill_from(FILE_PREAD, m + 0x800, 0x1000, 0x1000), 0x800);
    end();
  }

  out(failures ? "RESULT: FAIL\n" : "RESULT: PASS\n");
  sc1(SYS_exit_group, failures);
  __builtin_unreachable();
}

__asm__(".globl _start\n_start:\n  andq $-16, %rsp\n  call _start_c\n  hlt\n");
