/*
  tests for system calls that store into a page of executed code (read, pread, recv).
  The kernel's write raises no SIGSEGV, so the page's write protection has to be handled around the system call.
*/

#include <cstdint>
#include <cstring>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <catch2/catch_test_macros.hpp>

namespace {
constexpr size_t PageSize = 4096;

// mov eax, imm32; ret
void EmitCode(char* Code, uint32_t Value) {
  Code[0] = 0xB8;
  memcpy(Code + 1, &Value, sizeof(Value));
  Code[5] = 0xC3;
}

int Call(char* Code) {
  return ((int (*)())Code)();
}

char* MapRWX(size_t Pages) {
  return (char*)mmap(nullptr, Pages * PageSize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
}

int FileWith(const char* Data, size_t Size) {
  int fd = memfd_create("smc-kernel-write", 0);
  REQUIRE(write(fd, Data, Size) == (ssize_t)Size);
  REQUIRE(lseek(fd, 0, SEEK_SET) == 0);
  return fd;
}
} // namespace

TEST_CASE("SMC: read") {
  auto Code = MapRWX(1);
  EmitCode(Code, 1);
  REQUIRE(Call(Code) == 1);

  char New[6];
  EmitCode(New, 2);
  int fd = FileWith(New, sizeof(New));
  CHECK(read(fd, Code, sizeof(New)) == sizeof(New));
  CHECK(Call(Code) == 2);

  // An ordinary store is still tracked afterwards.
  Code[1] = 3;
  CHECK(Call(Code) == 3);
  close(fd);
}

TEST_CASE("SMC: pread") {
  auto Code = MapRWX(1);
  EmitCode(Code, 1);
  REQUIRE(Call(Code) == 1);

  char New[6];
  EmitCode(New, 2);
  int fd = FileWith(New, sizeof(New));
  CHECK(pread(fd, Code, sizeof(New), 0) == sizeof(New));
  CHECK(Call(Code) == 2);
  close(fd);
}

TEST_CASE("SMC: recv") {
  auto Code = MapRWX(1);
  EmitCode(Code, 1);
  REQUIRE(Call(Code) == 1);

  char New[6];
  EmitCode(New, 2);
  int fds[2];
  REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
  REQUIRE(write(fds[1], New, sizeof(New)) == sizeof(New));
  CHECK(recv(fds[0], Code, sizeof(New), 0) == sizeof(New));
  CHECK(Call(Code) == 2);
  close(fds[0]);
  close(fds[1]);
}

TEST_CASE("SMC: read across pages") {
  // Starts in a data page and covers two pages of executed code.
  auto Mem = MapRWX(3);
  EmitCode(Mem + PageSize, 1);
  EmitCode(Mem + 2 * PageSize, 2);
  REQUIRE(Call(Mem + PageSize) == 1);
  REQUIRE(Call(Mem + 2 * PageSize) == 2);

  static char New[PageSize + PageSize / 2 + 6];
  EmitCode(New + PageSize / 2, 11);
  EmitCode(New + PageSize / 2 + PageSize, 12);
  int fd = FileWith(New, sizeof(New));
  CHECK(read(fd, Mem + PageSize / 2, sizeof(New)) == sizeof(New));
  CHECK(Call(Mem + PageSize) == 11);
  CHECK(Call(Mem + 2 * PageSize) == 12);
  close(fd);
}

TEST_CASE("SMC: short read ending at a code page") {
  // The pipe runs dry exactly where the executed page starts: the bytes that are there, without waiting for more.
  auto Mem = MapRWX(2);
  EmitCode(Mem + PageSize, 1);
  REQUIRE(Call(Mem + PageSize) == 1);

  static char Data[PageSize / 2];
  int fds[2];
  REQUIRE(pipe(fds) == 0);
  REQUIRE(write(fds[1], Data, sizeof(Data)) == sizeof(Data));
  CHECK(read(fds[0], Mem + PageSize / 2, PageSize) == sizeof(Data));
  CHECK(Call(Mem + PageSize) == 1);
  close(fds[0]);
  close(fds[1]);
}

TEST_CASE("SMC: read into read-only code") {
  auto Code = MapRWX(1);
  EmitCode(Code, 1);
  REQUIRE(mprotect(Code, PageSize, PROT_READ | PROT_EXEC) == 0);
  REQUIRE(Call(Code) == 1);

  char New[6];
  EmitCode(New, 2);
  int fd = FileWith(New, sizeof(New));
  CHECK(read(fd, Code, sizeof(New)) == -1);
  CHECK(errno == EFAULT);
  CHECK(Call(Code) == 1);
  close(fd);
}
