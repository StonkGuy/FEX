#include <catch2/catch_test_macros.hpp>

#include <cerrno>
#include <cstdint>
#include <sys/mman.h>

// x86-64 munmap takes a range that starts below 4GB and ends above it, and skips the pages that are not mapped.

namespace {
constexpr size_t PageSize = 4096;
constexpr uintptr_t FourGB = 0x1'0000'0000ULL;

void* MapAt(uintptr_t Addr, size_t Size, int Flags = MAP_FIXED_NOREPLACE) {
  return mmap(reinterpret_cast<void*>(Addr), Size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | Flags, -1, 0);
}

bool IsMapped(uintptr_t Addr) {
  unsigned char Vec {};
  return mincore(reinterpret_cast<void*>(Addr), PageSize, &Vec) == 0 || errno != ENOMEM;
}
} // namespace

TEST_CASE("munmap: range crossing 4GB") {
  const uintptr_t Low = FourGB - 16 * PageSize;
  REQUIRE(MapAt(Low, 16 * PageSize) == reinterpret_cast<void*>(Low));
  REQUIRE(MapAt(FourGB, 16 * PageSize) == reinterpret_cast<void*>(FourGB));

  CHECK(munmap(reinterpret_cast<void*>(Low), 32 * PageSize) == 0);
  CHECK(!IsMapped(Low));
  CHECK(!IsMapped(FourGB - PageSize));
  CHECK(!IsMapped(FourGB));
  CHECK(!IsMapped(FourGB + 15 * PageSize));
}

TEST_CASE("munmap: 4GB range with holes") {
  REQUIRE(MapAt(0x9000'0000ULL, PageSize) == reinterpret_cast<void*>(0x9000'0000ULL));
  REQUIRE(MapAt(0x1'4000'0000ULL, PageSize) == reinterpret_cast<void*>(0x1'4000'0000ULL));

  CHECK(munmap(reinterpret_cast<void*>(0x8000'0000ULL), FourGB) == 0);
  CHECK(!IsMapped(0x9000'0000ULL));
  CHECK(!IsMapped(0x1'4000'0000ULL));
}

TEST_CASE("munmap: unaligned length below 4GB") {
  REQUIRE(MapAt(0x7000'0000ULL, 2 * PageSize) == reinterpret_cast<void*>(0x7000'0000ULL));

  CHECK(munmap(reinterpret_cast<void*>(0x7000'0000ULL), PageSize + 1) == 0);
  CHECK(!IsMapped(0x7000'0000ULL));
  CHECK(!IsMapped(0x7000'0000ULL + PageSize));
}

TEST_CASE("munmap: MAP_32BIT mapping can be mapped again") {
  auto Ptr = mmap(nullptr, 2 * PageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
  REQUIRE(Ptr != MAP_FAILED);
  const auto Addr = reinterpret_cast<uintptr_t>(Ptr);
  REQUIRE(Addr < FourGB);

  CHECK(munmap(Ptr, 2 * PageSize) == 0);
  CHECK(!IsMapped(Addr));
  CHECK(MapAt(Addr, 2 * PageSize, MAP_32BIT | MAP_FIXED_NOREPLACE) == Ptr);
  CHECK(munmap(Ptr, 2 * PageSize) == 0);
}

TEST_CASE("munmap: invalid arguments") {
  REQUIRE(MapAt(0x7000'0000ULL, PageSize) == reinterpret_cast<void*>(0x7000'0000ULL));

  CHECK(munmap(reinterpret_cast<void*>(0x7000'0001ULL), PageSize) == -1);
  CHECK(errno == EINVAL);
  CHECK(munmap(reinterpret_cast<void*>(0x7000'0000ULL), 0) == -1);
  CHECK(errno == EINVAL);
  CHECK(IsMapped(0x7000'0000ULL));
  CHECK(munmap(reinterpret_cast<void*>(0x7000'0000ULL), PageSize) == 0);
}
