// DIV/IDIV throughput loops (register divisors), for FEX before/after timing.
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec * 1e-9; }
int main(int argc, char** argv) {
  long n = argc > 1 ? atol(argv[1]) : 100000000;
  uint64_t acc = 1;
  double t0 = now();
  for (long i = 0; i < n; i++) { uint32_t q, r; __asm__ volatile("div %4" : "=a"(q), "=d"(r) : "a"((uint32_t)(acc * 2654435761u)), "d"(0), "r"((uint32_t)(i | 3))); acc += q ^ r; }
  double t1 = now();
  for (long i = 0; i < n; i++) { uint64_t q, r; __asm__ volatile("div %4" : "=a"(q), "=d"(r) : "a"(acc * 0x9e3779b97f4a7c15ull), "d"(0ull), "r"((uint64_t)(i | 3))); acc += q ^ r; }
  double t2 = now();
  for (long i = 0; i < n; i++) { int64_t q, r; __asm__ volatile("cqo; idiv %3" : "=a"(q), "=&d"(r) : "a"((int64_t)(acc * 0x9e3779b97f4a7c15ull)), "r"((int64_t)(i | 3)) ); acc += q ^ r; }
  double t3 = now();
  for (long i = 0; i < n; i++) { int32_t q, r; __asm__ volatile("cdq; idiv %3" : "=a"(q), "=&d"(r) : "a"((int32_t)(acc * 2654435761u)), "r"((int32_t)(i | 3))); acc += q ^ r; }
  double t4 = now();
  printf("div32 %.2f ns  div64 %.2f ns  idiv64 %.2f ns  idiv32 %.2f ns  (acc %llx)\n", (t1 - t0) / n * 1e9, (t2 - t1) / n * 1e9,
         (t3 - t2) / n * 1e9, (t4 - t3) / n * 1e9, (unsigned long long)acc);
  return 0;
}
