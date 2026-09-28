#include "dobby.h"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <atomic>
#include <thread>
#include <vector>
#include <sys/mman.h>
#include <unistd.h>

static bool is_rw_without_exec(void *address) {
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps)
    return false;
  char line[4096], permissions[5] = {};
  unsigned long long start = 0, end = 0;
  bool found = false;
  while (fgets(line, sizeof(line), maps)) {
    if (sscanf(line, "%llx-%llx %4s", &start, &end, permissions) != 3)
      continue;
    auto target = reinterpret_cast<uintptr_t>(address);
    if (target >= start && target < end) {
      found = true;
      break;
    }
  }
  fclose(maps);
  return found && permissions[0] == 'r' && permissions[1] == 'w' && permissions[2] != 'x';
}

static bool verify_rw_mapping_remains_rw() {
  const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  auto *code = static_cast<uint8_t *>(mmap(nullptr, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  if (code == MAP_FAILED)
    return false;
  constexpr uint32_t body[] = {0x528000e0, 0xd65f03c0, 0xd503201f, 0xd503201f};
  memcpy(code, body, sizeof(body));
  dobby_dummy_func_t original = nullptr;
  const bool before = is_rw_without_exec(code);
  const int installed = DobbyHook(code, reinterpret_cast<dobby_dummy_func_t>(+[]() -> long { return 99; }), &original);
  const bool during = is_rw_without_exec(code);
  // The source is intentionally non-executable. A near trampoline resumes in
  // that RW mapping, so we must not invoke this original function pointer.
  const bool relocated = original != nullptr;
  const int destroyed = installed == RT_SUCCESS ? DobbyDestroy(code) : RT_FAILED;
  const bool after = is_rw_without_exec(code);
  munmap(code, page);
  printf("original-RW mapping: installed=%d destroy=%d permissions=%d/%d/%d result=%s\n", installed, destroyed, before,
         during, after,
         before && installed == RT_SUCCESS && during && relocated && destroyed == RT_SUCCESS && after ? "PASS"
                                                                                                      : "FAIL");
  return before && installed == RT_SUCCESS && during && relocated && destroyed == RT_SUCCESS && after;
}
#include <inttypes.h>

#if !defined(__aarch64__)
#error This fixture must run on native ARM64
#endif

extern "C" long review_x17(long);
extern "C" long review_literal(long);
extern "C" long review_short(long);
extern "C" long review_short_neighbor(long);

asm(R"(
.text
.p2align 4
.global review_x17
.type review_x17,%function
review_x17:
  mov x17, #0x1234
  add x0, x0, #1
  eor x0, x0, x17
  ret
.size review_x17, .-review_x17

.p2align 4
.global review_literal
.type review_literal,%function
review_literal:
  ldr x0, 1f
  ret
1:
  .quad 0x1122334455667788
.size review_literal, .-review_literal

.p2align 4
.global review_short
.type review_short,%function
review_short:
  mov w0, #7
  ret
.size review_short, .-review_short
.global review_short_neighbor
.type review_short_neighbor,%function
review_short_neighbor:
  mov w0, #31
  ret
.size review_short_neighbor, .-review_short_neighbor
)");

static long replacement_x17(long) {
  return 77;
}
static long replacement_literal(long) {
  return 99;
}
static long replacement_short(long) {
  return 123;
}

static int test_concurrent_execution() {
  // This exercises an aligned single-instruction near patch while target
  // threads continue running. It must not be used as proof that long patches
  // or arbitrary instruction-cache synchronization are atomic.
  dobby_require_near_branch_trampoline(true);
  std::atomic<bool> go{false};
  std::atomic<bool> done{false};
  std::atomic<uint64_t> calls{0};
  std::atomic<unsigned> unexpected{0};
  std::vector<std::thread> readers;
  for (int i = 0; i < 4; ++i) {
    readers.emplace_back([&] {
      while (!go.load(std::memory_order_acquire))
        std::this_thread::yield();
      while (!done.load(std::memory_order_acquire)) {
        const long value = review_short(0);
        if (value != 7 && value != 123)
          unexpected.fetch_add(1, std::memory_order_relaxed);
        calls.fetch_add(1, std::memory_order_relaxed);
      }
    });
  }
  go.store(true, std::memory_order_release);
  unsigned installs = 0;
  unsigned errors = 0;
  for (int i = 0; i < 120; ++i) {
    dobby_dummy_func_t original = nullptr;
    const int result = DobbyHook(reinterpret_cast<void *>(review_short),
                                 reinterpret_cast<dobby_dummy_func_t>(replacement_short), &original);
    if (result != RT_SUCCESS || original == nullptr) {
      ++errors;
      break;
    }
    ++installs;
    if (reinterpret_cast<long (*)(long)>(original)(0) != 7 ||
        DobbyDestroy(reinterpret_cast<void *>(review_short)) != RT_SUCCESS) {
      ++errors;
      break;
    }
  }
  done.store(true, std::memory_order_release);
  for (auto &reader : readers)
    reader.join();
  dobby_disable_near_branch_trampoline();
  const bool ok = errors == 0 && unexpected == 0 && installs == 120 && calls.load() > 0 && review_short(0) == 7;
  printf("execute-race installs=%u calls=%llu unexpected=%u errors=%u result=%s\n", installs,
         static_cast<unsigned long long>(calls.load()), unexpected.load(), errors, ok ? "PASS" : "FAIL");
  return ok ? 0 : 1;
}

static void print_layout(const char *name, void *address) {
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps)
    return;
  char line[4096] = {};
  char previous[4096] = {};
  const uintptr_t at = reinterpret_cast<uintptr_t>(address);
  while (fgets(line, sizeof(line), maps)) {
    uintptr_t begin = 0, end = 0;
    char permissions[5] = {};
    if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s", &begin, &end, permissions) == 3 && at >= begin && at < end) {
      printf("%s=%p previous=%s", name, address, previous);
      printf("%s", line);
      if (fgets(line, sizeof(line), maps))
        printf("next=%s", line);
      break;
    }
    strncpy(previous, line, sizeof(previous) - 1);
  }
  fclose(maps);
}

static int permission_at(void *address) {
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps)
    return -1;
  char line[4096];
  int value = -1;
  uintptr_t target = reinterpret_cast<uintptr_t>(address);
  while (fgets(line, sizeof(line), maps)) {
    uintptr_t start = 0, end = 0;
    char permissions[5] = {};
    if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s", &start, &end, permissions) == 3 && target >= start &&
        target < end) {
      value = (permissions[0] == 'r' ? PROT_READ : 0) | (permissions[1] == 'w' ? PROT_WRITE : 0) |
              (permissions[2] == 'x' ? PROT_EXEC : 0);
      break;
    }
  }
  fclose(maps);
  return value;
}

static int check_reserved_neighbor_pages(bool owner_released_slot) {
  // A guest code page inside a PROT_NONE reservation must not justify an
  // unsafe MAP_FIXED replacement of another address-space owner's pages.
  const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  const size_t half = size_t{1} << 27;
  const size_t length = half * 2 + page * 3;
  auto *reservation = static_cast<uint8_t *>(mmap(nullptr, length, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  if (reservation == MAP_FAILED)
    return 2;
  auto *target = reservation + half + page;
  if (mprotect(target, page, PROT_READ | PROT_WRITE) != 0)
    return 2;
  const uint32_t body[] = {0x528000e0, 0xd65f03c0, 0x528003e0, 0xd65f03c0};
  memcpy(target, body, sizeof(body));
  __builtin___clear_cache(reinterpret_cast<char *>(target), reinterpret_cast<char *>(target) + sizeof(body));
  if (mprotect(target, page, PROT_READ | PROT_EXEC) != 0)
    return 2;
  // Only the reservation owner can release one page for Dobby to allocate.
  // Do not use this technique against an actual native bridge reservation.
  if (owner_released_slot && munmap(target - page, page) != 0)
    return 2;
  dobby_require_near_branch_trampoline(true);
  dobby_dummy_func_t original = nullptr;
  auto replacement = reinterpret_cast<dobby_dummy_func_t>(replacement_short);
  const int status = DobbyHook(target, replacement, &original);
  bool ok = permission_at(target - 2 * page) == 0 && permission_at(target + page) == 0 &&
            memcmp(target + 4, reinterpret_cast<const uint8_t *>(body) + 4, 12) == 0;
  if (status == RT_SUCCESS) {
    uint32_t first = 0;
    memcpy(&first, target, sizeof(first));
    auto call = reinterpret_cast<long (*)(long)>(target);
    auto orig = reinterpret_cast<long (*)(long)>(original);
    ok = ok && original != nullptr && (first & 0x7c000000u) == 0x14000000u && call(0) == 123 && orig(0) == 7 &&
         DobbyDestroy(target) == RT_SUCCESS;
  } else {
    ok = ok && original == nullptr && !owner_released_slot;
  }
  ok = ok && memcmp(target, body, sizeof(body)) == 0 && permission_at(target - 2 * page) == 0 &&
       permission_at(target + page) == 0;
  dobby_disable_near_branch_trampoline();
  printf("reservation near owner_released_slot=%d status=%d guard_previous=%d guard_next=%d result=%s\n",
         owner_released_slot, status, permission_at(target - 2 * page), permission_at(target + page),
         ok ? "PASS" : "FAIL");
  munmap(reservation, length);
  return ok ? 0 : 1;
}

template <typename T> static bool roundtrip(const char *name, T target, T replacement, long input, long expected) {
  const long before = target(input);
  dobby_dummy_func_t original = nullptr;
  int installed =
      DobbyHook(reinterpret_cast<void *>(target), reinterpret_cast<dobby_dummy_func_t>(replacement), &original);
  if (installed != RT_SUCCESS || !original) {
    printf("%s hook failed: rc=%d original=%p before=%ld\n", name, installed, reinterpret_cast<void *>(original),
           before);
    return false;
  }
  auto trampoline = reinterpret_cast<T>(original);
  bool ok = before == expected;
  for (int i = 0; i < 200 && ok; ++i) {
    const long hooked = target(input);
    const long replaced = replacement(input);
    const long relocated = trampoline(input);
    if (hooked != replaced || relocated != expected) {
      printf("%s iteration=%d hooked=%ld replacement=%ld original=%ld expected=%ld\n", name, i, hooked, replaced,
             relocated, expected);
      ok = false;
    }
  }
  int destroyed = DobbyDestroy(reinterpret_cast<void *>(target));
  ok = ok && destroyed == RT_SUCCESS && target(input) == expected;
  printf("%s before=%ld expected=%ld destroy=%d result=%s\n", name, before, expected, destroyed, ok ? "PASS" : "FAIL");
  return ok;
}

int main(int argc, char **argv) {
  setbuf(stdout, nullptr);
  if (argc > 1 && strcmp(argv[1], "execute-race") == 0)
    return test_concurrent_execution();
  if (argc > 1 && strcmp(argv[1], "reservation") == 0)
    return check_reserved_neighbor_pages(false);
  if (argc > 1 && strcmp(argv[1], "reservation-owned-gap") == 0)
    return check_reserved_neighbor_pages(true);
  if (argc > 1 && strcmp(argv[1], "maps") == 0) {
    print_layout("x17", reinterpret_cast<void *>(review_x17));
    print_layout("literal", reinterpret_cast<void *>(review_literal));
    return 0;
  }
  if (argc > 1 && strcmp(argv[1], "short") == 0) {
    const long before = review_short(0);
    const long neighbor_before = review_short_neighbor(0);
    uint8_t saved[16] = {};
    memcpy(saved, reinterpret_cast<const void *>(review_short), sizeof(saved));
    dobby_require_near_branch_trampoline(true);
    dobby_dummy_func_t original = nullptr;
    const int installed = DobbyHook(reinterpret_cast<void *>(review_short),
                                    reinterpret_cast<dobby_dummy_func_t>(replacement_short), &original);
    if (installed != RT_SUCCESS || !original) {
      printf("short near hook failed rc=%d original=%p\n", installed, reinterpret_cast<void *>(original));
      dobby_disable_near_branch_trampoline();
      return 1;
    }
    uint32_t first = 0;
    memcpy(&first, reinterpret_cast<const void *>(review_short), sizeof(first));
    bool ok = (first & 0x7c000000u) == 0x14000000u &&
              memcmp(saved + 4, reinterpret_cast<const uint8_t *>(review_short) + 4, 12) == 0;
    for (int i = 0; i < 200 && ok; ++i)
      ok = review_short(0) == 123 && reinterpret_cast<long (*)(long)>(original)(0) == 7 &&
           review_short_neighbor(0) == neighbor_before;
    const int destroyed = DobbyDestroy(reinterpret_cast<void *>(review_short));
    ok = ok && destroyed == RT_SUCCESS &&
         memcmp(saved, reinterpret_cast<const void *>(review_short), sizeof(saved)) == 0 && review_short(0) == before &&
         review_short_neighbor(0) == neighbor_before;
    dobby_disable_near_branch_trampoline();
    printf("short near first=%08x before=%ld neighbor=%ld destroy=%d result=%s\n", first, before, neighbor_before,
           destroyed, ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
  }
  if (argc > 1 && strcmp(argv[1], "near") == 0) {
    dobby_enable_near_branch_trampoline();
  } else if (argc > 1 && strcmp(argv[1], "required") == 0) {
    dobby_require_near_branch_trampoline(true);
  }
  bool a = roundtrip("x17-live", review_x17, replacement_x17, 3, (4 ^ 0x1234));
  bool b = roundtrip("literal-load", review_literal, replacement_literal, 0, 0x1122334455667788LL);
  bool c = verify_rw_mapping_remains_rw();
  return a && b && c ? 0 : 1;
}
