#include "dobby.h"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <linux/membarrier.h>
#include <sched.h>
#include <sys/syscall.h>
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

static std::atomic<uintptr_t> fail_restore_page{0};
static std::atomic<unsigned> restore_injections{0};
extern "C" int __real_mprotect(void *, size_t, int);
extern "C" int __wrap_mprotect(void *address, size_t size, int prot) {
  uintptr_t watched = fail_restore_page.load(std::memory_order_relaxed);
  if (watched != 0 && reinterpret_cast<uintptr_t>(address) == watched && prot == (PROT_READ | PROT_EXEC) &&
      fail_restore_page.compare_exchange_strong(watched, 0)) {
    restore_injections.fetch_add(1, std::memory_order_relaxed);
    errno = EACCES;
    return -1;
  }
  return __real_mprotect(address, size, prot);
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
extern "C" const uint64_t *review_adr();
extern "C" long review_overlap(long);

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
.global review_adr
.type review_adr,%function
review_adr:
  adr x0, 1f
  ret
1:
  .quad 0x1020304050607080
.size review_adr, .-review_adr

.p2align 4
1:
  .word 0x11223344
.global review_overlap
.type review_overlap,%function
review_overlap:
  ldr x0, 1b
  ret
  nop
  nop
.size review_overlap, .-review_overlap

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

static int test_restore_failure(bool near, bool required) {
  uint8_t before[16];
  memcpy(before, reinterpret_cast<const void *>(review_short), sizeof(before));
  if (required)
    dobby_require_near_branch_trampoline(true);
  else if (near)
    dobby_enable_near_branch_trampoline();
  const uintptr_t page =
      reinterpret_cast<uintptr_t>(review_short) & ~(static_cast<uintptr_t>(sysconf(_SC_PAGESIZE)) - 1);
  fail_restore_page.store(page, std::memory_order_release);
  dobby_dummy_func_t original = reinterpret_cast<dobby_dummy_func_t>(1);
  const int failed = DobbyHook(reinterpret_cast<void *>(review_short),
                               reinterpret_cast<dobby_dummy_func_t>(replacement_short), &original);
  fail_restore_page.store(0);
  const bool rolled_back = failed != RT_SUCCESS && original == nullptr && restore_injections.load() == 1 &&
                           memcmp(before, reinterpret_cast<const void *>(review_short), sizeof(before)) == 0 &&
                           review_short(0) == 7 && review_short_neighbor(0) == 31;
  dobby_dummy_func_t retry_original = nullptr;
  const int retried = rolled_back ? DobbyHook(reinterpret_cast<void *>(review_short),
                                              reinterpret_cast<dobby_dummy_func_t>(replacement_short), &retry_original)
                                  : RT_FAILED;
  const bool retried_correctly = retried == RT_SUCCESS && retry_original != nullptr &&
                                 reinterpret_cast<long (*)(long)>(retry_original)(0) == 7 && review_short(0) == 123;
  const int restored = retried == RT_SUCCESS ? DobbyDestroy(reinterpret_cast<void *>(review_short)) : RT_FAILED;
  if (near || required)
    dobby_disable_near_branch_trampoline();
  const bool ok = rolled_back && retried_correctly && restored == RT_SUCCESS &&
                  memcmp(before, reinterpret_cast<const void *>(review_short), sizeof(before)) == 0 &&
                  review_short(0) == 7 && review_short_neighbor(0) == 31;
  printf("rollback: mode=%s injected=%u failed=%d retried=%d destroyed=%d result=%s\n",
         required ? "required"
         : near   ? "near"
                  : "default",
         restore_injections.load(), failed, retried, restored, ok ? "PASS" : "FAIL");
  return ok ? 0 : 1;
}

static const uint64_t *replacement_adr() {
  static uint64_t replacement = 0x123456789;
  return &replacement;
}

static int test_adr_inline_data(bool near, bool required) {
  const auto *source = review_adr();
  constexpr uint64_t expected = 0x1020304050607080ULL;
  const bool before = *source == expected;
  uint8_t entry[16];
  memcpy(entry, reinterpret_cast<const void *>(review_adr), sizeof(entry));
  if (required)
    dobby_require_near_branch_trampoline(true);
  else if (near)
    dobby_enable_near_branch_trampoline();
  dobby_dummy_func_t original = nullptr;
  int installed =
      DobbyHook(reinterpret_cast<void *>(review_adr), reinterpret_cast<dobby_dummy_func_t>(replacement_adr), &original);
  bool correct = installed == RT_SUCCESS && original != nullptr;
  const uint64_t *relocated_pointer = correct ? reinterpret_cast<const uint64_t *(*)()>(original)() : nullptr;
  const uint64_t value = relocated_pointer ? *relocated_pointer : 0;
  const uint64_t source_after = *source;
  const int destroyed = installed == RT_SUCCESS ? DobbyDestroy(reinterpret_cast<void *>(review_adr)) : RT_FAILED;
  const bool restored = memcmp(entry, reinterpret_cast<const void *>(review_adr), sizeof(entry)) == 0;
  if (near || required)
    dobby_disable_near_branch_trampoline();
  const bool ok = (!near && !required)
                      ? before && installed != RT_SUCCESS && original == nullptr && restored &&
                            source_after == expected && *review_adr() == expected
                      : before && installed == RT_SUCCESS && relocated_pointer == source && value == expected &&
                            source_after == expected && destroyed == RT_SUCCESS && restored;
  printf("adr-data: mode=%s before=%d installed=%d source=%p return=%p expected=0x%llx value=0x%llx "
         "source_after=0x%llx destroy=%d restored=%d result=%s\n",
         required ? "required"
         : near   ? "near"
                  : "default",
         before, installed, static_cast<const void *>(source), static_cast<const void *>(relocated_pointer),
         static_cast<unsigned long long>(expected), static_cast<unsigned long long>(value),
         static_cast<unsigned long long>(source_after), destroyed, restored, ok ? "PASS" : "FAIL");
  return ok ? 0 : 1;
}

static int test_literal_left_overlap(bool near, bool required) {
  const uint64_t expected = static_cast<uint64_t>(review_overlap(0));
  if (required)
    dobby_require_near_branch_trampoline(true);
  else if (near)
    dobby_enable_near_branch_trampoline();
  dobby_dummy_func_t original = nullptr;
  const int installed = DobbyHook(reinterpret_cast<void *>(review_overlap),
                                  reinterpret_cast<dobby_dummy_func_t>(replacement_literal), &original);
  const uint64_t actual = original ? static_cast<uint64_t>(reinterpret_cast<long (*)(long)>(original)(0)) : 0;
  const int destroyed = installed == RT_SUCCESS ? DobbyDestroy(reinterpret_cast<void *>(review_overlap)) : RT_FAILED;
  if (near || required)
    dobby_disable_near_branch_trampoline();
  const bool ok = installed == RT_SUCCESS && actual == expected && destroyed == RT_SUCCESS;
  printf("literal-left-overlap: mode=%s installed=%d expected=0x%llx actual=0x%llx destroy=%d result=%s\n",
         required ? "required"
         : near   ? "near"
                  : "default",
         installed, static_cast<unsigned long long>(expected), static_cast<unsigned long long>(actual), destroyed,
         ok ? "PASS" : "FAIL");
  return ok ? 0 : 1;
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

static int test_cross_core_instruction_visibility() {
  // Unlike the live execute-race test (which accepts old OR new behavior
  // during the mutation), this checks the exact result on *other* CPUs after
  // each install/remove API returns. Kernel sync-core membarrier is a separate
  // architectural requirement from an aligned atomic instruction store.
  const long supported = syscall(SYS_membarrier, MEMBARRIER_CMD_QUERY, 0, 0);
  const int required = MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE;
  if (supported < 0 || (supported & required) != required) {
    printf("cross-core: sync-core membarrier unsupported query=%ld\n", supported);
    return 2;
  }
  cpu_set_t allowed;
  CPU_ZERO(&allowed);
  if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0)
    return 2;
  int cores[2] = {-1, -1};
  for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
    if (CPU_ISSET(cpu, &allowed)) {
      cores[cores[0] < 0 ? 0 : 1] = cpu;
      if (cores[1] >= 0)
        break;
    }
  }
  if (cores[1] < 0) {
    printf("cross-core: fewer than two allowed CPUs\n");
    return 2;
  }
  dobby_require_near_branch_trampoline(true);
  constexpr unsigned kWorkers = 2;
  constexpr unsigned kPhases = 160;
  std::atomic<unsigned> epoch{0}, completed{0}, errors{0}, pinned{0};
  std::atomic<bool> done{false};
  std::vector<std::thread> readers;
  for (unsigned id = 0; id < kWorkers; ++id) {
    readers.emplace_back([&, id] {
      cpu_set_t selected;
      CPU_ZERO(&selected);
      CPU_SET(cores[id], &selected);
      if (sched_setaffinity(0, sizeof(selected), &selected) == 0)
        pinned.fetch_add(1, std::memory_order_release);
      else
        errors.fetch_add(1, std::memory_order_relaxed);
      unsigned previous = 0;
      while (!done.load(std::memory_order_acquire)) {
        const unsigned current = epoch.load(std::memory_order_acquire);
        if (current == previous) {
          std::this_thread::yield();
          continue;
        }
        previous = current;
        const long expected = (current & 1u) ? 123 : 7;
        if (review_short(0) != expected)
          errors.fetch_add(1, std::memory_order_relaxed);
        completed.fetch_add(1, std::memory_order_release);
      }
    });
  }
  unsigned phases = 0;
  bool hooked = false;
  for (unsigned phase = 1; phase <= kPhases; ++phase) {
    if (phase & 1u) {
      dobby_dummy_func_t original = nullptr;
      if (DobbyHook(reinterpret_cast<void *>(review_short), reinterpret_cast<dobby_dummy_func_t>(replacement_short),
                    &original) != RT_SUCCESS ||
          !original || reinterpret_cast<long (*)(long)>(original)(0) != 7) {
        errors.fetch_add(1);
        break;
      }
      hooked = true;
    } else {
      if (DobbyDestroy(reinterpret_cast<void *>(review_short)) != RT_SUCCESS) {
        errors.fetch_add(1);
        break;
      }
      hooked = false;
    }
    completed.store(0, std::memory_order_relaxed);
    epoch.store(phase, std::memory_order_release);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (completed.load(std::memory_order_acquire) < kWorkers && std::chrono::steady_clock::now() < deadline)
      std::this_thread::yield();
    if (completed.load(std::memory_order_acquire) != kWorkers) {
      errors.fetch_add(1);
      break;
    }
    ++phases;
  }
  done.store(true, std::memory_order_release);
  for (auto &reader : readers)
    reader.join();
  if (hooked && DobbyDestroy(reinterpret_cast<void *>(review_short)) != RT_SUCCESS)
    errors.fetch_add(1);
  dobby_disable_near_branch_trampoline();
  const bool ok = errors == 0 && pinned == kWorkers && phases == kPhases && review_short(0) == 7;
  printf("cross-core: sync_core=1 pinned=%u cores=%d,%d phases=%u errors=%u result=%s\n", pinned.load(), cores[0],
         cores[1], phases, errors.load(), ok ? "PASS" : "FAIL");
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
  if (argc > 1 && strcmp(argv[1], "adr-data") == 0)
    return test_adr_inline_data(false, false);
  if (argc > 1 && strcmp(argv[1], "adr-data-near") == 0)
    return test_adr_inline_data(true, false);
  if (argc > 1 && strcmp(argv[1], "adr-data-required") == 0)
    return test_adr_inline_data(true, true);
  if (argc > 1 && strcmp(argv[1], "literal-left-overlap") == 0)
    return test_literal_left_overlap(false, false);
  if (argc > 1 && strcmp(argv[1], "literal-left-overlap-near") == 0)
    return test_literal_left_overlap(true, false);
  if (argc > 1 && strcmp(argv[1], "literal-left-overlap-required") == 0)
    return test_literal_left_overlap(true, true);
  if (argc > 1 && strcmp(argv[1], "rollback-default") == 0)
    return test_restore_failure(false, false);
  if (argc > 1 && strcmp(argv[1], "rollback-near") == 0)
    return test_restore_failure(true, false);
  if (argc > 1 && strcmp(argv[1], "rollback-required") == 0)
    return test_restore_failure(true, true);
  if (argc > 1 && strcmp(argv[1], "execute-race") == 0)
    return test_concurrent_execution();
  if (argc > 1 && strcmp(argv[1], "cross-core") == 0)
    return test_cross_core_instruction_visibility();
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
