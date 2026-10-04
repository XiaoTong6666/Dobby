#include "dobby.h"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <atomic>
#include <cerrno>
#include <cstdarg>
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
extern "C" long __real_syscall(long, ...);
extern "C" long __wrap_syscall(long number, ...) {
  va_list args;
  va_start(args, number);
  const long a = va_arg(args, long);
  const long b = va_arg(args, long);
  const long c = va_arg(args, long);
  const long d = va_arg(args, long);
  va_end(args);
  uintptr_t watched = fail_restore_page.load(std::memory_order_relaxed);
  if (number == SYS_mprotect && watched != 0 && static_cast<uintptr_t>(a) == watched &&
      static_cast<int>(c) == (PROT_READ | PROT_EXEC) && fail_restore_page.compare_exchange_strong(watched, 0)) {
    restore_injections.fetch_add(1, std::memory_order_relaxed);
    errno = EACCES;
    return -1;
  }
  return __real_syscall(number, a, b, c, d);
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
extern "C" long review_bti(long);
extern "C" long review_paciasp(long);
extern "C" long review_pacibsp(long);
extern "C" long review_resume_cycle(long);
extern "C" long review_resume_cbz_cycle(long);
extern "C" long review_resume_bcond_cycle(long);
extern "C" long review_resume_tbz_cycle(long);
extern "C" long review_resume_retaa(long);
extern "C" long review_resume_retab(long);
extern "C" long review_resume_eretaa(long);
extern "C" long review_resume_eretab(long);
extern "C" const uint64_t *review_adr();
extern "C" const uint64_t *review_adr_left();
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
.global review_adr_left
.type review_adr_left,%function
review_adr_left:
  adr x0, 1b
  ret
  nop
  nop
.size review_adr_left, .-review_adr_left

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

.p2align 4
.global review_bti
.type review_bti,%function
review_bti:
  .inst 0xd503245f
  mov w0, #9
  ret
.size review_bti, .-review_bti

.p2align 4
.global review_paciasp
.type review_paciasp,%function
review_paciasp:
  .inst 0xd503233f
  mov w0, #11
  .inst 0xd50323bf
  ret
.size review_paciasp, .-review_paciasp

.p2align 4
.global review_pacibsp
.type review_pacibsp,%function
review_pacibsp:
  .inst 0xd503237f
  mov w0, #12
  .inst 0xd50323ff
  ret
.size review_pacibsp, .-review_pacibsp

.p2align 4
.global review_resume_cycle
.type review_resume_cycle,%function
review_resume_cycle:
  nop
  b review_resume_cycle
.size review_resume_cycle, .-review_resume_cycle

.p2align 4
.global review_resume_cbz_cycle
.type review_resume_cbz_cycle,%function
review_resume_cbz_cycle:
  nop
  cbz x0, review_resume_cbz_cycle
  ret
.size review_resume_cbz_cycle, .-review_resume_cbz_cycle

.p2align 4
.global review_resume_bcond_cycle
.type review_resume_bcond_cycle,%function
review_resume_bcond_cycle:
  nop
  b.eq review_resume_bcond_cycle
  ret
.size review_resume_bcond_cycle, .-review_resume_bcond_cycle

.p2align 4
.global review_resume_tbz_cycle
.type review_resume_tbz_cycle,%function
review_resume_tbz_cycle:
  nop
  tbz x0, #0, review_resume_tbz_cycle
  ret
.size review_resume_tbz_cycle, .-review_resume_tbz_cycle

.p2align 4
.global review_resume_retaa
.type review_resume_retaa,%function
review_resume_retaa:
  nop
  .inst 0xd65f0bff
.size review_resume_retaa, .-review_resume_retaa

.p2align 4
.global review_resume_retab
.type review_resume_retab,%function
review_resume_retab:
  nop
  .inst 0xd65f0fff
.size review_resume_retab, .-review_resume_retab

.p2align 4
.global review_resume_eretaa
.type review_resume_eretaa,%function
review_resume_eretaa:
  nop
  .inst 0xd69f0bff
.size review_resume_eretaa, .-review_resume_eretaa

.p2align 4
.global review_resume_eretab
.type review_resume_eretab,%function
review_resume_eretab:
  nop
  .inst 0xd69f0fff
.size review_resume_eretab, .-review_resume_eretab
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

static std::atomic<dobby_dummy_func_t> g_transaction_backup{nullptr};
static long replacement_transaction(long value) {
  const auto original = reinterpret_cast<long (*)(long)>(g_transaction_backup.load(std::memory_order_acquire));
  return original ? original(value) + 116 : -1000;
}

static int test_transaction_api(bool rollback) {
  uint8_t before[16];
  memcpy(before, reinterpret_cast<const void *>(review_short), sizeof(before));
  DobbyHookOptions options = {sizeof(options),
                              DOBBY_BRANCH_REQUIRE_NEAR,
                              DOBBY_HOOK_REQUIRE_CONCURRENT_SAFE | DOBBY_HOOK_REQUIRE_PRISTINE_ENTRY |
                                  DOBBY_HOOK_VALIDATE_BACKUP,
                              0,
                              reinterpret_cast<void *>(review_short),
                              reinterpret_cast<dobby_dummy_func_t>(replacement_transaction)};
  DobbyHookResult result = {sizeof(result)};
  bool ok = DobbyPrepareHook(&options, &result) == RS_SUCCESS && result.status == DOBBY_HOOK_OK && result.handle &&
            result.original && result.patch_size == 4 && result.selected_branch == DOBBY_BRANCH_REQUIRE_NEAR &&
            review_short(0) == 7 && reinterpret_cast<long (*)(long)>(result.original)(0) == 7 &&
            memcmp(before, reinterpret_cast<const void *>(review_short), sizeof(before)) == 0;
  if (!ok) {
    printf("transaction-arm64: mode=%s prepare_status=%u result=FAIL\n", rollback ? "rollback" : "roundtrip",
           result.status);
    return 1;
  }
  const DobbyHookHandle ticket = result.handle;
  g_transaction_backup.store(result.original, std::memory_order_release);
  dobby_dummy_func_t legacy_backup = reinterpret_cast<dobby_dummy_func_t>(1);
  ok &= DobbyHook(reinterpret_cast<void *>(review_short), reinterpret_cast<dobby_dummy_func_t>(replacement_short),
                  &legacy_backup) == RS_FAILED &&
        legacy_backup == nullptr;
  if (rollback) {
    const uintptr_t page =
        reinterpret_cast<uintptr_t>(review_short) & ~(static_cast<uintptr_t>(sysconf(_SC_PAGESIZE)) - 1);
    fail_restore_page.store(page, std::memory_order_release);
  }
  const int committed = DobbyCommitHook(ticket, &result);
  fail_restore_page.store(0, std::memory_order_release);
  if (rollback) {
    ok &= committed == RS_FAILED && result.status == DOBBY_HOOK_PATCH_FAILED && result.restored_and_synchronized &&
          result.ever_published && result.handle == 0 && review_short(0) == 7 &&
          memcmp(before, reinterpret_cast<const void *>(review_short), sizeof(before)) == 0;
  } else {
    ok &= committed == RS_SUCCESS && result.status == DOBBY_HOOK_OK && result.handle == ticket &&
          review_short(0) == 123 && reinterpret_cast<long (*)(long)>(result.original)(0) == 7 &&
          memcmp(before + 4, reinterpret_cast<const uint8_t *>(review_short) + 4, 12) == 0;
    DobbyHookResult removed = {sizeof(removed)};
    ok &= DobbyDestroyHook(ticket, &removed) == RS_SUCCESS && removed.restored_and_synchronized &&
          review_short(0) == 7 && memcmp(before, reinterpret_cast<const void *>(review_short), sizeof(before)) == 0;
  }
  DobbyHookResult stale = {sizeof(stale)};
  ok &= DobbyCommitHook(ticket, &stale) == RS_FAILED && stale.status == DOBBY_HOOK_INVALID_HANDLE;
  g_transaction_backup.store(nullptr);
  printf("transaction-arm64: mode=%s committed=%d state=%u stale=%u result=%s\n", rollback ? "rollback" : "roundtrip",
         committed, result.status, stale.status, ok ? "PASS" : "FAIL");
  return ok ? 0 : 1;
}

static int test_strict_prepatched_entry() {
  const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  const uintptr_t target = reinterpret_cast<uintptr_t>(review_short);
  const uintptr_t page_start = target & ~(static_cast<uintptr_t>(page) - 1);
  uint32_t original = 0;
  memcpy(&original, reinterpret_cast<const void *>(target), sizeof(original));
  const intptr_t delta = reinterpret_cast<uintptr_t>(review_short_neighbor) - target;
  if ((delta & 3) != 0 || delta < -(intptr_t{1} << 27) || delta >= (intptr_t{1} << 27))
    return 2;
  const uint32_t foreign_branch = 0x14000000u | (static_cast<uint32_t>(delta >> 2) & 0x03ffffffu);

  if (mprotect(reinterpret_cast<void *>(page_start), page, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
    return 2;
  memcpy(reinterpret_cast<void *>(target), &foreign_branch, sizeof(foreign_branch));
  __builtin___clear_cache(reinterpret_cast<char *>(target), reinterpret_cast<char *>(target + sizeof(foreign_branch)));
  if (mprotect(reinterpret_cast<void *>(page_start), page, PROT_READ | PROT_EXEC) != 0)
    return 2;

  DobbyHookOptions options = {sizeof(options),
                              DOBBY_BRANCH_REQUIRE_NEAR,
                              DOBBY_HOOK_REQUIRE_CONCURRENT_SAFE | DOBBY_HOOK_REQUIRE_PRISTINE_ENTRY |
                                  DOBBY_HOOK_VALIDATE_BACKUP,
                              0,
                              reinterpret_cast<void *>(target),
                              reinterpret_cast<dobby_dummy_func_t>(replacement_transaction)};
  DobbyHookResult result = {sizeof(result)};
  const int prepared = DobbyPrepareHook(&options, &result);

  if (mprotect(reinterpret_cast<void *>(page_start), page, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
    return 2;
  memcpy(reinterpret_cast<void *>(target), &original, sizeof(original));
  __builtin___clear_cache(reinterpret_cast<char *>(target), reinterpret_cast<char *>(target + sizeof(original)));
  if (mprotect(reinterpret_cast<void *>(page_start), page, PROT_READ | PROT_EXEC) != 0)
    return 2;

  const bool ok = prepared == RS_FAILED && result.status == DOBBY_HOOK_TARGET_PREPATCHED && result.handle == 0 &&
                  result.original == nullptr && review_short(0) == 7;
  printf("strict-prepatched: prepared=%d status=%u handle=%llu result=%s\n", prepared, result.status,
         static_cast<unsigned long long>(result.handle), ok ? "PASS" : "FAIL");
  return ok ? 0 : 1;
}

static int test_strict_prepatched_late_entry() {
  const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  const uintptr_t target = reinterpret_cast<uintptr_t>(review_short);
  const uintptr_t page_start = target & ~(static_cast<uintptr_t>(page) - 1);
  uint32_t original_second = 0;
  memcpy(&original_second, reinterpret_cast<const void *>(target + sizeof(uint32_t)), sizeof(original_second));
  const uint32_t foreign_second = 0xd503201fu; // nop: preserve word 0, alter word 1

  if (mprotect(reinterpret_cast<void *>(page_start), page, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
    return 2;
  memcpy(reinterpret_cast<void *>(target + sizeof(uint32_t)), &foreign_second, sizeof(foreign_second));
  __builtin___clear_cache(reinterpret_cast<char *>(target + sizeof(uint32_t)),
                          reinterpret_cast<char *>(target + 2 * sizeof(uint32_t)));
  if (mprotect(reinterpret_cast<void *>(page_start), page, PROT_READ | PROT_EXEC) != 0)
    return 2;

  DobbyHookOptions options = {sizeof(options),
                              DOBBY_BRANCH_REQUIRE_NEAR,
                              DOBBY_HOOK_REQUIRE_CONCURRENT_SAFE | DOBBY_HOOK_REQUIRE_PRISTINE_ENTRY |
                                  DOBBY_HOOK_VALIDATE_BACKUP | DOBBY_HOOK_PRESERVE_LANDING_PAD,
                              0,
                              reinterpret_cast<void *>(target),
                              reinterpret_cast<dobby_dummy_func_t>(replacement_transaction)};
  DobbyHookResult result = {sizeof(result)};
  const int prepared = DobbyPrepareHook(&options, &result);

  if (mprotect(reinterpret_cast<void *>(page_start), page, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
    return 2;
  memcpy(reinterpret_cast<void *>(target + sizeof(uint32_t)), &original_second, sizeof(original_second));
  __builtin___clear_cache(reinterpret_cast<char *>(target + sizeof(uint32_t)),
                          reinterpret_cast<char *>(target + 2 * sizeof(uint32_t)));
  if (mprotect(reinterpret_cast<void *>(page_start), page, PROT_READ | PROT_EXEC) != 0)
    return 2;

  const bool ok = prepared == RS_FAILED && result.status == DOBBY_HOOK_TARGET_PREPATCHED && result.handle == 0 &&
                  result.original == nullptr && review_short(0) == 7;
  printf("strict-prepatched-late: prepared=%d status=%u handle=%llu result=%s\n", prepared, result.status,
         static_cast<unsigned long long>(result.handle), ok ? "PASS" : "FAIL");
  return ok ? 0 : 1;
}

static int test_strict_target_changed_late() {
  const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  const uintptr_t target = reinterpret_cast<uintptr_t>(review_short);
  const uintptr_t page_start = target & ~(static_cast<uintptr_t>(page) - 1);
  uint32_t original_second = 0;
  memcpy(&original_second, reinterpret_cast<const void *>(target + sizeof(uint32_t)), sizeof(original_second));

  DobbyHookOptions options = {sizeof(options),
                              DOBBY_BRANCH_REQUIRE_NEAR,
                              DOBBY_HOOK_REQUIRE_CONCURRENT_SAFE | DOBBY_HOOK_REQUIRE_PRISTINE_ENTRY |
                                  DOBBY_HOOK_VALIDATE_BACKUP | DOBBY_HOOK_PRESERVE_LANDING_PAD,
                              0,
                              reinterpret_cast<void *>(target),
                              reinterpret_cast<dobby_dummy_func_t>(replacement_transaction)};
  DobbyHookResult result = {sizeof(result)};
  if (DobbyPrepareHook(&options, &result) != RS_SUCCESS || result.handle == 0 || result.original == nullptr)
    return 1;
  const DobbyHookHandle ticket = result.handle;

  const uint32_t foreign_second = 0xd503201fu;
  if (mprotect(reinterpret_cast<void *>(page_start), page, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
    return 2;
  memcpy(reinterpret_cast<void *>(target + sizeof(uint32_t)), &foreign_second, sizeof(foreign_second));
  __builtin___clear_cache(reinterpret_cast<char *>(target + sizeof(uint32_t)),
                          reinterpret_cast<char *>(target + 2 * sizeof(uint32_t)));
  if (mprotect(reinterpret_cast<void *>(page_start), page, PROT_READ | PROT_EXEC) != 0)
    return 2;

  const int committed = DobbyCommitHook(ticket, &result);

  if (mprotect(reinterpret_cast<void *>(page_start), page, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
    return 2;
  memcpy(reinterpret_cast<void *>(target + sizeof(uint32_t)), &original_second, sizeof(original_second));
  __builtin___clear_cache(reinterpret_cast<char *>(target + sizeof(uint32_t)),
                          reinterpret_cast<char *>(target + 2 * sizeof(uint32_t)));
  if (mprotect(reinterpret_cast<void *>(page_start), page, PROT_READ | PROT_EXEC) != 0)
    return 2;

  DobbyHookResult aborted = {sizeof(aborted)};
  const int abort_status = DobbyAbortHook(ticket, &aborted);
  const bool ok = committed == RS_FAILED && result.status == DOBBY_HOOK_TARGET_CHANGED && !result.ever_published &&
                  !result.target_may_be_patched && result.handle == ticket && abort_status == RS_SUCCESS &&
                  review_short(0) == 7;
  printf("strict-target-changed-late: committed=%d status=%u abort=%d result=%s\n", committed, result.status,
         abort_status, ok ? "PASS" : "FAIL");
  return ok ? 0 : 1;
}

static int test_strict_backup_cycle() {
  const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  auto *code = static_cast<uint32_t *>(mmap(nullptr, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  if (code == MAP_FAILED)
    return 2;
  code[0] = 0x14000000u; // b .
  code[1] = 0xd65f03c0u; // ret
  __builtin___clear_cache(reinterpret_cast<char *>(code), reinterpret_cast<char *>(code + 2));
  if (mprotect(code, page, PROT_READ | PROT_EXEC) != 0) {
    munmap(code, page);
    return 2;
  }

  DobbyHookOptions options = {sizeof(options),
                              DOBBY_BRANCH_REQUIRE_NEAR,
                              DOBBY_HOOK_REQUIRE_CONCURRENT_SAFE | DOBBY_HOOK_VALIDATE_BACKUP,
                              0,
                              code,
                              reinterpret_cast<dobby_dummy_func_t>(replacement_transaction)};
  DobbyHookResult result = {sizeof(result)};
  const int prepared = DobbyPrepareHook(&options, &result);
  const bool ok = prepared == RS_FAILED && result.status == DOBBY_HOOK_BACKUP_INVALID && result.handle == 0 &&
                  result.original == nullptr;
  printf("strict-backup-cycle: prepared=%d status=%u handle=%llu result=%s\n", prepared, result.status,
         static_cast<unsigned long long>(result.handle), ok ? "PASS" : "FAIL");
  munmap(code, page);
  return ok ? 0 : 1;
}

static int test_strict_bti_entry() {
  uint32_t before_bti = 0;
  memcpy(&before_bti, reinterpret_cast<const void *>(review_bti), sizeof(before_bti));
  DobbyHookOptions options = {sizeof(options),
                              DOBBY_BRANCH_REQUIRE_NEAR,
                              DOBBY_HOOK_REQUIRE_CONCURRENT_SAFE | DOBBY_HOOK_REQUIRE_PRISTINE_ENTRY |
                                  DOBBY_HOOK_VALIDATE_BACKUP | DOBBY_HOOK_PRESERVE_LANDING_PAD,
                              0,
                              reinterpret_cast<void *>(review_bti),
                              reinterpret_cast<dobby_dummy_func_t>(replacement_transaction)};
  DobbyHookResult result = {sizeof(result)};
  const int prepared = DobbyPrepareHook(&options, &result);
  bool ok = prepared == RS_SUCCESS && result.status == DOBBY_HOOK_OK && result.handle != 0 &&
            result.original != nullptr && result.patch_size == sizeof(uint32_t) && review_bti(0) == 9 &&
            reinterpret_cast<long (*)(long)>(result.original)(0) == 9;
  uint32_t after_prepare_bti = 0;
  memcpy(&after_prepare_bti, reinterpret_cast<const void *>(review_bti), sizeof(after_prepare_bti));
  ok &= after_prepare_bti == before_bti;
  if (ok) {
    g_transaction_backup.store(result.original, std::memory_order_release);
    ok &= DobbyCommitHook(result.handle, &result) == RS_SUCCESS && review_bti(0) == 125;
    uint32_t after_commit_bti = 0;
    memcpy(&after_commit_bti, reinterpret_cast<const void *>(review_bti), sizeof(after_commit_bti));
    ok &= after_commit_bti == before_bti;
    DobbyHookResult removed = {sizeof(removed)};
    ok &= DobbyDestroyHook(result.handle, &removed) == RS_SUCCESS && review_bti(0) == 9;
    uint32_t after_destroy_bti = 0;
    memcpy(&after_destroy_bti, reinterpret_cast<const void *>(review_bti), sizeof(after_destroy_bti));
    ok &= after_destroy_bti == before_bti;
    g_transaction_backup.store(nullptr, std::memory_order_release);
  }
  printf("strict-bti: prepared=%d status=%u handle=%llu bti=%08x result=%s\n", prepared, result.status,
         static_cast<unsigned long long>(result.handle), before_bti, ok ? "PASS" : "FAIL");
  return ok ? 0 : 1;
}

static int test_strict_pac_landing_pad() {
  auto check = [](void *target, const char *label) {
    DobbyHookOptions options = {sizeof(options),
                                DOBBY_BRANCH_REQUIRE_NEAR,
                                DOBBY_HOOK_REQUIRE_CONCURRENT_SAFE | DOBBY_HOOK_VALIDATE_BACKUP |
                                    DOBBY_HOOK_PRESERVE_LANDING_PAD,
                                0,
                                target,
                                reinterpret_cast<dobby_dummy_func_t>(replacement_transaction)};
    DobbyHookResult result = {sizeof(result)};
    const int prepared = DobbyPrepareHook(&options, &result);
    const bool ok = prepared == RS_FAILED && result.status == DOBBY_HOOK_TARGET_UNSUPPORTED &&
                    result.handle == 0 && result.original == nullptr;
    printf("strict-pac-landing-%s: prepared=%d status=%u result=%s\n", label, prepared, result.status,
           ok ? "PASS" : "FAIL");
    return ok;
  };
  const bool a = check(reinterpret_cast<void *>(review_paciasp), "a");
  const bool b = check(reinterpret_cast<void *>(review_pacibsp), "b");
  return a && b ? 0 : 1;
}

static int test_strict_bti_ownership() {
  DobbyHookOptions first_options = {sizeof(first_options),
                                    DOBBY_BRANCH_REQUIRE_NEAR,
                                    DOBBY_HOOK_REQUIRE_CONCURRENT_SAFE | DOBBY_HOOK_REQUIRE_PRISTINE_ENTRY |
                                        DOBBY_HOOK_VALIDATE_BACKUP | DOBBY_HOOK_PRESERVE_LANDING_PAD,
                                    0,
                                    reinterpret_cast<void *>(review_bti),
                                    reinterpret_cast<dobby_dummy_func_t>(replacement_transaction)};
  DobbyHookResult first = {sizeof(first)};
  if (DobbyPrepareHook(&first_options, &first) != RS_SUCCESS || first.handle == 0 || first.original == nullptr) {
    printf("strict-bti-ownership: first_status=%u result=FAIL\n", first.status);
    return 1;
  }

  DobbyHookOptions logical_options = first_options;
  DobbyHookResult logical = {sizeof(logical)};
  const int logical_prepare = DobbyPrepareHook(&logical_options, &logical);

  DobbyHookOptions physical_options = first_options;
  physical_options.target = reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(review_bti) + sizeof(uint32_t));
  DobbyHookResult physical = {sizeof(physical)};
  const int physical_prepare = DobbyPrepareHook(&physical_options, &physical);

  DobbyHookResult aborted = {sizeof(aborted)};
  const int abort_status = DobbyAbortHook(first.handle, &aborted);
  const bool ok = logical_prepare == RS_FAILED && logical.status == DOBBY_HOOK_TARGET_BUSY && logical.handle == 0 &&
                  physical_prepare == RS_FAILED && physical.status == DOBBY_HOOK_TARGET_BUSY && physical.handle == 0 &&
                  abort_status == RS_SUCCESS && review_bti(0) == 9;
  printf("strict-bti-ownership: logical=%u physical=%u abort=%d result=%s\n", logical.status, physical.status,
         abort_status, ok ? "PASS" : "FAIL");
  return ok ? 0 : 1;
}

static int test_strict_bti_foreign_destroy() {
  const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  const uintptr_t target = reinterpret_cast<uintptr_t>(review_bti);
  const uintptr_t patch_site = target + sizeof(uint32_t);
  const uintptr_t page_start = patch_site & ~(static_cast<uintptr_t>(page) - 1);
  uint32_t landing_before = 0;
  memcpy(&landing_before, reinterpret_cast<const void *>(target), sizeof(landing_before));

  DobbyHookOptions options = {sizeof(options),
                              DOBBY_BRANCH_REQUIRE_NEAR,
                              DOBBY_HOOK_REQUIRE_CONCURRENT_SAFE | DOBBY_HOOK_REQUIRE_PRISTINE_ENTRY |
                                  DOBBY_HOOK_VALIDATE_BACKUP | DOBBY_HOOK_PRESERVE_LANDING_PAD,
                              0,
                              reinterpret_cast<void *>(target),
                              reinterpret_cast<dobby_dummy_func_t>(replacement_transaction)};
  DobbyHookResult result = {sizeof(result)};
  if (DobbyPrepareHook(&options, &result) != RS_SUCCESS || result.handle == 0 || result.original == nullptr)
    return 1;
  const DobbyHookHandle ticket = result.handle;
  g_transaction_backup.store(result.original, std::memory_order_release);
  if (DobbyCommitHook(ticket, &result) != RS_SUCCESS)
    return 1;

  uint32_t dobby_patch = 0;
  memcpy(&dobby_patch, reinterpret_cast<const void *>(patch_site), sizeof(dobby_patch));
  const uint32_t foreign_patch = 0xd503201fu; // nop
  if (mprotect(reinterpret_cast<void *>(page_start), page, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
    return 2;
  memcpy(reinterpret_cast<void *>(patch_site), &foreign_patch, sizeof(foreign_patch));
  __builtin___clear_cache(reinterpret_cast<char *>(patch_site),
                          reinterpret_cast<char *>(patch_site + sizeof(foreign_patch)));
  if (mprotect(reinterpret_cast<void *>(page_start), page, PROT_READ | PROT_EXEC) != 0)
    return 2;

  DobbyHookResult rejected = {sizeof(rejected)};
  const int first_destroy = DobbyDestroyHook(ticket, &rejected);
  uint32_t after_reject = 0;
  memcpy(&after_reject, reinterpret_cast<const void *>(patch_site), sizeof(after_reject));

  if (mprotect(reinterpret_cast<void *>(page_start), page, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
    return 2;
  memcpy(reinterpret_cast<void *>(patch_site), &dobby_patch, sizeof(dobby_patch));
  __builtin___clear_cache(reinterpret_cast<char *>(patch_site),
                          reinterpret_cast<char *>(patch_site + sizeof(dobby_patch)));
  if (mprotect(reinterpret_cast<void *>(page_start), page, PROT_READ | PROT_EXEC) != 0)
    return 2;

  DobbyHookResult removed = {sizeof(removed)};
  const int second_destroy = DobbyDestroyHook(ticket, &removed);
  uint32_t landing_after = 0;
  memcpy(&landing_after, reinterpret_cast<const void *>(target), sizeof(landing_after));
  g_transaction_backup.store(nullptr, std::memory_order_release);

  const bool ok = first_destroy == RS_FAILED && rejected.status == DOBBY_HOOK_TARGET_CHANGED &&
                  rejected.handle == ticket && after_reject == foreign_patch && second_destroy == RS_SUCCESS &&
                  landing_after == landing_before && review_bti(0) == 9;
  printf("strict-bti-foreign-destroy: first=%d status=%u second=%d result=%s\n", first_destroy, rejected.status,
         second_destroy, ok ? "PASS" : "FAIL");
  return ok ? 0 : 1;
}

static int test_strict_resume_cycle() {
  DobbyHookOptions options = {sizeof(options),
                              DOBBY_BRANCH_REQUIRE_NEAR,
                              DOBBY_HOOK_REQUIRE_CONCURRENT_SAFE | DOBBY_HOOK_REQUIRE_PRISTINE_ENTRY |
                                  DOBBY_HOOK_VALIDATE_BACKUP,
                              0,
                              reinterpret_cast<void *>(review_resume_cycle),
                              reinterpret_cast<dobby_dummy_func_t>(replacement_transaction)};
  DobbyHookResult result = {sizeof(result)};
  const int prepared = DobbyPrepareHook(&options, &result);
  const bool ok = prepared == RS_FAILED && result.status == DOBBY_HOOK_BACKUP_INVALID && result.handle == 0 &&
                  result.original == nullptr;
  printf("strict-resume-cycle: prepared=%d status=%u handle=%llu result=%s\n", prepared, result.status,
         static_cast<unsigned long long>(result.handle), ok ? "PASS" : "FAIL");
  return ok ? 0 : 1;
}

static int test_strict_conditional_resume_cycles() {
  struct Case {
    const char *name;
    void *target;
  } cases[] = {
      {"cbz", reinterpret_cast<void *>(review_resume_cbz_cycle)},
      {"bcond", reinterpret_cast<void *>(review_resume_bcond_cycle)},
      {"tbz", reinterpret_cast<void *>(review_resume_tbz_cycle)},
  };
  bool all_ok = true;
  for (const auto &test : cases) {
    DobbyHookOptions options = {sizeof(options),
                                DOBBY_BRANCH_REQUIRE_NEAR,
                                DOBBY_HOOK_REQUIRE_CONCURRENT_SAFE | DOBBY_HOOK_VALIDATE_BACKUP,
                                0,
                                test.target,
                                reinterpret_cast<dobby_dummy_func_t>(replacement_transaction)};
    DobbyHookResult result = {sizeof(result)};
    const int prepared = DobbyPrepareHook(&options, &result);
    const bool ok = prepared == RS_FAILED && result.status == DOBBY_HOOK_BACKUP_INVALID && result.handle == 0 &&
                    result.original == nullptr;
    printf("strict-resume-%s-cycle: prepared=%d status=%u result=%s\n", test.name, prepared, result.status,
           ok ? "PASS" : "FAIL");
    all_ok &= ok;
  }
  return all_ok ? 0 : 1;
}

static int test_strict_authenticated_resume() {
  struct Case {
    const char *name;
    void *target;
  } cases[] = {
      {"retaa", reinterpret_cast<void *>(review_resume_retaa)},
      {"retab", reinterpret_cast<void *>(review_resume_retab)},
      {"eretaa", reinterpret_cast<void *>(review_resume_eretaa)},
      {"eretab", reinterpret_cast<void *>(review_resume_eretab)},
  };
  bool all_ok = true;
  for (const auto &test : cases) {
    DobbyHookOptions options = {sizeof(options),
                                DOBBY_BRANCH_REQUIRE_NEAR,
                                DOBBY_HOOK_REQUIRE_CONCURRENT_SAFE | DOBBY_HOOK_VALIDATE_BACKUP,
                                0,
                                test.target,
                                reinterpret_cast<dobby_dummy_func_t>(replacement_transaction)};
    DobbyHookResult result = {sizeof(result)};
    const int prepared = DobbyPrepareHook(&options, &result);
    const bool ok = prepared == RS_FAILED && result.status == DOBBY_HOOK_TARGET_UNSUPPORTED && result.handle == 0 &&
                    result.original == nullptr;
    printf("strict-resume-pauth-%s: prepared=%d status=%u result=%s\n", test.name, prepared, result.status,
           ok ? "PASS" : "FAIL");
    all_ok &= ok;
  }
  return all_ok ? 0 : 1;
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

static int test_adr_left_overlap(bool near) {
  const auto *pointer = reinterpret_cast<const uint8_t *>(review_adr_left());
  uint64_t before = 0;
  memcpy(&before, pointer, sizeof(before));
  uint8_t entry[16] = {};
  memcpy(entry, reinterpret_cast<const void *>(review_adr_left), sizeof(entry));
  if (near)
    dobby_enable_near_branch_trampoline();
  dobby_dummy_func_t original = nullptr;
  const int installed = DobbyHook(reinterpret_cast<void *>(review_adr_left),
                                  reinterpret_cast<dobby_dummy_func_t>(replacement_adr), &original);
  uint64_t after = 0;
  memcpy(&after, pointer, sizeof(after));
  int destroyed = installed == RT_SUCCESS ? DobbyDestroy(reinterpret_cast<void *>(review_adr_left)) : RT_FAILED;
  if (near)
    dobby_disable_near_branch_trampoline();
  const bool restored = memcmp(entry, reinterpret_cast<const void *>(review_adr_left), sizeof(entry)) == 0;
  // ADR's address is before the entry, but an eight-byte access overlaps it.
  // No patch should silently mutate the data visible through this pointer.
  const bool ok = installed != RT_SUCCESS && original == nullptr && before == after && restored;
  printf("adr-left-overlap mode=%s status=%d before=0x%llx after=0x%llx destroy=%d restored=%d result=%s\n",
         near ? "near" : "default", installed, static_cast<unsigned long long>(before),
         static_cast<unsigned long long>(after), destroyed, restored, ok ? "PASS" : "FAIL");
  return ok ? 0 : 1;
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
  if (argc > 1 && strcmp(argv[1], "adr-left-overlap") == 0)
    return test_adr_left_overlap(false);
  if (argc > 1 && strcmp(argv[1], "adr-left-overlap-near") == 0)
    return test_adr_left_overlap(true);
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
  if (argc > 1 && strcmp(argv[1], "transaction") == 0)
    return test_transaction_api(false);
  if (argc > 1 && strcmp(argv[1], "transaction-rollback") == 0)
    return test_transaction_api(true);
  if (argc > 1 && strcmp(argv[1], "strict-prepatched") == 0)
    return test_strict_prepatched_entry();
  if (argc > 1 && strcmp(argv[1], "strict-prepatched-late") == 0)
    return test_strict_prepatched_late_entry();
  if (argc > 1 && strcmp(argv[1], "strict-target-changed-late") == 0)
    return test_strict_target_changed_late();
  if (argc > 1 && strcmp(argv[1], "strict-backup-cycle") == 0)
    return test_strict_backup_cycle();
  if (argc > 1 && strcmp(argv[1], "strict-bti") == 0)
    return test_strict_bti_entry();
  if (argc > 1 && strcmp(argv[1], "strict-pac-landing") == 0)
    return test_strict_pac_landing_pad();
  if (argc > 1 && strcmp(argv[1], "strict-bti-ownership") == 0)
    return test_strict_bti_ownership();
  if (argc > 1 && strcmp(argv[1], "strict-bti-foreign-destroy") == 0)
    return test_strict_bti_foreign_destroy();
  if (argc > 1 && strcmp(argv[1], "strict-resume-cycle") == 0)
    return test_strict_resume_cycle();
  if (argc > 1 && strcmp(argv[1], "strict-resume-conditional") == 0)
    return test_strict_conditional_resume_cycles();
  if (argc > 1 && strcmp(argv[1], "strict-resume-pauth") == 0)
    return test_strict_authenticated_resume();
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
