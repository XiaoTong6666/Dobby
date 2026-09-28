#include "dobby.h"
#include "Interceptor.h"
#include <atomic>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <linux/membarrier.h>
#include <sys/syscall.h>

extern "C" long review_sync_target(long);
asm(R"(
.text
.p2align 4
.global review_sync_target
.type review_sync_target,%function
review_sync_target:
  mov x0, #7
  ret
  nop
  nop
.size review_sync_target, .-review_sync_target
)");

static long replacement(long) { return 123; }
static std::atomic<int> failures{0};
static std::atomic<bool> deny_support{false};
extern "C" long __real_syscall(long number, ...);
extern "C" long __wrap_syscall(long number, ...) {
  va_list ap;
  va_start(ap, number);
  const long a = va_arg(ap, long);
  const long b = va_arg(ap, long);
  const long c = va_arg(ap, long);
  va_end(ap);
  if (number == SYS_membarrier && a == MEMBARRIER_CMD_QUERY && deny_support.load(std::memory_order_relaxed))
    return 0; // Kernel advertises no sync-core capability.
  if (number == SYS_membarrier && a == MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE) {
    uint32_t word = 0;
    memcpy(&word, reinterpret_cast<const void *>(review_sync_target), sizeof(word));
    if (((word & 0x7c000000u) == 0x14000000u || failures.load() > 0) && failures.load() < 2) {
      failures.fetch_add(1);
      errno = EIO;
      return -1;
    }
  }
  return __real_syscall(number, a, b, c);
}

int main(int argc, char **argv) {
  setbuf(stdout, nullptr);
  if (argc == 2 && strcmp(argv[1], "--unsupported") == 0) {
    deny_support.store(true);
    DobbyHookOptions options{sizeof(DobbyHookOptions),
                             DOBBY_BRANCH_REQUIRE_NEAR,
                             DOBBY_HOOK_REQUIRE_CONCURRENT_SAFE,
                             0,
                             reinterpret_cast<void *>(review_sync_target),
                             reinterpret_cast<dobby_dummy_func_t>(replacement)};
    DobbyHookResult result{};
    result.struct_size = sizeof(result);
    uint8_t entry[16] = {};
    memcpy(entry, reinterpret_cast<const void *>(review_sync_target), sizeof(entry));
    const int status = DobbyPrepareHook(&options, &result);
    const bool ok = status == RS_FAILED && result.status == DOBBY_HOOK_SYNC_UNAVAILABLE && result.handle == 0 &&
                    result.original == nullptr && !result.ever_published &&
                    memcmp(entry, reinterpret_cast<const void *>(review_sync_target), sizeof(entry)) == 0 &&
                    Interceptor::SharedInstance()->count() == 0 && review_sync_target(0) == 7;
    printf("sync-unsupported: status=%d cause=%u result=%s\n", status, result.status, ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
  }
  dobby_require_near_branch_trampoline(true);
  dobby_dummy_func_t original = nullptr;
  const int status = DobbyHook(reinterpret_cast<void *>(review_sync_target),
                               reinterpret_cast<dobby_dummy_func_t>(replacement), &original);
  auto *entry = Interceptor::SharedInstance()->find(reinterpret_cast<addr_t>(review_sync_target));
  const bool retained_removing = entry && entry->state == InterceptEntryState::Removing;
  uint32_t actual = 0;
  memcpy(&actual, reinterpret_cast<const void *>(review_sync_target), sizeof(actual));
  dobby_dummy_func_t duplicate = reinterpret_cast<dobby_dummy_func_t>(1);
  const int duplicate_status = DobbyHook(reinterpret_cast<void *>(review_sync_target),
                                          reinterpret_cast<dobby_dummy_func_t>(replacement), &duplicate);
  // A caller must explicitly retry restoration and its cross-core barrier
  // before the registry may drop the potentially in-flight branch metadata.
  const int recovered = entry ? DobbyDestroy(reinterpret_cast<void *>(review_sync_target)) : RT_FAILED;
  const bool ok = status != RT_SUCCESS && failures.load() == 2 && original == nullptr &&
                  retained_removing && actual == 0xd28000e0u &&
                  duplicate_status != RT_SUCCESS && duplicate == nullptr &&
                  recovered == RT_SUCCESS &&
                  Interceptor::SharedInstance()->find(reinterpret_cast<addr_t>(review_sync_target)) == nullptr &&
                  review_sync_target(0) == 7;
  printf("sync-failure: status=%d sync_failures=%d retained=%d duplicate=%d recovered=%d original=%p result=%s\n",
         status, failures.load(), entry != nullptr, duplicate_status, recovered,
         reinterpret_cast<void *>(original), ok ? "PASS" : "FAIL");
  return ok ? 0 : 1;
}
