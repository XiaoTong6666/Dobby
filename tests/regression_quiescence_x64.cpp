#include "dobby.h"
#include "Interceptor.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <pthread.h>
#include <sys/mman.h>
#include <thread>
#include <unistd.h>
#include <vector>

#if defined(__x86_64__)
namespace {
using Target = int (*)();
int Replacement() { return 99; }

struct ExecutionHost {
  pthread_rwlock_t entry_gate = PTHREAD_RWLOCK_INITIALIZER;
  std::atomic<int> inside{0};
  std::atomic<bool> writer_pending{false};
  std::atomic<int> pauses{0};
  std::atomic<int> resumes{0};
  std::atomic<bool> deny_next{false};
  void *target = nullptr;
};
std::atomic<bool> g_fail_after_patch{false};
void *g_fault_target = nullptr;
int StopAll(void *opaque, void *target, uint32_t span) {
  auto &host = *static_cast<ExecutionHost *>(opaque);
  if (host.deny_next.exchange(false))
    return 0; // Must reject BEFORE publishing any patch.
  if (target != host.target || span < 5 || span > 256)
    return 0;
  // The fixture guarantees every possible entrant owns entry_gate in read
  // mode and cannot spawn an unregistered entrant during the exclusive lease.
  // Block admission before waiting for the writer lock. The default glibc
  // rwlock may prefer readers, so an endless stream of reader acquisitions is
  // otherwise allowed to starve this writer forever and make the regression
  // depend on scheduler luck rather than Dobby's transaction semantics.
  host.writer_pending.store(true, std::memory_order_release);
  if (pthread_rwlock_wrlock(&host.entry_gate) != 0) {
    host.writer_pending.store(false, std::memory_order_release);
    return 0;
  }
  if (host.inside.load() != 0) {
    pthread_rwlock_unlock(&host.entry_gate);
    host.writer_pending.store(false, std::memory_order_release);
    return 0;
  }
  ++host.pauses;
  return 1;
}
void ResumeAll(void *opaque) {
  auto &host = *static_cast<ExecutionHost *>(opaque);
  ++host.resumes;
  pthread_rwlock_unlock(&host.entry_gate);
  host.writer_pending.store(false, std::memory_order_release);
}
bool Assert(bool condition, const char *message) {
  if (!condition)
    fprintf(stderr, "quiescence-x64 FAIL: %s\n", message);
  return condition;
}
DobbyHookResult Result() {
  DobbyHookResult result{};
  result.struct_size = sizeof(result);
  return result;
}
}
#endif

#if defined(__x86_64__)
extern "C" MemoryOperationError __real_DobbyCodePatch(void *, uint8_t *, uint32_t);
extern "C" MemoryOperationError __wrap_DobbyCodePatch(void *address, uint8_t *bytes, uint32_t size) {
  const auto result = __real_DobbyCodePatch(address, bytes, size);
  if (address == g_fault_target && result == kMemoryOperationSuccess && g_fail_after_patch.exchange(false))
    return kMemoryOperationError; // Physical entry was already modified.
  return result;
}
#endif

int main() {
#if !defined(__x86_64__)
  return 0;
#else
  const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  void *code = mmap(nullptr, page, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (code == MAP_FAILED) return 2;
  // Keep the fixture on well-covered legacy x86 encodings while forcing the
  // stolen span to cross the long trampoline boundary: 5 + 3 + 3 + 5 = 16
  // bytes before RET.  The arithmetic immediates are zero, so the function
  // still returns 7.
  const uint8_t original[] = {0xb8, 0x07, 0x00, 0x00, 0x00,       // mov eax,7
                              0x83, 0xc0, 0x00,                   // add eax,0
                              0x83, 0xe8, 0x00,                   // sub eax,0
                              0xb9, 0x00, 0x00, 0x00, 0x00,       // mov ecx,0
                              0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                              0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
  memcpy(code, original, sizeof(original));
  auto target = reinterpret_cast<Target>(code);
  ExecutionHost host;
  host.target = code;
  DobbyHookOptionsQuiescentV2 options{};
  options.base = {sizeof(options), DOBBY_BRANCH_FORCE_LONG, DOBBY_HOOK_REQUIRE_CONCURRENT_SAFE, 0,
                  code, reinterpret_cast<dobby_dummy_func_t>(Replacement)};
  options.user_data = &host;
  options.acquire = StopAll;
  options.release = ResumeAll;
  std::atomic<bool> running{true};
  std::atomic<int> errors{0};
  std::vector<std::thread> workers;
  for (int t = 0; t < 8; ++t) {
    workers.emplace_back([&] {
      while (running.load(std::memory_order_acquire)) {
        while (host.writer_pending.load(std::memory_order_acquire) &&
               running.load(std::memory_order_relaxed))
          std::this_thread::yield();
        pthread_rwlock_rdlock(&host.entry_gate);
        ++host.inside;
        const int value = target();
        --host.inside;
        pthread_rwlock_unlock(&host.entry_gate);
        if (value != 7 && value != 99)
          ++errors;
      }
    });
  }
  bool okay = true;
  const auto exclusive = reinterpret_cast<const DobbyHookOptions *>(&options);

  DobbyHookOptions unguarded{sizeof(unguarded), DOBBY_BRANCH_FORCE_LONG,
                            DOBBY_HOOK_REQUIRE_CONCURRENT_SAFE, 0, code,
                            reinterpret_cast<dobby_dummy_func_t>(Replacement)};
  auto unsafe = Result();
  okay &= Assert(DobbyPrepareHook(&unguarded, &unsafe) == RS_FAILED &&
                    unsafe.status == DOBBY_HOOK_CONCURRENCY_UNSUPPORTED &&
                    unsafe.handle == 0 && memcmp(code, original, sizeof(original)) == 0,
                 "unmanaged x64 entry rejects before patching");

  // A host unable to park all entrants MUST fail without publishing bytes.
  auto result = Result();
  okay &= Assert(DobbyPrepareHook(exclusive, &result) == RS_SUCCESS, "prepare lease rejection");
  const auto rejected_ticket = result.handle;
  host.deny_next = true;
  result = Result();
  okay &= Assert(DobbyCommitHook(rejected_ticket, &result) == RS_FAILED &&
                    result.status == DOBBY_HOOK_CONCURRENCY_UNSUPPORTED &&
                    !result.ever_published && result.handle == rejected_ticket &&
                    memcmp(code, original, sizeof(original)) == 0,
                  "failed lease leaves original bytes and prepared ownership intact");
  auto aborted = Result();
  okay &= Assert(DobbyAbortHook(rejected_ticket, &aborted) == RS_SUCCESS, "abort uncommitted lease");

  // The backend reports an error after an otherwise successful text write.
  // Ownership and executable metadata must outlive the failed Commit, and
  // recovery must acquire a fresh exclusive lease before restoring bytes.
  auto injected = Result();
  okay &= Assert(DobbyPrepareHook(exclusive, &injected) == RS_SUCCESS, "prepare injected patch failure");
  const auto injected_ticket = injected.handle;
  g_fault_target = code;
  g_fail_after_patch.store(true);
  injected = Result();
  okay &= Assert(DobbyCommitHook(injected_ticket, &injected) == RS_FAILED &&
                    injected.status == DOBBY_HOOK_RECOVERY_REQUIRED &&
                    injected.handle == injected_ticket && injected.ever_published &&
                    target() == 99,
                 "published failure retains exact ticket");
  injected = Result();
  okay &= Assert(DobbyRecoverHook(injected_ticket, &injected) == RS_SUCCESS &&
                    injected.restored_and_synchronized && target() == 7 &&
                    Interceptor::SharedInstance()->count() == 0,
                 "rollback uses a fresh lease and synchronized restoration");
  g_fault_target = nullptr;

  for (int i = 0; okay && i < 150; ++i) {
    result = Result();
    if (DobbyPrepareHook(exclusive, &result) != RS_SUCCESS || !result.original ||
        reinterpret_cast<Target>(result.original)() != 7) {
      okay = Assert(false, "prepared original trampoline");
      break;
    }
    const auto ticket = result.handle;
    result = Result();
    if (DobbyCommitHook(ticket, &result) != RS_SUCCESS || target() != 99) {
      okay = Assert(false, "quiescent commit");
      break;
    }
    if (i == 0) {
      host.deny_next = true;
      auto refused = Result();
      okay &= Assert(DobbyDestroyHook(ticket, &refused) == RS_FAILED &&
                        refused.status == DOBBY_HOOK_RECOVERY_REQUIRED &&
                        refused.handle == ticket && target() == 99,
                     "failed destroy lease retains installed ownership");
      if (!okay)
        break;
    }
    result = Result();
    if (DobbyDestroyHook(ticket, &result) != RS_SUCCESS || target() != 7 ||
        memcmp(code, original, sizeof(original)) != 0) {
      okay = Assert(false, "quiescent destroy");
      break;
    }
  }
  running = false;
  for (auto &worker : workers)
    worker.join();

  // A foreign writer can modify bytes in the stolen-prologue tail that lie
  // beyond Dobby's physical trampoline. Destroy must reject rather than
  // restoring origin_insn_size bytes over that foreign modification.
  if (okay) {
    result = Result();
    okay &= Assert(DobbyPrepareHook(exclusive, &result) == RS_SUCCESS && result.handle != 0,
                   "prepare foreign-tail ownership fixture");
    const auto ticket = result.handle;
    const auto patch_size = result.patch_size;
    auto *entry = Interceptor::SharedInstance()->find(reinterpret_cast<addr_t>(code));
    okay &= Assert(entry != nullptr && entry->origin_insn_size > patch_size,
                   "x64 stolen span exceeds trampoline span");
    if (okay) {
      result = Result();
      okay &= Assert(DobbyCommitHook(ticket, &result) == RS_SUCCESS && target() == 99,
                     "commit foreign-tail ownership fixture");
    }
    if (okay) {
      auto *bytes = static_cast<uint8_t *>(code);
      const uint8_t expected_tail = original[patch_size];
      const uint8_t foreign_tail = static_cast<uint8_t>(expected_tail ^ 0x5a);
      bytes[patch_size] = foreign_tail;
      __builtin___clear_cache(reinterpret_cast<char *>(bytes + patch_size),
                              reinterpret_cast<char *>(bytes + patch_size + 1));

      auto rejected = Result();
      okay &= Assert(DobbyDestroyHook(ticket, &rejected) == RS_FAILED &&
                         rejected.status == DOBBY_HOOK_TARGET_CHANGED && rejected.handle == ticket &&
                         bytes[patch_size] == foreign_tail && target() == 99,
                     "destroy rejects foreign change in stolen-prologue tail");

      bytes[patch_size] = expected_tail;
      __builtin___clear_cache(reinterpret_cast<char *>(bytes + patch_size),
                              reinterpret_cast<char *>(bytes + patch_size + 1));
      auto removed = Result();
      okay &= Assert(DobbyDestroyHook(ticket, &removed) == RS_SUCCESS && target() == 7 &&
                         memcmp(code, original, sizeof(original)) == 0,
                     "destroy succeeds after tail ownership is restored");
    }
  }

  okay &= Assert(errors.load() == 0 && host.inside.load() == 0 &&
                    host.pauses.load() == host.resumes.load() &&
                    host.pauses.load() >= 2 &&
                    Interceptor::SharedInstance()->count() == 0 && target() == 7,
                  "all entrants quiesced and restored with balanced leases");
  munmap(code, page);
  pthread_rwlock_destroy(&host.entry_gate);
  printf("quiescence-x64 pauses=%d resumes=%d errors=%d result=%s\n",
         host.pauses.load(), host.resumes.load(), errors.load(), okay ? "PASS" : "FAIL");
  return okay ? 0 : 1;
#endif
}
