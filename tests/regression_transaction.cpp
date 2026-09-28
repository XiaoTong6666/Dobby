#include "dobby.h"
#include "Interceptor.h"

#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

#if defined(__x86_64__)
using Fn = int (*)();
static Fn g_backup = nullptr;
static void *g_target = nullptr;
static bool g_inject_partial_commit = false;

extern "C" MemoryOperationError __real_DobbyCodePatch(void *, uint8_t *, uint32_t);
extern "C" MemoryOperationError __wrap_DobbyCodePatch(void *address, uint8_t *bytes, uint32_t size) {
  auto rc = __real_DobbyCodePatch(address, bytes, size);
  if (address == g_target && g_inject_partial_commit && rc == kMemoryOperationSuccess) {
    g_inject_partial_commit = false;
    // The target is already executing the replacement. The caller must retain
    // its handle even when Commit returns a failure.
    return kMemoryOperationError;
  }
  return rc;
}

static int Replacement() { return g_backup ? g_backup() + 92 : -1000; }
static DobbyHookOptions Options(void *target, uint32_t branch = DOBBY_BRANCH_FORCE_LONG, uint32_t flags = 0) {
  DobbyHookOptions options = {sizeof(options), branch, flags, 0, target,
                              reinterpret_cast<dobby_dummy_func_t>(Replacement)};
  return options;
}
static DobbyHookResult Result() {
  DobbyHookResult result = {sizeof(result)};
  return result;
}
static bool Expect(bool pass, const char *case_name) {
  if (!pass)
    fprintf(stderr, "transaction: FAIL %s\n", case_name);
  return pass;
}
#endif

int main() {
#if !defined(__x86_64__)
  return 0;
#else
  const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  auto *code = static_cast<uint8_t *>(mmap(nullptr, page, PROT_READ | PROT_WRITE | PROT_EXEC,
                                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  if (code == MAP_FAILED) return 2;
  constexpr uint8_t original[] = {0xb8, 0x07, 0x00, 0x00, 0x00, 0xc3, 0x90, 0x90,
                                   0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
  memcpy(code, original, sizeof(original));
  g_target = code;
  const auto target = reinterpret_cast<Fn>(code);
  auto opts = Options(code);
  auto result = Result();
  bool okay = true;

  okay &= Expect(DobbyPrepareHook(&opts, &result) == RS_SUCCESS && result.handle &&
                     result.original && result.status == DOBBY_HOOK_OK &&
                     result.patch_size > 4 && result.selected_branch == DOBBY_BRANCH_FORCE_LONG &&
                     target() == 7 && memcmp(code, original, sizeof(original)) == 0 &&
                     Interceptor::SharedInstance()->count() == 1,
                 "prepare reserves target without modifying its bytes");
  if (!okay) return 1;
  auto first = result.handle;
  auto backup = reinterpret_cast<Fn>(result.original);
  okay &= Expect(backup() == 7, "original callable before commit");
  auto second_result = Result();
  auto duplicate = reinterpret_cast<dobby_dummy_func_t>(1);
  okay &= Expect(DobbyHook(code, opts.replacement, &duplicate) == RS_FAILED && duplicate == nullptr &&
                     DobbyPrepareHook(&opts, &second_result) == RS_FAILED &&
                     second_result.status == DOBBY_HOOK_TARGET_BUSY,
                 "pending target is reserved against legacy and transaction callers");

  auto abort_result = Result();
  okay &= Expect(DobbyAbortHook(first, &abort_result) == RS_SUCCESS &&
                     abort_result.restored_and_synchronized && !abort_result.handle &&
                     target() == 7 && Interceptor::SharedInstance()->count() == 0,
                 "abort releases an unpublished target");
  auto stale = Result();
  okay &= Expect(DobbyCommitHook(first, &stale) == RS_FAILED &&
                     stale.status == DOBBY_HOOK_INVALID_HANDLE,
                 "stale ticket rejected");

  // The caller may keep a Prepared handle across linker activity. Detect a
  // changed prologue before any destructive Commit, then allow explicit
  // Abort without overwriting the independent mutation.
  result = Result();
  okay &= Expect(DobbyPrepareHook(&opts, &result) == RS_SUCCESS,
                 "prepare for target-change rejection");
  const auto changed_ticket = result.handle;
  code[0] = 0x90;
  auto changed = Result();
  okay &= Expect(DobbyCommitHook(changed_ticket, &changed) == RS_FAILED &&
                     changed.status == DOBBY_HOOK_TARGET_CHANGED &&
                     changed.handle == changed_ticket &&
                     !changed.ever_published && !changed.target_may_be_patched &&
                     code[0] == 0x90 && Interceptor::SharedInstance()->count() == 1,
                 "changed target cannot be overwritten after prepare");
  abort_result = Result();
  okay &= Expect(DobbyAbortHook(changed_ticket, &abort_result) == RS_SUCCESS &&
                     Interceptor::SharedInstance()->count() == 0 && code[0] == 0x90,
                 "abort never restores somebody else's modification");
  code[0] = original[0];

  result = Result();
  okay &= Expect(DobbyPrepareHook(&opts, &result) == RS_SUCCESS && result.handle != first &&
                     reinterpret_cast<Fn>(result.original)() == 7,
                 "new incarnation receives a different ticket");
  const auto current = result.handle;
  g_backup = reinterpret_cast<Fn>(result.original); // Publish before commit.
  auto invalid_abort = Result();
  okay &= Expect(DobbyCommitHook(current, &result) == RS_SUCCESS && result.status == DOBBY_HOOK_OK &&
                     result.handle == current && result.target_may_be_patched &&
                     result.patch_size > 4 && result.selected_branch == DOBBY_BRANCH_FORCE_LONG &&
                     target() == 99 && g_backup() == 7,
                 "commit observes caller-published backup");
  okay &= Expect(DobbyAbortHook(current, &invalid_abort) == RS_FAILED &&
                     invalid_abort.status == DOBBY_HOOK_INVALID_STATE,
                 "committed hook cannot be aborted");
  auto second_commit = Result();
  okay &= Expect(DobbyCommitHook(current, &second_commit) == RS_FAILED &&
                     second_commit.status == DOBBY_HOOK_INVALID_STATE,
                 "double commit rejected");
  auto destroyed = Result();
  okay &= Expect(DobbyDestroyHook(current, &destroyed) == RS_SUCCESS &&
                     destroyed.restored_and_synchronized && target() == 7 &&
                     g_backup() == 7 && Interceptor::SharedInstance()->count() == 0,
                 "destroy retains published original trampoline");
  stale = Result();
  okay &= Expect(DobbyDestroyHook(current, &stale) == RS_FAILED &&
                     stale.status == DOBBY_HOOK_INVALID_HANDLE,
                 "destroyed ticket is invalid");

  // A legacy address-based Destroy must also invalidate the ticket.
  result = Result();
  okay &= Expect(DobbyPrepareHook(&opts, &result) == RS_SUCCESS, "prepare address destroy");
  const auto external = result.handle;
  g_backup = reinterpret_cast<Fn>(result.original);
  okay &= Expect(DobbyCommitHook(external, &result) == RS_SUCCESS &&
                     DobbyDestroy(code) == RS_SUCCESS,
                 "address destroy works for committed transaction");
  stale = Result();
  okay &= Expect(DobbyCommitHook(external, &stale) == RS_FAILED &&
                     stale.status == DOBBY_HOOK_INVALID_HANDLE,
                 "address destroy invalidates ticket");

  // Concurrent-safety policy cannot turn the x64 multi-byte entry into an
  // atomic patch. RequireNear on x64 is also unsupported; neither may write
  // the original bytes or reserve the target.
  opts = Options(code, DOBBY_BRANCH_FORCE_LONG, DOBBY_HOOK_REQUIRE_CONCURRENT_SAFE);
  result = Result();
  okay &= Expect(DobbyPrepareHook(&opts, &result) == RS_FAILED &&
                     result.status == DOBBY_HOOK_CONCURRENCY_UNSUPPORTED &&
                     memcmp(code, original, sizeof(original)) == 0 &&
                     Interceptor::SharedInstance()->count() == 0,
                 "x64 unsafe long patch fails closed");
  opts = Options(code, DOBBY_BRANCH_REQUIRE_NEAR);
  result = Result();
  okay &= Expect(DobbyPrepareHook(&opts, &result) == RS_FAILED &&
                     result.status == DOBBY_HOOK_NEAR_UNAVAILABLE &&
                     memcmp(code, original, sizeof(original)) == 0,
                 "x64 require near does not fall back to long");

  opts = Options(code);
  g_inject_partial_commit = true;
  result = Result();
  okay &= Expect(DobbyPrepareHook(&opts, &result) == RS_SUCCESS, "prepare injected failure");
  const auto recover_handle = result.handle;
  auto failure = Result();
  okay &= Expect(DobbyCommitHook(recover_handle, &failure) == RS_FAILED &&
                     failure.status == DOBBY_HOOK_RECOVERY_REQUIRED &&
                     failure.handle == recover_handle && failure.target_may_be_patched &&
                     failure.ever_published &&
                     Interceptor::SharedInstance()->count() == 1,
                 "partially published failure retains ownership");
  second_result = Result();
  okay &= Expect(DobbyPrepareHook(&opts, &second_result) == RS_FAILED &&
                     second_result.status == DOBBY_HOOK_TARGET_BUSY,
                 "partial commit blocks replacement");
  abort_result = Result();
  okay &= Expect(DobbyAbortHook(recover_handle, &abort_result) == RS_FAILED &&
                     abort_result.status == DOBBY_HOOK_INVALID_STATE,
                 "partially committed target cannot be aborted");
  auto recovered = Result();
  okay &= Expect(DobbyRecoverHook(recover_handle, &recovered) == RS_SUCCESS &&
                     recovered.restored_and_synchronized &&
                     target() == 7 && Interceptor::SharedInstance()->count() == 0,
                 "explicit recovery restores target and unregisters owner");
  stale = Result();
  okay &= Expect(DobbyRecoverHook(recover_handle, &stale) == RS_FAILED &&
                     stale.status == DOBBY_HOOK_INVALID_HANDLE,
                 "recovered ticket invalidated");
  munmap(code, page);
  printf("transaction: result=%s\n", okay ? "PASS" : "FAIL");
  return okay ? 0 : 1;
#endif
}
