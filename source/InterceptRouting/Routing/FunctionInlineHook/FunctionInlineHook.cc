#include "dobby_internal.h"

#include "Interceptor.h"
#include "InterceptRouting/Routing/FunctionInlineHook/FunctionInlineHookRouting.h"
#include "InterceptRouting/HookFailure.h"
#include "InterceptRouting/QuiescenceGuard.h"

#include <memory>

namespace {

// All callers hold MutationMutex, including the legacy one-shot wrapper.
// Numeric tickets avoid a dangling opaque pointer after an address-based
// Destroy, Abort, or subsequent reuse of the same target address.
uint64_t g_next_transaction_id = 1;

InterceptEntry *FindTransaction(DobbyHookHandle handle) {
  if (!handle)
    return nullptr;
  auto *interceptor = Interceptor::SharedInstance();
  for (int i = 0; i < interceptor->count(); ++i) {
    auto *entry = const_cast<InterceptEntry *>(interceptor->getEntry(i));
    if (entry && entry->transaction_id == handle && entry->type == kFunctionInlineHook)
      return entry;
  }
  return nullptr;
}

bool ResetResult(DobbyHookResult *result) {
  if (!result || result->struct_size < sizeof(DobbyHookResult))
    return false;
  memset(result, 0, sizeof(*result));
  result->struct_size = sizeof(*result);
  return true;
}

int Fail(DobbyHookResult *result, DobbyHookStatus status, DobbyHookStatus cause = DOBBY_HOOK_OK) {
  if (result) {
    result->status = status;
    result->cause = cause == DOBBY_HOOK_OK ? status : cause;
  }
  return RS_FAILED;
}

DobbyHookStatus PatchCause(MemoryOperationError error) {
  switch (error) {
  case kInstructionSyncUnavailable:
    return DOBBY_HOOK_SYNC_UNAVAILABLE;
  case kInstructionSyncFailed:
    return DOBBY_HOOK_SYNC_FAILED;
  default:
    return DOBBY_HOOK_PATCH_FAILED;
  }
}

// The original branch is safe for concurrent execution only if its entire
// entry patch is one aligned atomic A64 instruction. Cross-core instruction
// synchronization is separately required by DobbyCodePatch on Linux/Android.
bool CanCommitConcurrently(const InterceptEntry *entry) {
#if defined(TARGET_ARCH_ARM64) && (defined(__ANDROID__) || defined(__linux__))
  return entry && entry->routing && entry->routing->GetTrampolineBuffer() &&
         entry->routing->GetTrampolineBuffer()->GetBufferSize() == sizeof(uint32_t) && (entry->patched_addr & 3u) == 0;
#elif defined(TARGET_ARCH_X64) && (defined(__ANDROID__) || defined(__linux__))
  return entry && entry->quiescence_acquire && entry->quiescence_release &&
         entry->origin_insn_size && entry->origin_insn_size <= sizeof(entry->origin_insns);
#else
  (void)entry;
  return false; // The x64 5-byte jump and other multi-byte patches are not atomic.
#endif
}

} // namespace

PUBLIC int DobbyPrepareHook(const DobbyHookOptions *options, DobbyHookResult *result) {
  std::lock_guard<std::recursive_mutex> mutation(Interceptor::MutationMutex());
  if (!ResetResult(result))
    return RS_FAILED;
  if (!options || options->struct_size < sizeof(DobbyHookOptions) || !options->target || !options->replacement ||
      options->reserved || options->branch_policy > DOBBY_BRANCH_FORCE_LONG ||
      (options->flags & ~DOBBY_HOOK_REQUIRE_CONCURRENT_SAFE))
    return Fail(result, DOBBY_HOOK_INVALID_ARGUMENT);
  if (options->struct_size > sizeof(DobbyHookOptions) &&
      options->struct_size < sizeof(DobbyHookOptionsQuiescentV2))
    return Fail(result, DOBBY_HOOK_INVALID_ARGUMENT);
  const auto *exclusive = options->struct_size >= sizeof(DobbyHookOptionsQuiescentV2)
                              ? reinterpret_cast<const DobbyHookOptionsQuiescentV2 *>(options) : nullptr;
  if (exclusive) {
#if defined(TARGET_ARCH_X64) && (defined(__ANDROID__) || defined(__linux__))
    if (!(options->flags & DOBBY_HOOK_REQUIRE_CONCURRENT_SAFE) ||
        !exclusive->acquire || !exclusive->release)
      return Fail(result, DOBBY_HOOK_INVALID_ARGUMENT);
#else
    return Fail(result, DOBBY_HOOK_INVALID_ARGUMENT);
#endif
  }

  void *address = options->target;
  dobby_dummy_func_t replacement = options->replacement;
#if defined(__APPLE__) && defined(__arm64__)
#if __has_feature(ptrauth_calls)
  address = ptrauth_strip(address, ptrauth_key_asia);
  replacement = ptrauth_strip(replacement, ptrauth_key_asia);
#endif
#endif

  if (Interceptor::SharedInstance()->find((addr_t)address))
    return Fail(result, DOBBY_HOOK_TARGET_BUSY);
  if (!DobbyEnsureInstructionSync())
    return Fail(result, DOBBY_HOOK_SYNC_UNAVAILABLE);
  if (g_next_transaction_id == 0)
    return Fail(result, DOBBY_HOOK_INVALID_STATE); // Never reuse wrapped tickets.

  std::unique_ptr<InterceptEntry> pending(new InterceptEntry(kFunctionInlineHook, (addr_t)address));
  auto *entry = pending.get();
  entry->transaction_id = g_next_transaction_id++;
  entry->branch_policy = options->branch_policy;
  entry->hook_flags = options->flags;
  if (exclusive) {
    entry->quiescence_user_data = exclusive->user_data;
    entry->quiescence_acquire = exclusive->acquire;
    entry->quiescence_release = exclusive->release;
  }
  auto *routing = new FunctionInlineHookRouting(entry, replacement);

  // Reserve BEFORE relocation. Another thread's Prepare or legacy DobbyHook
  // must reject this address while the caller is preparing its publication gate.
  Interceptor::SharedInstance()->add(entry);
  routing->Prepare();
  if (!routing->DispatchRouting() || !entry->relocated_addr) {
    const bool near_unavailable = routing->NearBranchUnavailable();
    Interceptor::SharedInstance()->remove(entry->patched_addr);
    return Fail(result, near_unavailable ? DOBBY_HOOK_NEAR_UNAVAILABLE : DOBBY_HOOK_RELOCATION_FAILED);
  }
  if ((options->flags & DOBBY_HOOK_REQUIRE_CONCURRENT_SAFE) && !CanCommitConcurrently(entry)) {
    Interceptor::SharedInstance()->remove(entry->patched_addr);
    return Fail(result, DOBBY_HOOK_CONCURRENCY_UNSUPPORTED);
  }

  result->handle = entry->transaction_id;
  result->original = reinterpret_cast<dobby_dummy_func_t>(entry->relocated_addr);
  result->patch_size = static_cast<uint32_t>(entry->routing->GetTrampolineBuffer()->GetBufferSize());
#if defined(TARGET_ARCH_ARM64)
  result->selected_branch =
      result->patch_size == sizeof(uint32_t) ? DOBBY_BRANCH_REQUIRE_NEAR : DOBBY_BRANCH_FORCE_LONG;
#else
  result->selected_branch = DOBBY_BRANCH_FORCE_LONG;
#endif
  result->status = DOBBY_HOOK_OK;
  pending.release();
  return RS_SUCCESS;
}

PUBLIC int DobbyCommitHook(DobbyHookHandle handle, DobbyHookResult *result) {
  std::lock_guard<std::recursive_mutex> mutation(Interceptor::MutationMutex());
  if (!ResetResult(result))
    return RS_FAILED;
  auto *entry = FindTransaction(handle);
  if (!entry)
    return Fail(result, DOBBY_HOOK_INVALID_HANDLE);
  if (entry->state != InterceptEntryState::Installing)
    return Fail(result, DOBBY_HOOK_INVALID_STATE);

  result->handle = handle;
  result->original = reinterpret_cast<dobby_dummy_func_t>(entry->relocated_addr);
  result->patch_size = static_cast<uint32_t>(entry->routing->GetTrampolineBuffer()->GetBufferSize());
#if defined(TARGET_ARCH_ARM64)
  result->selected_branch =
      result->patch_size == sizeof(uint32_t) ? DOBBY_BRANCH_REQUIRE_NEAR : DOBBY_BRANCH_FORCE_LONG;
#else
  result->selected_branch = DOBBY_BRANCH_FORCE_LONG;
#endif
  DobbyScopedQuiescence exclusive(entry);
  if (!exclusive.Acquire())
    return Fail(result, exclusive.SyncUnavailable() ? DOBBY_HOOK_SYNC_UNAVAILABLE
                                                   : DOBBY_HOOK_CONCURRENCY_UNSUPPORTED);
  // Prepare can outlive the caller's loader activity. Refuse to overwrite a
  // target whose original bytes were modified or unmapped in that interval.
  // The caller still owns a never-published handle and must Abort it.
  if (!DobbyOriginalEntryMatches(entry))
    return Fail(result, DOBBY_HOOK_TARGET_CHANGED);
  if (!entry->routing->Commit()) {
    const auto cause = PatchCause(entry->routing->LastPatchError());
    result->ever_published = DobbyLastPatchWasPublished();
    if (DobbyOriginalBytesRestored(entry)) {
      Interceptor::SharedInstance()->remove(entry->patched_addr);
      delete entry;
      result->handle = 0;
      result->original = nullptr;
      result->restored_and_synchronized = 1;
      return Fail(result, cause);
    }
    entry->state = InterceptEntryState::Removing;
    result->target_may_be_patched = 1;
    return Fail(result, DOBBY_HOOK_RECOVERY_REQUIRED, cause);
  }
  entry->state = InterceptEntryState::Active;
  result->target_may_be_patched = 1;
  result->ever_published = 1;
  result->status = DOBBY_HOOK_OK;
  return RS_SUCCESS;
}

PUBLIC int DobbyAbortHook(DobbyHookHandle handle, DobbyHookResult *result) {
  std::lock_guard<std::recursive_mutex> mutation(Interceptor::MutationMutex());
  if (!ResetResult(result))
    return RS_FAILED;
  auto *entry = FindTransaction(handle);
  if (!entry)
    return Fail(result, DOBBY_HOOK_INVALID_HANDLE);
  if (entry->state != InterceptEntryState::Installing)
    return Fail(result, DOBBY_HOOK_INVALID_STATE);
  Interceptor::SharedInstance()->remove(entry->patched_addr);
  delete entry;
  result->restored_and_synchronized = 1; // Target was never patched.
  return RS_SUCCESS;
}

PUBLIC int DobbyDestroyHook(DobbyHookHandle handle, DobbyHookResult *result) {
  std::lock_guard<std::recursive_mutex> mutation(Interceptor::MutationMutex());
  if (!ResetResult(result))
    return RS_FAILED;
  auto *entry = FindTransaction(handle);
  if (!entry)
    return Fail(result, DOBBY_HOOK_INVALID_HANDLE);
  if (entry->state == InterceptEntryState::Installing)
    return Fail(result, DOBBY_HOOK_INVALID_STATE);
  const void *address = reinterpret_cast<void *>(entry->patched_addr);
  if (DobbyDestroy(const_cast<void *>(address)) != RS_SUCCESS) {
    result->handle = handle;
    result->target_may_be_patched = 1;
    const DobbyHookStatus cause =
        entry->routing ? PatchCause(entry->routing->LastPatchError()) : DOBBY_HOOK_PATCH_FAILED;
    return Fail(result, DOBBY_HOOK_RECOVERY_REQUIRED, cause);
  }
  result->restored_and_synchronized = 1;
  return RS_SUCCESS;
}

PUBLIC int DobbyRecoverHook(DobbyHookHandle handle, DobbyHookResult *result) {
  std::lock_guard<std::recursive_mutex> mutation(Interceptor::MutationMutex());
  if (!ResetResult(result))
    return RS_FAILED;
  auto *entry = FindTransaction(handle);
  if (!entry)
    return Fail(result, DOBBY_HOOK_INVALID_HANDLE);
  if (entry->state != InterceptEntryState::Removing)
    return Fail(result, DOBBY_HOOK_INVALID_STATE);
  result->struct_size = sizeof(*result);
  return DobbyDestroyHook(handle, result);
}

PUBLIC int DobbyHook(void *address, dobby_dummy_func_t replace_func, dobby_dummy_func_t *origin_func) {
  // Hold the same lock across both phases to preserve the legacy one-shot
  // ordering. Unlike the new API it cannot publish a caller-owned backup
  // before commit; self-reentrant callbacks must use Prepare/Commit.
  std::lock_guard<std::recursive_mutex> mutation(Interceptor::MutationMutex());
  if (origin_func)
    *origin_func = nullptr;
  DobbyHookOptions options = {sizeof(options), DOBBY_BRANCH_LEGACY, 0, 0, address, replace_func};
  DobbyHookResult result = {sizeof(result)};
  if (DobbyPrepareHook(&options, &result) != RS_SUCCESS)
    return RS_FAILED;
  const auto handle = result.handle;
  if (DobbyCommitHook(handle, &result) != RS_SUCCESS)
    return RS_FAILED;
  if (origin_func)
    *origin_func = result.original;
  return RS_SUCCESS;
}
