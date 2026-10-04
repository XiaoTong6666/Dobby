#include "dobby_internal.h"
#include "Interceptor.h"
#include "InterceptRouting/HookFailure.h"
#include "InterceptRouting/QuiescenceGuard.h"

__attribute__((constructor)) static void ctor() {
  DLOG(-1, "================================");
  DLOG(-1, "Dobby");
  DLOG(-1, "================================");

  DLOG(-1, "dobby in debug log mode, disable with cmake flag \"-DDOBBY_DEBUG=OFF\"");
}

PUBLIC const char *DobbyGetVersion() {
  return __DOBBY_BUILD_VERSION__;
}

PUBLIC int DobbyDestroy(void *address) {
  std::lock_guard<std::recursive_mutex> mutation(Interceptor::MutationMutex());
#if defined(TARGET_ARCH_ARM)
  if ((addr_t)address % 2) {
    address = (void *)((addr_t)address - 1);
  }
#endif
  auto entry = Interceptor::SharedInstance()->find((addr_t)address);
  if (entry && (entry->state == InterceptEntryState::Active || entry->state == InterceptEntryState::Removing)) {
    DobbyScopedQuiescence exclusive(entry);
    if (!exclusive.Acquire())
      return RT_FAILED;
    // Validate ownership only after the trusted host has parked every entrant
    // participating in its quiescence protocol.  The compare must cover the
    // complete restore span, not merely Dobby's physical trampoline bytes,
    // because x86/x64 relocation can steal beyond the published patch.
    // A foreign engine that does not participate in the lease can still race
    // this operation; Dobby therefore guarantees fail-closed validation at
    // the lease boundary, not global mutual exclusion with arbitrary writers.
    if (entry->state == InterceptEntryState::Active && !DobbyInstalledEntryMatches(entry))
      return RT_FAILED;
    const auto prior_state = entry->state;
    entry->state = InterceptEntryState::Removing;
    uint8_t *buffer = entry->origin_insns;
    uint32_t buffer_size = entry->origin_insn_size;
    const auto patch_error = DobbyCodePatch(reinterpret_cast<void *>(entry->patched_addr), buffer, buffer_size);
    if (entry->routing)
      entry->routing->RecordPatchError(patch_error);
    if (patch_error != kMemoryOperationSuccess) {
      // A backend failure can be reported after the restoration bytes were
      // already published (for example a subsequent cache/synchronization
      // step failed).  In that case the physical entry may already contain
      // the original prologue, so marking the ticket Active again would make
      // the next Destroy treat our own partial removal as a foreign writer.
      // Retain exact ownership in Removing and require an explicit Recover;
      // only a failure that provably published no bytes can return to the
      // previous Active state.
      entry->state = DobbyLastPatchWasPublished() ? InterceptEntryState::Removing : prior_state;
      return RT_FAILED;
    }
    entry = Interceptor::SharedInstance()->remove(entry->logical_target);
    if (entry->type == kInstructionInstrument) {
      // Closure trampoline carries this pointer. Keep metadata valid for
      // in-flight callbacks; code arenas themselves are process-lifetime.
      Interceptor::SharedInstance()->retireInstrumentation(entry);
    } else {
      delete entry;
    }
    return RT_SUCCESS;
  }

  return RT_FAILED;
}
