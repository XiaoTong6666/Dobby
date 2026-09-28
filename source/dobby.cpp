#include "dobby_internal.h"
#include "Interceptor.h"

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
    const auto prior_state = entry->state;
    entry->state = InterceptEntryState::Removing;
    uint8_t *buffer = entry->origin_insns;
    uint32_t buffer_size = entry->origin_insn_size;
    const auto patch_error = DobbyCodePatch(address, buffer, buffer_size);
    if (entry->routing)
      entry->routing->RecordPatchError(patch_error);
    if (patch_error != kMemoryOperationSuccess) {
      entry->state = prior_state;
      return RT_FAILED;
    }
    entry = Interceptor::SharedInstance()->remove((addr_t)address);
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
