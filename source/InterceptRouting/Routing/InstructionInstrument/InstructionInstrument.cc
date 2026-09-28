#include "dobby_internal.h"

#include "Interceptor.h"
#include "InterceptRouting/InterceptRouting.h"
#include "InterceptRouting/Routing/InstructionInstrument/InstructionInstrumentRouting.h"
#include "InterceptRouting/HookFailure.h"
#include <memory>

PUBLIC int DobbyInstrument(void *address, dobby_instrument_callback_t pre_handler) {
  std::lock_guard<std::recursive_mutex> mutation(Interceptor::MutationMutex());
  if (!address || !pre_handler) {
    ERROR_LOG("address is 0x0.\n");
    return RS_FAILED;
  }

#if defined(__APPLE__) && defined(__arm64__)
#if __has_feature(ptrauth_calls)
  address = ptrauth_strip(address, ptrauth_key_asia);
#endif
#endif

  DLOG(0, "\n\n----- [DobbyInstrument:%p] -----", address);

  auto entry = Interceptor::SharedInstance()->find((addr_t)address);
  if (entry) {
    ERROR_LOG("%s already been instrumented.", address);
    return RS_FAILED;
  }

  std::unique_ptr<InterceptEntry> pending(new InterceptEntry(kInstructionInstrument, (addr_t)address));
  entry = pending.get();

  auto routing = new InstructionInstrumentRouting(entry, pre_handler, nullptr);
  Interceptor::SharedInstance()->add(entry);
  routing->Prepare();
  if (!routing->DispatchRouting()) {
    Interceptor::SharedInstance()->remove(entry->patched_addr);
    return RS_FAILED;
  }
  if (!routing->Commit()) {
    if (DobbyOriginalBytesRestored(entry)) {
      Interceptor::SharedInstance()->remove(entry->patched_addr);
    } else {
      entry->state = InterceptEntryState::Removing;
      pending.release();
    }
    return RS_FAILED;
  }

  entry->state = InterceptEntryState::Active;
  pending.release();

  return RS_SUCCESS;
}
