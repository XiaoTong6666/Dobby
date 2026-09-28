#include "dobby_internal.h"

#include "Interceptor.h"
#include "InterceptRouting/Routing/FunctionInlineHook/FunctionInlineHookRouting.h"
#include "InterceptRouting/HookFailure.h"
#include <memory>

PUBLIC int DobbyHook(void *address, dobby_dummy_func_t replace_func, dobby_dummy_func_t *origin_func) {
  std::lock_guard<std::recursive_mutex> mutation(Interceptor::MutationMutex());
  if (origin_func) {
    *origin_func = nullptr;
  }
  if (!address || !replace_func) {
    ERROR_LOG("function address is 0x0");
    return RS_FAILED;
  }

#if defined(__APPLE__) && defined(__arm64__)
#if __has_feature(ptrauth_calls)
  address = ptrauth_strip(address, ptrauth_key_asia);
  replace_func = ptrauth_strip(replace_func, ptrauth_key_asia);
#endif
#endif

  DLOG(0, "----- [DobbyHook:%p] -----", address);

  // check if already register
  auto entry = Interceptor::SharedInstance()->find((addr_t)address);
  if (entry) {
    ERROR_LOG("%p already been hooked.", address);
    return RS_FAILED;
  }

  std::unique_ptr<InterceptEntry> pending(new InterceptEntry(kFunctionInlineHook, (addr_t)address));
  entry = pending.get();

  auto *routing = new FunctionInlineHookRouting(entry, replace_func);
  // Reserve this address while routing is being built; also prevents a
  // callback re-entering DobbyHook for the same address on this thread.
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
      pending.release(); // retain metadata until DobbyDestroy retries restoration
    }
    return RS_FAILED;
  }

  entry->state = InterceptEntryState::Active;

  // Do not publish a trampoline for a hook that did not install successfully.
  if (origin_func) {
    *origin_func = (dobby_dummy_func_t)entry->relocated_addr;
  }
  pending.release();

  return RS_SUCCESS;
}
