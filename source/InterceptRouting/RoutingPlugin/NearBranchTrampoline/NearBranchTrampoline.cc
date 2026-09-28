#include "InterceptRouting/RoutingPlugin/NearBranchTrampoline/NearBranchTrampoline.h"

#include "dobby_internal.h"

#include "MemoryAllocator/NearMemoryAllocator.h"

#include "InterceptRouting/RoutingPlugin/RoutingPlugin.h"
#include "Interceptor.h"
#include <algorithm>

using namespace zz;

PUBLIC void dobby_enable_near_branch_trampoline() {
  std::lock_guard<std::recursive_mutex> guard(Interceptor::MutationMutex());
  if (RoutingPluginManager::near_branch_trampoline)
    return;
  RoutingPluginInterface *plugin = new NearBranchTrampolinePlugin;
  RoutingPluginManager::registerPlugin("near_branch_trampoline", plugin);
  RoutingPluginManager::near_branch_trampoline = plugin;
}

PUBLIC void dobby_disable_near_branch_trampoline() {
  std::lock_guard<std::recursive_mutex> guard(Interceptor::MutationMutex());
  dobby_require_near_branch_trampoline(false);
  NearBranchTrampolinePlugin *plugin = (NearBranchTrampolinePlugin *)RoutingPluginManager::near_branch_trampoline;
  auto &registered = RoutingPluginManager::plugins;
  registered.erase(std::remove(registered.begin(), registered.end(), plugin), registered.end());
  delete plugin;
  RoutingPluginManager::near_branch_trampoline = NULL;
}

#if 0
int NearBranchTrampolinePlugin::PredefinedTrampolineSize() {
#if __arm64__
  return 4;
#elif __arm__
  return 4;
#endif
}
#endif

extern CodeBufferBase *GenerateNearTrampolineBuffer(InterceptRouting *routing, addr_t from, addr_t to);
bool NearBranchTrampolinePlugin::GenerateTrampolineBuffer(InterceptRouting *routing, addr_t src, addr_t dst) {
  CodeBufferBase *trampoline_buffer;
  trampoline_buffer = GenerateNearTrampolineBuffer(routing, src, dst);
  if (trampoline_buffer == NULL)
    return false;
  routing->SetTrampolineBuffer(trampoline_buffer);
  return true;
}

// generate trampoline, patch the original entry
bool NearBranchTrampolinePlugin::Active(InterceptRouting *routing) {
  return true;
}
