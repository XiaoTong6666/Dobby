#include "dobby_internal.h"

#include "InterceptRouting/InterceptRouting.h"
#include "InterceptRouting/RoutingPlugin/RoutingPlugin.h"
#include "InterceptRouting/RoutingPlugin/NearBranchTrampoline/NearBranchTrampoline.h"
#include "Interceptor.h"

using namespace zz;

static bool g_near_trampoline_required = false;

bool NearBranchTrampolineRequired() {
  std::lock_guard<std::recursive_mutex> guard(Interceptor::MutationMutex());
  return g_near_trampoline_required;
}

PUBLIC void dobby_require_near_branch_trampoline(bool required) {
  std::lock_guard<std::recursive_mutex> guard(Interceptor::MutationMutex());
  g_near_trampoline_required = required;
#if defined(DOBBY_HAS_NEAR_BRANCH_TRAMPOLINE)
  if (required)
    dobby_enable_near_branch_trampoline();
#endif
}

void log_hex_format(uint8_t *buffer, uint32_t buffer_size) {
  char output[1024] = {0};
  for (uint32_t i = 0; i < buffer_size; i++) {
    size_t offset = strlen(output);
    if (offset + 4 > sizeof(output)) {
      break;
    }
    snprintf(output + offset, sizeof(output) - offset, "%02x ", buffer[i]);
  }
  DLOG(0, "%s", output);
};

void InterceptRouting::Prepare() {
}

// generate relocated code
bool InterceptRouting::GenerateRelocatedCode() {
  uint32_t tramp_size = GetTrampolineBuffer()->GetBufferSize();
  origin_ = new CodeMemBlock(entry_->patched_addr, tramp_size);
  relocated_ = new CodeMemBlock();

  auto buffer = (void *)entry_->patched_addr;
#if defined(TARGET_ARCH_ARM)
  if (entry_->thumb_mode) {
    buffer = (void *)((addr_t)buffer + 1);
  }
#endif
  GenRelocateCodeAndBranch(buffer, origin_, relocated_);
  if (relocated_->size == 0) {
    ERROR_LOG("[insn relocate]] failed");
    return false;
  }
  if (origin_->size > sizeof(entry_->origin_insns)) {
    ERROR_LOG("[insn relocate] stolen prologue exceeds backup capacity");
    return false;
  }

  // set the relocated instruction address
  entry_->relocated_addr = relocated_->addr;

  // save original prologue
  memcpy((void *)entry_->origin_insns, (void *)origin_->addr, origin_->size);
  entry_->origin_insn_size = origin_->size;

  // log
  DLOG(0, "[insn relocate] origin %p - %d", origin_->addr, origin_->size);
  log_hex_format((uint8_t *)origin_->addr, origin_->size);

  DLOG(0, "[insn relocate] relocated %p - %d", relocated_->addr, relocated_->size);
  log_hex_format((uint8_t *)relocated_->addr, relocated_->size);

  return true;
}

bool InterceptRouting::GenerateTrampolineBuffer(addr_t src, addr_t dst) {
  // if near branch trampoline plugin enabled
  if (RoutingPluginManager::near_branch_trampoline) {
    auto plugin = static_cast<RoutingPluginInterface *>(RoutingPluginManager::near_branch_trampoline);
    if (plugin->GenerateTrampolineBuffer(this, src, dst) == false) {
      DLOG(0, "Failed enable near branch trampoline plugin");
      if (NearBranchTrampolineRequired())
        return false;
    }
  }
  if (!RoutingPluginManager::near_branch_trampoline && NearBranchTrampolineRequired())
    return false;

  if (GetTrampolineBuffer() == nullptr) {
    auto tramp_buffer = GenerateNormalTrampolineBuffer(src, dst);
    SetTrampolineBuffer(tramp_buffer);
  }
  return GetTrampolineBuffer() != nullptr;
}

// active routing, patch origin instructions as trampoline
bool InterceptRouting::Active() {
  MemoryOperationError err;
  err = DobbyCodePatch((void *)entry_->patched_addr, trampoline_buffer_->GetBuffer(),
                       trampoline_buffer_->GetBufferSize());
  if (err != kMemoryOperationSuccess) {
    ERROR_LOG("[intercept routing] active failed");
    return false;
  }
  DLOG(0, "[intercept routing] active");
  return true;
}

bool InterceptRouting::Commit() {
  return this->Active();
}

#if 0
int InterceptRouting::PredefinedTrampolineSize() {
#if __arm64__
  return 12;
#elif __arm__
  return 8;
#endif
}
#endif

InterceptEntry *InterceptRouting::GetInterceptEntry() {
  return entry_;
};
