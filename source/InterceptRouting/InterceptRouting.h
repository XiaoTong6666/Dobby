#pragma once

#include "InterceptEntry.h"
#include "MemoryAllocator/AssemblyCodeBuilder.h"
#include "InstructionRelocation/InstructionRelocation.h"
#include "TrampolineBridge/Trampoline/Trampoline.h"

class InterceptRouting {
public:
  explicit InterceptRouting(InterceptEntry *entry) : entry_(entry) {
    entry->routing = this;

    origin_ = nullptr;
    relocated_ = nullptr;

    trampoline_ = nullptr;
    trampoline_buffer_ = nullptr;
    trampoline_target_ = 0;
  }

  virtual ~InterceptRouting() {
    // These are metadata objects; executable arena pages are intentionally
    // retained because the caller may still hold an original-function pointer.
    delete origin_;
    delete relocated_;
    delete trampoline_;
    delete trampoline_buffer_;
  }

  virtual bool DispatchRouting() = 0;

  virtual void Prepare();

  virtual bool Active();

  bool Commit();

  bool NearBranchUnavailable() const {
    return near_branch_unavailable_;
  }
  MemoryOperationError LastPatchError() const {
    return last_patch_error_;
  }
  void RecordPatchError(MemoryOperationError error) {
    last_patch_error_ = error;
  }

  InterceptEntry *GetInterceptEntry();

  void SetTrampolineBuffer(CodeBufferBase *buffer) {
    trampoline_buffer_ = buffer;
  }

  CodeBufferBase *GetTrampolineBuffer() {
    return trampoline_buffer_;
  }

  void SetTrampolineTarget(addr_t address) {
    trampoline_target_ = address;
  }

  addr_t GetTrampolineTarget() {
    return trampoline_target_;
  }

protected:
  bool GenerateRelocatedCode();

  bool GenerateTrampolineBuffer(addr_t src, addr_t dst);

protected:
  InterceptEntry *entry_;

  CodeMemBlock *origin_;
  CodeMemBlock *relocated_;

  CodeMemBlock *trampoline_;
  // trampoline buffer before active
  CodeBufferBase *trampoline_buffer_;
  addr_t trampoline_target_;
  bool near_branch_unavailable_ = false;
  MemoryOperationError last_patch_error_ = kMemoryOperationSuccess;
};
