#pragma once

#include "InterceptEntry.h"
#include "PlatformUnifiedInterface/ExecMemory/CodePatchTool.h"

// This protocol is deliberately opt-in and scoped to trusted hosts. Dobby
// cannot inspect all user-space control flow to prove that a foreign runtime
// has stopped thread creation and all possible execution paths into target.
// A false or unavailable lease must reject before modifying the entry.
class DobbyScopedQuiescence {
public:
  explicit DobbyScopedQuiescence(const InterceptEntry *entry)
      : user_data_(entry ? entry->quiescence_user_data : nullptr),
        acquire_(entry ? entry->quiescence_acquire : nullptr),
        release_(entry ? entry->quiescence_release : nullptr),
        target_(entry ? reinterpret_cast<void *>(entry->patched_addr) : nullptr),
        size_(entry ? entry->origin_insn_size : 0) {}
  DobbyScopedQuiescence(const DobbyScopedQuiescence &) = delete;
  DobbyScopedQuiescence &operator=(const DobbyScopedQuiescence &) = delete;

  bool Acquire() {
    if (!acquire_)
      return true;
    if (!DobbyEnsureExclusiveInstructionSync()) {
      sync_unavailable_ = true;
      return false;
    }
    if (!acquire_(user_data_, target_, size_))
      return false;
    active_ = true;
    DobbySetExclusiveInstructionSync(true);
    return true;
  }
  bool SyncUnavailable() const { return sync_unavailable_; }
  ~DobbyScopedQuiescence() {
    if (active_) {
      // The physical patch, rollback and SYNC_CORE must finish before the
      // host resumes any execution capable of entering the overwritten span.
      DobbySetExclusiveInstructionSync(false);
      release_(user_data_);
    }
  }

private:
  // The transaction can delete its InterceptEntry before this RAII guard
  // exits. Copy lease callbacks and context, never dereference entry_ here.
  void *user_data_;
  int (*acquire_)(void *, void *, uint32_t);
  void (*release_)(void *);
  void *target_;
  uint32_t size_;
  bool active_ = false;
  bool sync_unavailable_ = false;
};
