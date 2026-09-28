#pragma once

#include <stdint.h>
#include "common_header.h"

typedef enum { kFunctionInlineHook, kInstructionInstrument } InterceptEntryType;

class InterceptRouting;
enum class InterceptEntryState { Installing, Active, Removing };

typedef struct InterceptEntry {
  uint32_t id;
  uint64_t transaction_id;
  InterceptEntryType type;
  InterceptRouting *routing;
  InterceptEntryState state;

  union {
    addr_t addr;
    addr_t patched_addr;
  };
  uint32_t patched_size;

  addr_t relocated_addr;
  uint32_t relocated_size;

  uint8_t origin_insns[256];
  uint32_t origin_insn_size;

  bool thumb_mode;
  uint32_t branch_policy; // DobbyHookBranchPolicy, per target
  uint32_t hook_flags;
  // Copied out of DobbyHookOptionsQuiescentV2; never retain caller's stack
  // options struct. Only valid for process-wide managed execution hosts.
  void *quiescence_user_data;
  int (*quiescence_acquire)(void *, void *, uint32_t);
  void (*quiescence_release)(void *);

  InterceptEntry(InterceptEntryType type, addr_t address);
  ~InterceptEntry();
} InterceptEntry;
