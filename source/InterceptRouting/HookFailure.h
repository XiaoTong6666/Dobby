#pragma once

#include "InterceptEntry.h"
#include "PlatformUtil/ProcessRuntimeUtility.h"
#include <cstring>

// A failed code patch may have rolled back completely, or may have left an
// unknown partial write if page protection changes were denied twice. Only
// free its closure metadata after confirming that the entry bytes are intact.
inline bool DobbyOriginalBytesRestored(const InterceptEntry *entry) {
#if defined(BUILDING_KERNEL)
  return false;
#else
  if (!entry->origin_insn_size || entry->origin_insn_size > sizeof(entry->origin_insns))
    return false;
  const addr_t start = entry->patched_addr;
  const auto size = entry->origin_insn_size;
  if (start > UINTPTR_MAX - size)
    return false;
  for (const auto &region : ProcessRuntimeUtility::GetProcessMemoryLayout()) {
    if (start >= region.start && start < region.end && region.end - start >= size && region.permission != kNoAccess)
      return memcmp(reinterpret_cast<const void *>(start), entry->origin_insns, size) == 0;
  }
  return false;
#endif
}
