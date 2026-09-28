#pragma once

#include "InterceptEntry.h"
#include "PlatformUtil/ProcessRuntimeUtility.h"
#include <cstring>

#if !defined(BUILDING_KERNEL) && (defined(__ANDROID__) || defined(__linux__))
bool DobbyLastPatchFailureWasSynchronized();
bool DobbyLastPatchWasPublished();
#else
// A backend without publication diagnostics must retain the conservative
// possibility that its failed patch became visible.
inline bool DobbyLastPatchWasPublished() {
  return true;
}
#endif

// Only readable, unchanged target bytes permit a transaction to proceed.
// This checks code bytes, not the process-local last-patch synchronization
// result. A prepared transaction must not depend on an unrelated patch's TLS.
inline bool DobbyOriginalEntryMatches(const InterceptEntry *entry) {
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

// A failed code patch may have rolled back completely, or may have left an
// unknown partial write. A local byte comparison is insufficient if another
// core has not synchronized its already-fetched instruction stream.
inline bool DobbyOriginalBytesRestored(const InterceptEntry *entry) {
#if defined(__ANDROID__) || defined(__linux__)
  if (!DobbyLastPatchFailureWasSynchronized())
    return false;
#endif
  return DobbyOriginalEntryMatches(entry);
}
