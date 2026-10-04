#pragma once

#include "InterceptEntry.h"
#include "InterceptRouting/InterceptRouting.h"
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

// An active hook is physically owned by Dobby only while the bytes at the
// patch site still equal the trampoline Dobby published.  A different hook
// framework can legally modify the same executable mapping without appearing
// in this Dobby instance's Interceptor registry.  Never restore our saved
// original over such a foreign writer.
inline bool DobbyInstalledEntryMatches(const InterceptEntry *entry) {
#if defined(BUILDING_KERNEL)
  return false;
#else
  if (!entry || !entry->routing || !entry->routing->GetTrampolineBuffer())
    return false;
  auto *trampoline = entry->routing->GetTrampolineBuffer();
  const auto patch_size = trampoline->GetBufferSize();
  const auto restore_size = entry->origin_insn_size;
  if (!patch_size || !restore_size || patch_size > restore_size ||
      entry->patched_addr > UINTPTR_MAX - restore_size)
    return false;
  const addr_t start = entry->patched_addr;
  for (const auto &region : ProcessRuntimeUtility::GetProcessMemoryLayout()) {
    if (start < region.start || start >= region.end || region.end - start < restore_size || region.permission == kNoAccess)
      continue;
    if (memcmp(reinterpret_cast<const void *>(start), trampoline->GetBuffer(), patch_size) != 0)
      return false;
    // The relocator may steal more bytes than the physical trampoline patch
    // (notably x86/x64 variable-length instructions). Dobby never modified
    // this tail, so it must still equal the Prepare snapshot before restoring
    // the whole origin_insn_size span. Otherwise restoring would overwrite a
    // foreign writer outside Dobby's published patch bytes.
    if (restore_size > patch_size &&
        memcmp(reinterpret_cast<const void *>(start + patch_size), entry->origin_insns + patch_size,
               restore_size - patch_size) != 0)
      return false;
    return true;
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
