
#include "dobby_internal.h"
#include "core/arch/Cpu.h"

#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <vector>

static bool GetOriginalProtections(uintptr_t first, uintptr_t last, size_t page_size, std::vector<int> *protections) {
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps)
    return false;
  protections->assign((last - first) / page_size + 1, -1);
  char line[4096];
  while (fgets(line, sizeof(line), maps)) {
    uintptr_t start = 0, end = 0;
    char permission[5] = {};
    if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s", &start, &end, permission) != 3 || end <= first || start > last)
      continue;
    int prot = (permission[0] == 'r' ? PROT_READ : 0) | (permission[1] == 'w' ? PROT_WRITE : 0) |
               (permission[2] == 'x' ? PROT_EXEC : 0);
    for (uintptr_t page = first > start ? first : start; page < end && page <= last; page += page_size)
      (*protections)[(page - first) / page_size] = prot;
  }
  fclose(maps);
  for (int prot : *protections) {
    if (prot < 0 || !(prot & PROT_READ))
      return false;
  }
  return true;
}

#if !defined(__APPLE__)
PUBLIC MemoryOperationError DobbyCodePatch(void *address, uint8_t *buffer, uint32_t buffer_size) {
#if defined(__ANDROID__) || defined(__linux__)
  if (address == nullptr || buffer == nullptr || buffer_size == 0) {
    return kMemoryOperationError;
  }
  if ((uintptr_t)address > UINTPTR_MAX - buffer_size) {
    return kMemoryOperationError;
  }
  int page_size = (int)sysconf(_SC_PAGESIZE);
  if (page_size <= 0) {
    return kMemoryOperationError;
  }
  uintptr_t patch_page = ALIGN_FLOOR(address, page_size);
  uintptr_t patch_end_page = ALIGN_FLOOR((uintptr_t)address + buffer_size - 1, page_size);
  std::vector<int> original_protections;
  if (!GetOriginalProtections(patch_page, patch_end_page, page_size, &original_protections))
    return kMemoryOperationError;
  // A failed RX restoration must not leave an unregistered inline hook in
  // place. Keep the original bytes until the patch is fully committed.
  auto *original = static_cast<uint8_t *>(malloc(buffer_size));
  if (!original)
    return kMemoryOperationError;

  // Protect every page before copying. Only changing first and last pages
  // crashes for a patch spanning three or more pages.
  for (uintptr_t page = patch_page; page <= patch_end_page; page += page_size) {
    if (mprotect((void *)page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
      for (uintptr_t previous = patch_page; previous < page; previous += page_size)
        mprotect((void *)previous, page_size, original_protections[(previous - patch_page) / page_size]);
      free(original);
      return kMemoryOperationError;
    }
  }

  // patch buffer
  memcpy(original, address, buffer_size);
  memcpy(address, buffer, buffer_size);

  // restore page permission
  bool restore_failed = false;
  for (uintptr_t page = patch_page; page <= patch_end_page; page += page_size) {
    if (mprotect((void *)page, page_size, original_protections[(page - patch_page) / page_size]) != 0) {
      ERROR_LOG("failed to restore RX protection for patched page %p", page);
      restore_failed = true;
    }
  }

  if (restore_failed) {
    bool writable = true;
    for (uintptr_t page = patch_page; page <= patch_end_page; page += page_size)
      writable &= mprotect((void *)page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
    if (writable) {
      memcpy(address, original, buffer_size);
      ClearCache(address, static_cast<uint8_t *>(address) + buffer_size);
    } else {
      ERROR_LOG("could not roll back patch after RX restoration failure");
    }
    for (uintptr_t page = patch_page; page <= patch_end_page; page += page_size)
      mprotect((void *)page, page_size, original_protections[(page - patch_page) / page_size]);
  } else {
    ClearCache(address, static_cast<uint8_t *>(address) + buffer_size);
  }
  free(original);
  return restore_failed ? kMemoryOperationError : kMemoryOperationSuccess;
#else
  return kMemoryOperationSuccess;
#endif
}

#endif
