
#include "dobby_internal.h"
#include "core/arch/Cpu.h"

#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

#if !defined(__APPLE__)
PUBLIC MemoryOperationError DobbyCodePatch(void *address, uint8_t *buffer, uint32_t buffer_size) {
#if defined(__ANDROID__) || defined(__linux__)
  if (address == nullptr || buffer == nullptr || buffer_size == 0) {
    return kMemoryOperationError;
  }
  int page_size = (int)sysconf(_SC_PAGESIZE);
  if (page_size <= 0) {
    return kMemoryOperationError;
  }
  uintptr_t patch_page = ALIGN_FLOOR(address, page_size);
  uintptr_t patch_end_page = ALIGN_FLOOR((uintptr_t)address + buffer_size - 1, page_size);

  // change page permission as rwx
  if (mprotect((void *)patch_page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    return kMemoryOperationError;
  }
  if (patch_page != patch_end_page) {
    if (mprotect((void *)patch_end_page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
      mprotect((void *)patch_page, page_size, PROT_READ | PROT_EXEC);
      return kMemoryOperationError;
    }
  }

  // patch buffer
  memcpy(address, buffer, buffer_size);

  // restore page permission
  if (mprotect((void *)patch_page, page_size, PROT_READ | PROT_EXEC) != 0) {
    ERROR_LOG("failed to restore RX protection for patched page");
  }
  if (patch_page != patch_end_page) {
    if (mprotect((void *)patch_end_page, page_size, PROT_READ | PROT_EXEC) != 0) {
      ERROR_LOG("failed to restore RX protection for patched end page");
    }
  }

  addr_t clear_start_ = (addr_t)address;
  ClearCache((void *)clear_start_, (void *)(clear_start_ + buffer_size));
#endif
  return kMemoryOperationSuccess;
}

#endif
