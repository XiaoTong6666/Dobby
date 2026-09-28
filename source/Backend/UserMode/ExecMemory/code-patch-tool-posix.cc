
#include "dobby_internal.h"
#include "core/arch/Cpu.h"

#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#if defined(__ANDROID__) || defined(__linux__)
#include <sys/syscall.h>
#if defined(__aarch64__) || defined(__x86_64__)
#include <linux/membarrier.h>
#endif
#endif

static int ProtectPage(void *page, size_t size, int permission) {
#if defined(__ANDROID__) || defined(__linux__)
  // Calling libc mprotect() here self-intercepts if the user hooks that
  // function. Always use the kernel entrypoint in this implementation.
  return static_cast<int>(syscall(SYS_mprotect, static_cast<long>(reinterpret_cast<uintptr_t>(page)),
                                  static_cast<long>(size), static_cast<long>(permission), 0L));
#else
  return mprotect(page, size, permission);
#endif
}

// This is deliberately per-thread: DobbyHook serializes each installation,
// and its failure handler reads the result immediately on the calling thread.
// Comparing restored bytes alone cannot prove that other CPU pipelines have
// stopped executing a previously installed branch.
static thread_local bool g_last_patch_failure_synchronized = true;
static thread_local bool g_last_patch_ever_published = false;
#if defined(__x86_64__) && (defined(__ANDROID__) || defined(__linux__))
static thread_local bool g_exclusive_x64_sync_core = false;
void DobbySetExclusiveInstructionSync(bool required) {
  g_exclusive_x64_sync_core = required;
}
#endif
bool DobbyLastPatchFailureWasSynchronized() {
  return g_last_patch_failure_synchronized;
}
bool DobbyLastPatchWasPublished() {
  return g_last_patch_ever_published;
}

// __clear_cache cleans/invalidates instruction and data caches, but its ISB
// only synchronizes the calling core's pipeline. Linux's sync-core membarrier
// executes a context-synchronizing operation on sibling threads as well.
// Register before editing: if the kernel cannot provide this guarantee, do
// not install a patch and claim that another CPU will observe it on return.
static bool RegisterProcessInstructionSync() {
#if (defined(__aarch64__) || defined(__x86_64__)) && (defined(__ANDROID__) || defined(__linux__))
  constexpr int required =
      MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE;
  const long available = syscall(SYS_membarrier, static_cast<long>(MEMBARRIER_CMD_QUERY), 0L, 0L, 0L);
  return available >= 0 && (available & required) == required &&
         syscall(SYS_membarrier, static_cast<long>(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE), 0L, 0L, 0L) ==
             0;
#else
  return true;
#endif
}

#if defined(__aarch64__) && (defined(__ANDROID__) || defined(__linux__))
bool DobbyEnsureInstructionSync() {
  return RegisterProcessInstructionSync();
}
#endif
#if defined(__x86_64__) && (defined(__ANDROID__) || defined(__linux__))
bool DobbyEnsureExclusiveInstructionSync() {
  return RegisterProcessInstructionSync();
}
#endif

static bool SynchronizeProcessInstructionStreams() {
#if defined(__aarch64__) && (defined(__ANDROID__) || defined(__linux__))
  return syscall(SYS_membarrier, static_cast<long>(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE), 0L, 0L, 0L) == 0;
#elif defined(__x86_64__) && (defined(__ANDROID__) || defined(__linux__))
  if (g_exclusive_x64_sync_core)
    return syscall(SYS_membarrier, static_cast<long>(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE), 0L, 0L, 0L) == 0;
  return true;
#else
  return true;
#endif
}

static bool GetOriginalProtections(uintptr_t first, uintptr_t last, size_t page_size, int *protections,
                                   size_t page_count) {
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps)
    return false;
  for (size_t i = 0; i < page_count; ++i)
    protections[i] = -1;
  char line[4096];
  while (fgets(line, sizeof(line), maps)) {
    uintptr_t start = 0, end = 0;
    char permission[5] = {};
    if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s", &start, &end, permission) != 3 || end <= first || start > last)
      continue;
    int prot = (permission[0] == 'r' ? PROT_READ : 0) | (permission[1] == 'w' ? PROT_WRITE : 0) |
               (permission[2] == 'x' ? PROT_EXEC : 0);
    for (uintptr_t page = first > start ? first : start; page < end && page <= last; page += page_size)
      protections[(page - first) / page_size] = prot;
  }
  fclose(maps);
  for (size_t i = 0; i < page_count; ++i) {
    const int prot = protections[i];
    if (prot < 0 || !(prot & PROT_READ))
      return false;
  }
  return true;
}

#if !defined(__APPLE__)
PUBLIC MemoryOperationError DobbyCodePatch(void *address, uint8_t *buffer, uint32_t buffer_size) {
#if defined(__ANDROID__) || defined(__linux__)
  g_last_patch_failure_synchronized = true;
  g_last_patch_ever_published = false;
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
  const size_t page_count = (patch_end_page - patch_page) / page_size + 1;
  // Patching malloc/free themselves must not invoke free() after the target
  // bytes are installed but before DobbyHook publishes the original entry.
  // Keep common patch metadata on the stack, and use direct mmap/munmap for
  // unusually large patches. std::vector and malloc-backed backups would
  // invoke the newly installed hook in their destructors / free().
  int inline_protections[64];
  void *mapped_protections = nullptr;
  const size_t protection_bytes = page_count * sizeof(int);
  int *original_protections = inline_protections;
  if (page_count > 64) {
    mapped_protections = mmap(nullptr, protection_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapped_protections == MAP_FAILED)
      return kMemoryOperationError;
    original_protections = static_cast<int *>(mapped_protections);
  }
  uint8_t inline_backup[256];
  void *mapped_backup = nullptr;
  uint8_t *original = inline_backup;
  if (buffer_size > sizeof(inline_backup)) {
    mapped_backup = mmap(nullptr, buffer_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapped_backup == MAP_FAILED) {
      if (mapped_protections)
        munmap(mapped_protections, protection_bytes);
      return kMemoryOperationError;
    }
    original = static_cast<uint8_t *>(mapped_backup);
  }
  auto release_scratch = [&]() {
    if (mapped_backup)
      munmap(mapped_backup, buffer_size);
    if (mapped_protections)
      munmap(mapped_protections, protection_bytes);
  };
  if (!GetOriginalProtections(patch_page, patch_end_page, page_size, original_protections, page_count)) {
    release_scratch();
    return kMemoryOperationError;
  }
  if (!DobbyEnsureInstructionSync()
#if defined(__x86_64__) && (defined(__ANDROID__) || defined(__linux__))
      || (g_exclusive_x64_sync_core && !DobbyEnsureExclusiveInstructionSync())
#endif
  ) {
    release_scratch();
    return kInstructionSyncUnavailable;
  }

  // Protect every page before copying. Only changing first and last pages
  // crashes for a patch spanning three or more pages.
  for (uintptr_t page = patch_page; page <= patch_end_page; page += page_size) {
    if (ProtectPage((void *)page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
      bool protections_restored = true;
      for (uintptr_t previous = patch_page; previous < page; previous += page_size)
        protections_restored &=
            ProtectPage((void *)previous, page_size, original_protections[(previous - patch_page) / page_size]) == 0;
      g_last_patch_failure_synchronized = protections_restored;
      release_scratch();
      return kMemoryOperationError;
    }
  }

  // patch buffer
  memcpy(original, address, buffer_size);
  // Conservatively mark publication *before* the first instruction byte is
  // written. A signal or fault between the store and a later marker must
  // never misclassify a possibly fetched branch as never-published.
  g_last_patch_ever_published = true;
#if defined(__aarch64__)
  // A near trampoline is one aligned A64 instruction. Install it with a
  // single store, rather than letting a generic memcpy expose torn bytes to
  // an executing thread. This does NOT make multi-instruction patches atomic.
  const bool atomic_instruction = buffer_size == sizeof(uint32_t) && ((uintptr_t)address & 3u) == 0;
  if (atomic_instruction) {
    uint32_t word = 0;
    memcpy(&word, buffer, sizeof(word));
    __atomic_store_n(static_cast<uint32_t *>(address), word, __ATOMIC_RELEASE);
  } else {
    memcpy(address, buffer, buffer_size);
  }
#else
  memcpy(address, buffer, buffer_size);
#endif
  // The new branch can now be visible. Keep the owner/closure metadata until
  // either the new instructions are fully synchronized or a synchronized
  // rollback has been completed.
  g_last_patch_failure_synchronized = false;

  // restore page permission
  bool restore_failed = false;
  for (uintptr_t page = patch_page; page <= patch_end_page; page += page_size) {
    if (ProtectPage((void *)page, page_size, original_protections[(page - patch_page) / page_size]) != 0) {
      restore_failed = true;
    }
  }

  bool synchronization_failed = false;
  if (!restore_failed) {
    ClearCache(address, static_cast<uint8_t *>(address) + buffer_size);
    // A completed cache flush is not by itself a synchronization point for
    // the execution pipelines of the other cores in the process.
    restore_failed = !SynchronizeProcessInstructionStreams();
    synchronization_failed = restore_failed;
    if (!restore_failed)
      g_last_patch_failure_synchronized = true;
  }

  if (restore_failed) {
    bool writable = true;
    for (uintptr_t page = patch_page; page <= patch_end_page; page += page_size)
      writable &= ProtectPage((void *)page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
    bool rollback_synchronized = false;
    if (writable) {
#if defined(__aarch64__)
      if (atomic_instruction) {
        uint32_t word = 0;
        memcpy(&word, original, sizeof(word));
        __atomic_store_n(static_cast<uint32_t *>(address), word, __ATOMIC_RELEASE);
      } else {
        memcpy(address, original, buffer_size);
      }
#else
      memcpy(address, original, buffer_size);
#endif
      ClearCache(address, static_cast<uint8_t *>(address) + buffer_size);
      // This cannot make a failed installation successful; it only helps
      // propagate the restored original instruction stream to other cores.
      rollback_synchronized = SynchronizeProcessInstructionStreams();
    } else {
      // Avoid an allocator-backed logging call while a partially installed
      // hook of free()/malloc() might still be active.
    }
    bool permissions_restored = true;
    for (uintptr_t page = patch_page; page <= patch_end_page; page += page_size)
      permissions_restored &=
          ProtectPage((void *)page, page_size, original_protections[(page - patch_page) / page_size]) == 0;
    g_last_patch_failure_synchronized = rollback_synchronized && permissions_restored;
  }
  release_scratch();
  return restore_failed ? (synchronization_failed ? kInstructionSyncFailed : kMemoryOperationError)
                        : kMemoryOperationSuccess;
#else
  return kMemoryOperationSuccess;
#endif
}

#endif
