#include "dobby.h"
#include "Interceptor.h"

#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

#if defined(__x86_64__)
static bool inject_partial_commit = false;
static void *target_entry = nullptr;
extern "C" MemoryOperationError __real_DobbyCodePatch(void *, uint8_t *, uint32_t);
extern "C" MemoryOperationError __wrap_DobbyCodePatch(void *address, uint8_t *buffer, uint32_t size) {
  const auto result = __real_DobbyCodePatch(address, buffer, size);
  if (inject_partial_commit && address == target_entry && result == kMemoryOperationSuccess) {
    inject_partial_commit = false;
    // Simulates restoration failing after the entry bytes were written and
    // rollback was denied: the new entry bytes may already be observable.
    return kMemoryOperationError;
  }
  return result;
}

static int Replacement() { return 99; }
#endif

int main() {
#if !defined(__x86_64__)
  return 0;
#else
  const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  auto *code = static_cast<uint8_t *>(mmap(nullptr, page, PROT_READ | PROT_WRITE | PROT_EXEC,
                                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  if (code == MAP_FAILED)
    return 2;
  const uint8_t original[] = {0xb8, 0x07, 0, 0, 0, 0xc3, 0x90, 0x90, 0x90, 0x90,
                              0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
  memcpy(code, original, sizeof(original));
  target_entry = code;
  inject_partial_commit = true;
  dobby_dummy_func_t trampoline = reinterpret_cast<dobby_dummy_func_t>(1);
  const int installed = DobbyHook(code, reinterpret_cast<dobby_dummy_func_t>(Replacement), &trampoline);
  auto *entry = Interceptor::SharedInstance()->find(reinterpret_cast<addr_t>(code));
  if (installed == RT_SUCCESS || trampoline != nullptr || !entry ||
      entry->state != InterceptEntryState::Removing ||
      Interceptor::SharedInstance()->count() != 1) {
    fprintf(stderr, "failed partial commit was published or its rollback metadata freed\n");
    return 1;
  }
  dobby_dummy_func_t duplicate = reinterpret_cast<dobby_dummy_func_t>(1);
  if (DobbyHook(code, reinterpret_cast<dobby_dummy_func_t>(Replacement), &duplicate) == RT_SUCCESS ||
      duplicate != nullptr) {
    fprintf(stderr, "hook replaced an unresolved partial commit\n");
    return 1;
  }
  if (DobbyDestroy(code) != RT_SUCCESS || Interceptor::SharedInstance()->count() != 0 ||
      memcmp(code, original, sizeof(original)) != 0 || reinterpret_cast<int (*)()>(code)() != 7) {
    fprintf(stderr, "failed partial commit could not be explicitly recovered\n");
    return 1;
  }
  munmap(code, page);
  return 0;
#endif
}
