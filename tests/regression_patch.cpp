#include "dobby_internal.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

static bool fail_rx_restore = false;
extern "C" int __real_mprotect(void *, size_t, int);
extern "C" int __wrap_mprotect(void *addr, size_t length, int prot) {
  if (fail_rx_restore && prot == (PROT_READ | PROT_EXEC)) {
    fail_rx_restore = false;
    errno = EACCES;
    return -1;
  }
  return __real_mprotect(addr, length, prot);
}

int main(int argc, char **argv) {
  if (argc != 2) return 2;
  const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  const bool three = strcmp(argv[1], "three") == 0;
  const bool restore = strcmp(argv[1], "restore") == 0;
  if (!three && !restore && strcmp(argv[1], "two") != 0) return 2;
  uint8_t *mapped = static_cast<uint8_t *>(mmap(nullptr, page * 4, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  if (mapped == MAP_FAILED) return 2;
  memset(mapped, 0x90, page * 4);
  if (mprotect(mapped, page * 4, PROT_READ | PROT_EXEC) != 0) return 2;
  const size_t size = three ? page + 16 : 16;
  std::vector<uint8_t> contents(size, 0xCC);
  if (restore) fail_rx_restore = true;
  auto *target = mapped + page - 8;
  auto result = DobbyCodePatch(target, contents.data(), static_cast<uint32_t>(size));
  if (restore) {
    if (result == kMemoryOperationSuccess || memcmp(target, contents.data(), size) == 0) {
      fprintf(stderr, "RX restoration failed but patch was accepted or left installed\n");
      return 1;
    }
  } else if (result != kMemoryOperationSuccess ||
             memcmp(target, contents.data(), size) != 0) {
    fprintf(stderr, "patch did not cover every page\n");
    return 1;
  }
  return 0;
}
