#include "dobby_internal.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>
#include <cinttypes>

static int PagePermissions(void *address) {
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps)
    return -1;
  char line[4096];
  int prot = -1;
  while (fgets(line, sizeof(line), maps)) {
    uintptr_t start = 0, end = 0;
    char perms[5] = {};
    if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s", &start, &end, perms) != 3)
      continue;
    uintptr_t ptr = reinterpret_cast<uintptr_t>(address);
    if (ptr >= start && ptr < end) {
      prot = (perms[0] == 'r' ? PROT_READ : 0) | (perms[1] == 'w' ? PROT_WRITE : 0) | (perms[2] == 'x' ? PROT_EXEC : 0);
      break;
    }
  }
  fclose(maps);
  return prot;
}

static bool fail_rx_restore = false;
static int fail_rx_count = 0;
static void *fail_writable_page = nullptr;
extern "C" int __real_mprotect(void *, size_t, int);
extern "C" int __wrap_mprotect(void *addr, size_t length, int prot) {
  if (addr == fail_writable_page && prot == (PROT_READ | PROT_WRITE | PROT_EXEC)) {
    fail_writable_page = nullptr;
    errno = EACCES;
    return -1;
  }
  if (fail_rx_count > 0 && prot == (PROT_READ | PROT_EXEC)) {
    --fail_rx_count;
    errno = EACCES;
    return -1;
  }
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
  const bool rw = strcmp(argv[1], "rw") == 0;
  const bool mixed = strcmp(argv[1], "mixed") == 0;
  const bool prepare_fail = strcmp(argv[1], "prepare-fail") == 0;
  const bool restore_both = strcmp(argv[1], "restore-both") == 0;
  if (!three && !restore && !rw && !mixed && !prepare_fail && !restore_both && strcmp(argv[1], "two") != 0)
    return 2;
  uint8_t *mapped = static_cast<uint8_t *>(mmap(nullptr, page * 4, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  if (mapped == MAP_FAILED) return 2;
  memset(mapped, 0x90, page * 4);
  if (mprotect(mapped, page * 4, PROT_READ | PROT_EXEC) != 0) return 2;
  if (rw && mprotect(mapped, page * 4, PROT_READ | PROT_WRITE) != 0)
    return 2;
  if (mixed && mprotect(mapped + page, page, PROT_READ | PROT_WRITE) != 0)
    return 2;
  const size_t size = (three || prepare_fail) ? page + 16 : 16;
  std::vector<uint8_t> contents(size, 0xCC);
  if (restore) fail_rx_restore = true;
  if (restore_both)
    fail_rx_count = 2;
  if (prepare_fail)
    fail_writable_page = mapped + 2 * page;
  auto *target = mapped + page - 8;
  auto result = DobbyCodePatch(target, contents.data(), static_cast<uint32_t>(size));
  if (restore || restore_both || prepare_fail) {
    bool unchanged = true;
    for (size_t i = 0; i < size; ++i)
      unchanged &= target[i] == 0x90;
    if (result == kMemoryOperationSuccess || !unchanged) {
      fprintf(stderr, "injected patch failure accepted or left changed bytes\n");
      return 1;
    }
  } else if (result != kMemoryOperationSuccess || memcmp(target, contents.data(), size) != 0) {
    fprintf(stderr, "patch did not cover every page\n");
    return 1;
  }
  if (rw && PagePermissions(target) != (PROT_READ | PROT_WRITE)) {
    fprintf(stderr, "RW mapping was changed to RX\n");
    return 1;
  }
  if (mixed && (PagePermissions(target) != (PROT_READ | PROT_EXEC) ||
                PagePermissions(mapped + page) != (PROT_READ | PROT_WRITE))) {
    fprintf(stderr, "mixed page permissions were not retained\n");
    return 1;
  }
  if (prepare_fail || restore_both) {
    for (size_t i = 0; i < 3; ++i) {
      if (PagePermissions(mapped + i * page) != (PROT_READ | PROT_EXEC)) {
        fprintf(stderr, "failed patch did not restore permission on page %zu\n", i);
        return 1;
      }
    }
  }
  return 0;
}
