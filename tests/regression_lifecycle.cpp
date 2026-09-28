#include "dobby.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

using Fn = int (*)();
static int Replacement() { return 99; }

int main(int argc, char **argv) {
#if !defined(__x86_64__)
  return 0;
#else
  if (argc != 2) return 2;
  const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  const uint8_t body[] = {0xb8, 0x07, 0, 0, 0, 0xc3, 0x90, 0x90, 0x90, 0x90};

  if (strcmp(argv[1], "hook") == 0) {
  // A MAP_SHARED view of an O_RDONLY file permits reading but not a writable
  // mapping. DobbyHook must not publish its original trampoline on failed patch.
  char name[] = "/tmp/dobby-regression-XXXXXX";
  int writable = mkstemp(name);
  if (writable < 0 || ftruncate(writable, page) != 0 || write(writable, body, sizeof(body)) != sizeof(body)) return 2;
  int readonly = open(name, O_RDONLY);
  unlink(name);
  close(writable);
  if (readonly < 0) return 2;
  void *ro = mmap(nullptr, page, PROT_READ, MAP_SHARED, readonly, 0);
  close(readonly);
  if (ro == MAP_FAILED) return 2;
  dobby_dummy_func_t original = reinterpret_cast<dobby_dummy_func_t>(0x1);
  const int failed = DobbyHook(ro, reinterpret_cast<dobby_dummy_func_t>(Replacement), &original);
  munmap(ro, page);
  if (failed == RT_SUCCESS || original != nullptr) {
    fprintf(stderr, "failed hook leaked published original pointer: rc=%d original=%p\n", failed,
            reinterpret_cast<void *>(original));
    return 1;
  }
    return 0;
  }
  if (strcmp(argv[1], "destroy") != 0) return 2;

  // Restoring a trampoline into an unmapped original must return failure;
  // otherwise the interceptor registry will incorrectly forget an active hook.
  void *rw = mmap(nullptr, page, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (rw == MAP_FAILED) return 2;
  memcpy(rw, body, sizeof(body));
  dobby_dummy_func_t original = nullptr;
  int installed = DobbyHook(rw, reinterpret_cast<dobby_dummy_func_t>(Replacement), &original);
  if (installed != RT_SUCCESS || original == nullptr) {
    fprintf(stderr, "fixture could not install a normal hook: rc=%d\n", installed);
    munmap(rw, page);
    return 2;
  }
  munmap(rw, page);
  const int destroyed = DobbyDestroy(rw);
  if (destroyed == RT_SUCCESS) {
    fprintf(stderr, "destroy reported success after target mapping was removed\n");
    return 1;
  }
  return 0;
#endif
}
