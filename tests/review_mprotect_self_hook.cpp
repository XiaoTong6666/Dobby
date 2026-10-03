#include "dobby.h"
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <sys/mman.h>
#include <unistd.h>

using ProtectFn = int (*)(void*, size_t, int);
static dobby_dummy_func_t published_original = nullptr;
static std::atomic<unsigned> before_publication{0};

extern "C" __attribute__((noinline)) int replacement_mprotect(void *addr, size_t len, int protection) {
  if (!published_original) {
    before_publication.fetch_add(1, std::memory_order_relaxed);
    errno = EACCES;
    return -1;
  }
  return reinterpret_cast<ProtectFn>(published_original)(addr, len, protection);
}

int main() {
  setbuf(stdout, nullptr);
  const int installed = DobbyHook(reinterpret_cast<void *>(static_cast<ProtectFn>(&mprotect)),
                                  reinterpret_cast<dobby_dummy_func_t>(replacement_mprotect), &published_original);
  const unsigned premature = before_publication.load();
  printf("self-mprotect-hook: status=%d premature=%u published=%p\n", installed, premature,
         reinterpret_cast<void*>(published_original));
  if (installed == RT_SUCCESS) {
    int destroyed = DobbyDestroy(reinterpret_cast<void *>(static_cast<ProtectFn>(&mprotect)));
    printf("self-mprotect-hook: destroy=%d\n", destroyed);
  }
  return installed == RT_SUCCESS && premature == 0 ? 0 : 1;
}
