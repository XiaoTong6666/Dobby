#include "dobby.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>

using FreeFn = void (*)(void *);
static dobby_dummy_func_t published_original = nullptr;
static std::atomic<int> before_publication{0};
static std::atomic<int> after_publication{0};

extern "C" __attribute__((noinline)) void replacement_free(void *p) {
  if (!published_original) {
    ++before_publication;
    return;
  }
  ++after_publication;
  reinterpret_cast<FreeFn>(published_original)(p);
}

int main() {
  auto *target = reinterpret_cast<void *>(static_cast<FreeFn>(&free));
  int status = DobbyHook(target, reinterpret_cast<dobby_dummy_func_t>(replacement_free), &published_original);
  if (status != RT_SUCCESS || !published_original) {
    printf("self-free-hook: status=%d trampoline=%p\n", status, reinterpret_cast<void *>(published_original));
    return 2;
  }
  int premature = before_publication.load();
  void *p = malloc(32);
  free(p);
  int restored = DobbyDestroy(target);
  printf("self-free-hook: premature=%d after_publication=%d destroy=%d\n",
         premature, after_publication.load(), restored);
  return premature == 0 && restored == RT_SUCCESS ? 0 : 1;
}
