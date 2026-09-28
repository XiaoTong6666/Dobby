#include "dobby.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>

using FreeFn = void (*)(void *);
static FreeFn published_original = nullptr;
static std::atomic<int> before_publication{0};
static std::atomic<int> after_publication{0};

extern "C" __attribute__((noinline)) void replacement_free(void *p) {
  if (!published_original) {
    ++before_publication;
    return;
  }
  ++after_publication;
  published_original(p);
}

int main() {
  dobby_dummy_func_t trampoline = nullptr;
  auto *target = reinterpret_cast<void *>(static_cast<FreeFn>(&free));
  int status = DobbyHook(target, reinterpret_cast<dobby_dummy_func_t>(replacement_free), &trampoline);
  if (status != RT_SUCCESS || !trampoline) {
    printf("self-free-hook: status=%d trampoline=%p\n", status, reinterpret_cast<void *>(trampoline));
    return 2;
  }
  int premature = before_publication.load();
  published_original = reinterpret_cast<FreeFn>(trampoline);
  void *p = malloc(32);
  free(p);
  int restored = DobbyDestroy(target);
  printf("self-free-hook: premature=%d after_publication=%d destroy=%d\n",
         premature, after_publication.load(), restored);
  return premature == 0 && restored == RT_SUCCESS ? 0 : 1;
}
