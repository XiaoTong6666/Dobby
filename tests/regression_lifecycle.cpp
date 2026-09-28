#include "dobby.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <atomic>
#include <thread>
#include <vector>
#include "Interceptor.h"

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
  const bool roundtrip = strcmp(argv[1], "roundtrip") == 0;
  const bool duplicate = strcmp(argv[1], "duplicate") == 0;
  const bool reinstall = strcmp(argv[1], "reinstall") == 0;
  const bool race = strcmp(argv[1], "race") == 0;
  // Intentionally NOT in the passing CTest suite: concurrent execution of
  // an x64 14-byte entry patch currently SIGSEGVs. Run this isolated child
  // process manually to reproduce; a registry mutex cannot quiesce readers.
  const bool execute_race = strcmp(argv[1], "execute-race-long") == 0;
  if (!roundtrip && !duplicate && !reinstall && !race && !execute_race && strcmp(argv[1], "destroy") != 0)
    return 2;

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
  if (roundtrip) {
    auto target = reinterpret_cast<Fn>(rw);
    auto trampoline = reinterpret_cast<Fn>(original);
    if (target() != 99 || trampoline() != 7 || DobbyDestroy(rw) != RT_SUCCESS || target() != 7) {
      fprintf(stderr, "hook/original/destroy roundtrip did not preserve behavior\n");
      munmap(rw, page);
      return 1;
    }
    munmap(rw, page);
    return 0;
  }
  if (duplicate || reinstall) {
    dobby_dummy_func_t second = reinterpret_cast<dobby_dummy_func_t>(0x1);
    const int duplicate_status = DobbyHook(rw, reinterpret_cast<dobby_dummy_func_t>(Replacement), &second);
    if (duplicate_status == RT_SUCCESS || second != nullptr || reinterpret_cast<Fn>(rw)() != 99 ||
        reinterpret_cast<Fn>(original)() != 7 || Interceptor::SharedInstance()->count() != 1) {
      fprintf(stderr, "duplicate install mutated the installed hook or registry\n");
      return 1;
    }
    if (DobbyDestroy(rw) != RT_SUCCESS || Interceptor::SharedInstance()->count() != 0)
      return 1;
    if (reinstall) {
      if (reinterpret_cast<Fn>(original)() != 7) {
        fprintf(stderr, "destroy invalidated a published original trampoline\n");
        return 1;
      }
      second = nullptr;
      if (DobbyHook(rw, reinterpret_cast<dobby_dummy_func_t>(Replacement), &second) != RT_SUCCESS ||
          second == nullptr || reinterpret_cast<Fn>(second)() != 7 || DobbyDestroy(rw) != RT_SUCCESS) {
        fprintf(stderr, "reinstall/roundtrip failed\n");
        return 1;
      }
    }
    const bool okay = reinterpret_cast<Fn>(rw)() == 7;
    munmap(rw, page);
    return okay ? 0 : 1;
  }
  if (race || execute_race) {
    if (DobbyDestroy(rw) != RT_SUCCESS)
      return 2;
    std::atomic<bool> go{false};
    std::atomic<int> errors{0};
    std::atomic<int> successes{0};
    std::vector<std::thread> workers;
    for (int t = 0; t < 8; ++t) {
      workers.emplace_back([&] {
        while (!go.load(std::memory_order_acquire))
          std::this_thread::yield();
        if (execute_race) {
          while (go.load(std::memory_order_acquire)) {
            const int value = reinterpret_cast<Fn>(rw)();
            if (value != 7 && value != 99)
              errors.fetch_add(1);
          }
          return;
        }
        for (int i = 0; i < 120; ++i) {
          dobby_dummy_func_t prior = reinterpret_cast<dobby_dummy_func_t>(0x1);
          int rc = DobbyHook(rw, reinterpret_cast<dobby_dummy_func_t>(Replacement), &prior);
          if (rc != RT_SUCCESS) {
            if (prior != nullptr)
              errors.fetch_add(1);
            continue;
          }
          successes.fetch_add(1);
          if (!prior || reinterpret_cast<Fn>(prior)() != 7 || DobbyDestroy(rw) != RT_SUCCESS)
            errors.fetch_add(1);
        }
      });
    }
    go.store(true, std::memory_order_release);
    if (execute_race) {
      for (int i = 0; i < 150; ++i) {
        dobby_dummy_func_t prior = nullptr;
        if (DobbyHook(rw, reinterpret_cast<dobby_dummy_func_t>(Replacement), &prior) != RT_SUCCESS || !prior ||
            reinterpret_cast<Fn>(prior)() != 7 || DobbyDestroy(rw) != RT_SUCCESS) {
          errors.fetch_add(1);
          break;
        }
        successes.fetch_add(1);
      }
      go.store(false, std::memory_order_release);
    }
    for (auto &worker : workers)
      worker.join();
    const bool okay =
        errors == 0 && successes > 0 && Interceptor::SharedInstance()->count() == 0 && reinterpret_cast<Fn>(rw)() == 7;
    if (!okay)
      fprintf(stderr, "race errors=%d successful=%d active=%d\n", errors.load(), successes.load(),
              Interceptor::SharedInstance()->count());
    munmap(rw, page);
    return okay ? 0 : 1;
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
