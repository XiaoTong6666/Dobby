#include "PlatformUnifiedInterface/MemoryAllocator.h"
#include "MemoryAllocator/NearMemoryAllocator.h"
#include "TINYSTL/buffer.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unordered_map>
#include <sys/mman.h>
#include <unistd.h>

struct TrackedAllocator {
  static std::unordered_map<void *, size_t> allocations;
  static bool invalid_free;
  static void *static_allocate(size_t n) {
    void *p = malloc(n);
    allocations[p] = n;
    return p;
  }
  static void static_deallocate(void *p, size_t n) {
    if (p == nullptr || allocations.count(p) == 0 || allocations[p] != n) invalid_free = true;
    allocations.erase(p);
    free(p);
  }
};
std::unordered_map<void *, size_t> TrackedAllocator::allocations;
bool TrackedAllocator::invalid_free = false;

int main(int argc, char **argv) {
  if (argc != 2) return 2;
  if (strcmp(argv[1], "tinystl") == 0) {
  tinystl::buffer<int, TrackedAllocator> b;
  tinystl::buffer_init(&b);
  tinystl::buffer_reserve(&b, 2);
  tinystl::buffer_reserve(&b, 8);
  tinystl::buffer_destroy(&b);
  if (TrackedAllocator::invalid_free) {
    fprintf(stderr, "TinySTL freed null or used new capacity instead of old allocation size\n");
    return 1;
  }

    return 0;
  }
  if (strcmp(argv[1], "near") == 0) {
    const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    auto *arena = MemoryAllocator::SharedAllocator()->allocateDataMemoryArena(page);
    if (arena == nullptr) return 2;
    const uint8_t payload[] = {'D', 'A', 'T', 'A', 0};
    uint8_t *copy = NearMemoryAllocator::SharedAllocator()->allocateNearDataMemory(
        const_cast<uint8_t *>(payload), sizeof(payload), arena->addr, page * 2);
    if (copy == nullptr || memcmp(copy, payload, sizeof(payload)) != 0) {
      fprintf(stderr, "near data allocator failed to produce writable data\n");
      return 1;
    }
    return 0;
  }
  if (strcmp(argv[1], "data") != 0) return 2;
  // A data block must not be provisioned through the executable arena path.
  auto *data = MemoryAllocator::SharedAllocator()->allocateDataBlock(8);
  if (data == nullptr || data->addr == 0) {
    fprintf(stderr, "data block allocation failed\n");
    return 1;
  }
  memcpy(reinterpret_cast<void *>(data->addr), "DATA", 5);
  if (strcmp(reinterpret_cast<char *>(data->addr), "DATA") != 0) return 1;
  return 0;
}
