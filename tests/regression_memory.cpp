#include "PlatformUnifiedInterface/MemoryAllocator.h"
#include "MemoryAllocator/NearMemoryAllocator.h"
#include "Backend/UserMode/UnifiedInterface/platform.h"
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
  if (strcmp(argv[1], "near-fail") == 0) {
    const uint8_t payload[] = {0x90, 0x90, 0x90, 0x90};
    auto *allocation = NearMemoryAllocator::SharedAllocator()->allocateNearExecMemory(const_cast<uint8_t *>(payload),
                                                                                      sizeof(payload), 0x1000, 0);
    if (allocation != nullptr) {
      fprintf(stderr, "an impossible near allocation unexpectedly succeeded\n");
      return 1;
    }
    return 0;
  }
  if (strcmp(argv[1], "fixed-map") == 0) {
    const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    auto *occupied =
        static_cast<uint8_t *>(mmap(nullptr, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (occupied == MAP_FAILED)
      return 2;
    memset(occupied, 0xA5, page);
    void *attempt = OSMemory::Allocate(page, kNoAccess, occupied);
    if (attempt != nullptr || occupied[page - 1] != 0xA5) {
      fprintf(stderr, "a fixed near allocation replaced an existing mapping\n");
      return 1;
    }
    munmap(occupied, page);
    return 0;
  }
  if (strcmp(argv[1], "near-data-reuse") == 0) {
    const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    auto *allocator = MemoryAllocator::SharedAllocator();
    auto *first = allocator->allocateDataMemoryArena(page);
    auto *second = allocator->allocateDataMemoryArena(page);
    if (!first || !second)
      return 2;
    auto *block =
        NearMemoryAllocator::SharedAllocator()->allocateNearBlockFromDefaultAllocator(16, first->addr, page, false);
    if (!block || block->addr < first->addr || block->addr + block->size > first->end) {
      fprintf(stderr, "near data block came from the wrong arena\n");
      return 1;
    }
    return 0;
  }
  if (strcmp(argv[1], "exec-align") == 0) {
    auto *first = MemoryAllocator::SharedAllocator()->allocateExecBlock(10);
    auto *second = MemoryAllocator::SharedAllocator()->allocateExecBlock(14);
    if (first == nullptr || second == nullptr || (second->addr & 3) != 0) {
      fprintf(stderr, "sequential executable allocations are not 4-byte aligned\n");
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
