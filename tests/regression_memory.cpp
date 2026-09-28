#include "PlatformUnifiedInterface/MemoryAllocator.h"
#include "TINYSTL/buffer.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

struct TrackedAllocator {
  static size_t allocated;
  static bool invalid_free;
  static void *static_allocate(size_t n) {
    allocated = n;
    return malloc(n);
  }
  static void static_deallocate(void *p, size_t n) {
    if (p == nullptr || allocated != n) invalid_free = true;
    free(p);
  }
};
size_t TrackedAllocator::allocated = 0;
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
