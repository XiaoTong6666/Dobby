#include "NearMemoryAllocator.h"

#include "dobby_internal.h"

#include "PlatformUtil/ProcessRuntimeUtility.h"
#include "Interceptor.h"

using namespace zz;

#define KB (1024uLL)
#define MB (1024uLL * KB)
#define GB (1024uLL * MB)

#if defined(WIN32)
static const void *memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) {
  if (!haystack || !needle) {
    return haystack;
  } else {
    const char *h = (const char *)haystack;
    const char *n = (const char *)needle;
    size_t l = needlelen;
    const char *r = h;
    while (l && (l <= haystacklen)) {
      if (*n++ != *h++) {
        r = h;
        n = (const char *)needle;
        l = needlelen;
      } else {
        --l;
      }
      --haystacklen;
    }
    return l ? nullptr : r;
  }
}
#endif

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

NearMemoryAllocator *NearMemoryAllocator::SharedAllocator() {
  static NearMemoryAllocator allocator;
  return &allocator;
}

MemBlock *NearMemoryAllocator::allocateNearBlockFromDefaultAllocator(uint32_t size, addr_t pos, size_t search_range,
                                                                     bool executable) {
  std::lock_guard<std::recursive_mutex> guard(Interceptor::MutationMutex());
  addr_t min_valid_addr, max_valid_addr;
  min_valid_addr = pos - search_range;
  max_valid_addr = pos + search_range;

  auto allocateFromDefaultArena = [&](MemoryArena *arena, uint32_t size) -> addr_t {
    addr_t unused_mem_start = arena->cursor_addr;
    addr_t unused_mem_end = arena->addr + arena->size;

    // check if unused region total out of search range
    if (unused_mem_end < min_valid_addr || unused_mem_start > max_valid_addr)
      return 0;

    unused_mem_start = max(unused_mem_start, min_valid_addr);
    unused_mem_end = min(unused_mem_end, max_valid_addr);
    if (executable)
      unused_mem_start = ALIGN_CEIL(unused_mem_start, 4);

    // check if invalid
    if(unused_mem_start >= unused_mem_end)
      return 0;
    

    // check if has sufficient memory
    if (unused_mem_end - unused_mem_start < size)
      return 0;
    
    DLOG(0, "[near memory allocator] unused memory from default allocator %p(%p), within pos: %p, serach_range: %p", unused_mem_start, size, pos, search_range);
    return unused_mem_start;
  };

  MemoryArena *arena = nullptr;
  addr_t unused_mem = 0;
  if (executable) {
    for (auto iter = default_allocator->code_arenas.begin(); iter != default_allocator->code_arenas.end(); iter++) {
      arena = *iter;
      unused_mem = allocateFromDefaultArena(arena, size);
      if (!unused_mem)
        continue;

      break;
    }
  } else {
    for (auto iter = default_allocator->data_arenas.begin(); iter != default_allocator->data_arenas.end(); iter++) {
      arena = *iter;
      unused_mem = allocateFromDefaultArena(arena, size);
      if (unused_mem)
        break;
    }
  }
  
  if (!unused_mem)
    return nullptr;
  
  // skip placeholder block
  // FIXME: allocate the placeholder but mark it as freed
  auto placeholder_block_size = unused_mem - arena->cursor_addr;
  if (placeholder_block_size)
    delete arena->allocMemBlock(placeholder_block_size);

  auto block = arena->allocMemBlock(size);
  return block;
}

MemBlock *NearMemoryAllocator::allocateNearBlockFromUnusedRegion(uint32_t size, addr_t pos, size_t search_range,
                                                                 bool executable) {
  std::lock_guard<std::recursive_mutex> guard(Interceptor::MutationMutex());

  addr_t min_valid_addr, max_valid_addr;
  min_valid_addr = pos - search_range;
  max_valid_addr = pos + search_range;

  auto check_has_sufficient_memory_between_region = [&](MemRegion region, MemRegion next_region, uint32_t size) -> addr_t {
    addr_t unused_mem_start = region.start + region.size;
    addr_t unused_mem_end = next_region.start;

    // check if unused region total out of search range
    if (unused_mem_end < min_valid_addr || unused_mem_start > max_valid_addr)
      return 0;

    // align
    unused_mem_start = ALIGN_CEIL(unused_mem_start, OSMemory::PageSize());

    unused_mem_start = max(unused_mem_start, min_valid_addr);
    unused_mem_end = min(unused_mem_end, max_valid_addr);
    unused_mem_start = ALIGN_CEIL(unused_mem_start, OSMemory::PageSize());

    // check if invalid
    if (unused_mem_start >= unused_mem_end)
      return 0;

    // check if has sufficient memory
    if (unused_mem_end - unused_mem_start < size)
      return 0;
    
    DLOG(0, "[near memory allocator] unused memory from unused region %p(%p), within pos: %p, serach_range: %p", unused_mem_start, size, pos, search_range);
    return unused_mem_start;
  };

  auto register_near_arena = [&](addr_t arena_addr, size_t arena_size) -> MemoryArena * {
    MemoryArena *arena = nullptr;
    if (executable) {
      arena = new CodeMemoryArena(arena_addr, arena_size);
    } else {
      arena = new DataMemoryArena(arena_addr, arena_size);
    }
    if (!OSMemory::SetPermission((void *)arena->addr, arena->size, executable ? kReadExecute : kReadWrite)) {
      OSMemory::Free((void *)arena_addr, arena_size);
      delete arena;
      return nullptr;
    }
    if (executable)
      default_allocator->code_arenas.push_back(arena);
    else
      default_allocator->data_arenas.push_back(arena);
    return arena;
  };

  // /proc/self/maps is only a snapshot. Another thread (or the runtime's
  // loader) can claim a candidate gap before MAP_FIXED_NOREPLACE reaches the
  // kernel. A stale first gap must not make a valid near allocation fail: try
  // every candidate in the requested window until one can actually be owned.
  const auto regions = ProcessRuntimeUtility::GetProcessMemoryLayout();
  for (size_t i = 0; i + 1 < regions.size(); i++) {
    const addr_t unused_mem = check_has_sufficient_memory_between_region(regions[i], regions[i + 1], size);
    if (unused_mem == 0)
      continue;

    const addr_t unused_arena_first_page_addr = (addr_t)ALIGN_FLOOR(unused_mem, OSMemory::PageSize());
    const addr_t unused_arena_end_page_addr = ALIGN_CEIL(unused_mem + size, OSMemory::PageSize());
    const size_t unused_arena_size = unused_arena_end_page_addr - unused_arena_first_page_addr;
    const addr_t unused_arena_addr = unused_arena_first_page_addr;

    if (OSMemory::Allocate(unused_arena_size, kNoAccess, (void *)unused_arena_addr) !=
        (void *)unused_arena_addr) {
      DLOG(0, "[near memory allocator] fixed candidate raced %p, trying next gap", unused_arena_addr);
      continue;
    }

    auto *unused_arena = register_near_arena(unused_arena_addr, unused_arena_size);
    if (!unused_arena)
      continue;

    // skip placeholder block
    // FIXME: allocate the placeholder but mark it as freed
    auto placeholder_block_size = unused_mem - unused_arena->cursor_addr;
    if (placeholder_block_size)
      delete unused_arena->allocMemBlock(placeholder_block_size);

    return unused_arena->allocMemBlock(size);
  }

  return nullptr;
}

MemBlock *NearMemoryAllocator::allocateNearBlock(uint32_t size, addr_t pos, size_t search_range, bool executable) {
  std::lock_guard<std::recursive_mutex> guard(Interceptor::MutationMutex());
  if (size == 0 || search_range < size || pos < search_range || pos > UINTPTR_MAX - search_range)
    return nullptr;
  MemBlock *result = nullptr;
  result = allocateNearBlockFromDefaultAllocator(size, pos, search_range, executable);
  if (!result) {
    result = allocateNearBlockFromUnusedRegion(size, pos, search_range, executable);
  }

  if (!result) {
    ERROR_LOG("[near memory allocator] allocate near block failed (%p, %p, %p)", size, pos, search_range);
  }
  return result;
}

uint8_t *NearMemoryAllocator::allocateNearExecMemory(uint32_t size, addr_t pos, size_t search_range) {
  auto block = allocateNearBlock(size, pos, search_range, true);
  if (!block)
    return nullptr;

  DLOG(0, "[near memory allocator] allocate exec memory at: %p, size: %p", block->addr, block->size);
  auto *address = reinterpret_cast<uint8_t *>(block->addr);
  delete block;
  return address;
}

uint8_t *NearMemoryAllocator::allocateNearExecMemory(uint8_t *buffer, uint32_t buffer_size, addr_t pos,
                                                     size_t search_range) {
  if (!buffer || !buffer_size)
    return nullptr;
  auto mem = allocateNearExecMemory(buffer_size, pos, search_range);
  if (!mem)
    return nullptr;
  auto ret = DobbyCodePatch(mem, buffer, buffer_size);
  return ret == kMemoryOperationSuccess ? mem : nullptr;
}

uint8_t *NearMemoryAllocator::allocateNearDataMemory(uint32_t size, addr_t pos, size_t search_range) {
  auto block = allocateNearBlock(size, pos, search_range, false);
  if (!block)
    return nullptr;

  DLOG(0, "[near memory allocator] allocate data memory at: %p, size: %p", block->addr, block->size);
  auto *address = reinterpret_cast<uint8_t *>(block->addr);
  delete block;
  return address;
}

uint8_t *NearMemoryAllocator::allocateNearDataMemory(uint8_t *buffer, uint32_t buffer_size, addr_t pos,
                                                     size_t search_range) {
  if (!buffer || !buffer_size)
    return nullptr;
  auto mem = allocateNearDataMemory(buffer_size, pos, search_range);
  if (mem == nullptr)
    return nullptr;
  memcpy(mem, buffer, buffer_size);
  return mem;
}
