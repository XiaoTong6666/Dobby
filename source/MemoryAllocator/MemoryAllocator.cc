#include "dobby_internal.h"

#include "PlatformUnifiedInterface/MemoryAllocator.h"
#include "Interceptor.h"
#include <new>

MemBlock *MemoryArena::allocMemBlock(size_t size) {
  std::lock_guard<std::recursive_mutex> guard(Interceptor::MutationMutex());
  if (this->cursor_addr > this->end || size > this->end - this->cursor_addr)
    return nullptr;
  // insufficient memory
  if (this->end - this->cursor_addr < size) {
    return nullptr;
  }

  auto result = new (std::nothrow) MemBlock(cursor_addr, size);
  if (!result)
    return nullptr;
  cursor_addr += size;
  return result;
}

MemoryAllocator *MemoryAllocator::SharedAllocator() {
  static MemoryAllocator allocator;
  return &allocator;
}

CodeMemoryArena *MemoryAllocator::allocateCodeMemoryArena(uint32_t size) {
  std::lock_guard<std::recursive_mutex> guard(Interceptor::MutationMutex());
  CHECK_EQ(size % OSMemory::PageSize(), 0);
  uint32_t arena_size = size;
  auto arena_addr = OSMemory::Allocate(arena_size, kNoAccess);
  if (!arena_addr)
    return nullptr;
  if (!OSMemory::SetPermission(arena_addr, arena_size, kReadExecute)) {
    OSMemory::Free(arena_addr, arena_size);
    return nullptr;
  }

  auto result = new (std::nothrow) CodeMemoryArena((addr_t)arena_addr, (size_t)arena_size);
  if (!result) {
    OSMemory::Free(arena_addr, arena_size);
    return nullptr;
  }
  code_arenas.push_back(result);
  return result;
}

CodeMemBlock *MemoryAllocator::allocateExecBlock(uint32_t size) {
  std::lock_guard<std::recursive_mutex> guard(Interceptor::MutationMutex());
  // ARM and ARM64 instructions require 4-byte alignment. Preserve that
  // alignment between successive variable-sized allocations in an arena.
  if (size == 0 || size > UINT32_MAX - 3)
    return nullptr;
  const uint32_t aligned_size = (size + 3u) & ~3u;
  CodeMemBlock *block = nullptr;
  for (auto iter = code_arenas.begin(); iter != code_arenas.end(); iter++) {
    auto arena = static_cast<CodeMemoryArena *>(*iter);
    block = arena->allocMemBlock(aligned_size);
    if (block)
      break;
  }
  if (!block) {
    // allocate new arena
    auto arena_size = ALIGN_CEIL(aligned_size, OSMemory::PageSize());
    auto arena = allocateCodeMemoryArena(arena_size);
    if (!arena)
      return nullptr;
    block = arena->allocMemBlock(aligned_size);
    if (!block)
      return nullptr;
  }

  DLOG(0, "[memory allocator] allocate exec memory at: %p, size: %p", block->addr, block->size);
  return block;
}

uint8_t *MemoryAllocator::allocateExecMemory(uint32_t size) {
  auto block = allocateExecBlock(size);
  if (!block)
    return nullptr;
  auto address = reinterpret_cast<uint8_t *>(block->addr);
  delete block; // Arena owns executable pages; caller owns only this descriptor.
  return address;
}
uint8_t *MemoryAllocator::allocateExecMemory(uint8_t *buffer, uint32_t buffer_size) {
  if (!buffer || !buffer_size)
    return nullptr;
  auto mem = allocateExecMemory(buffer_size);
  if (!mem)
    return nullptr;
  auto ret = DobbyCodePatch(mem, buffer, buffer_size);
  return ret == kMemoryOperationSuccess ? mem : nullptr;
}

DataMemoryArena *MemoryAllocator::allocateDataMemoryArena(uint32_t size) {
  std::lock_guard<std::recursive_mutex> guard(Interceptor::MutationMutex());
  DataMemoryArena *result = nullptr;

  uint32_t buffer_size = ALIGN_CEIL(size, OSMemory::PageSize());
  void *buffer = OSMemory::Allocate(buffer_size, kNoAccess);
  if (!buffer)
    return nullptr;
  if (!OSMemory::SetPermission(buffer, buffer_size, kReadWrite)) {
    OSMemory::Free(buffer, buffer_size);
    return nullptr;
  }

  result = new (std::nothrow) DataMemoryArena((addr_t)buffer, (size_t)buffer_size);
  if (!result) {
    OSMemory::Free(buffer, buffer_size);
    return nullptr;
  }
  data_arenas.push_back(result);
  return result;
}

DataMemBlock *MemoryAllocator::allocateDataBlock(uint32_t size) {
  std::lock_guard<std::recursive_mutex> guard(Interceptor::MutationMutex());
  CodeMemBlock *block = nullptr;
  for (auto iter = data_arenas.begin(); iter != data_arenas.end(); iter++) {
    auto arena = static_cast<DataMemoryArena *>(*iter);
    block = arena->allocMemBlock(size);
    if (block)
      break;
  }
  if (!block) {
    // allocate new arena
    auto arena = allocateDataMemoryArena(size);
    if (!arena)
      return nullptr;
    block = arena->allocMemBlock(size);
    if (!block)
      return nullptr;
  }

  DLOG(0, "[memory allocator] allocate data memory at: %p, size: %p", block->addr, block->size);
  return block;
}

uint8_t *MemoryAllocator::allocateDataMemory(uint32_t size) {
  auto block = allocateDataBlock(size);
  if (!block)
    return nullptr;
  auto address = reinterpret_cast<uint8_t *>(block->addr);
  delete block;
  return address;
}

uint8_t *MemoryAllocator::allocateDataMemory(uint8_t *buffer, uint32_t buffer_size) {
  if (!buffer || !buffer_size)
    return nullptr;
  auto mem = allocateDataMemory(buffer_size);
  if (!mem)
    return nullptr;
  memcpy(mem, buffer, buffer_size);
  return mem;
}
