#include "dobby.h"
#include "MemoryAllocator/NearMemoryAllocator.h"
#include "InstructionRelocation/x86/InstructionRelocationX86Shared.h"
#include "InstructionRelocation/InstructionRelocation.h"

#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

static int patch_three_pages() {
  const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  const size_t length = 3 * page;
  pid_t child = fork();
  if (child < 0)
    return 2;
  if (child == 0) {
    auto *mem =
        static_cast<uint8_t *>(mmap(nullptr, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (mem == MAP_FAILED)
      _exit(2);
    memset(mem, 0x90, length);
    if (mprotect(mem, length, PROT_READ | PROT_EXEC) != 0)
      _exit(2);
    std::vector<uint8_t> bytes(length, 0x91);
    _exit(DobbyCodePatch(mem, bytes.data(), bytes.size()) == kMemoryOperationSuccess ? 0 : 1);
  }
  int status = 0;
  waitpid(child, &status, 0);
  if (WIFSIGNALED(status)) {
    printf("patch_three_pages: child died from signal %d\n", WTERMSIG(status));
    return 1;
  }
  printf("patch_three_pages: exit=%d\n", WEXITSTATUS(status));
  return WEXITSTATUS(status);
}

static int patch_permissions() {
  size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  auto *mem = static_cast<uint8_t *>(mmap(nullptr, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  if (mem == MAP_FAILED)
    return 2;
  uint8_t bytes[] = {0x90};
  if (DobbyCodePatch(mem, bytes, sizeof(bytes)) != kMemoryOperationSuccess)
    return 2;
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps)
    return 2;
  char line[4096], perms[5] = {};
  unsigned long begin = 0, end = 0;
  while (fgets(line, sizeof(line), maps)) {
    if (sscanf(line, "%lx-%lx %4s", &begin, &end, perms) == 3 && begin <= reinterpret_cast<uintptr_t>(mem) &&
        reinterpret_cast<uintptr_t>(mem) < end)
      break;
  }
  fclose(maps);
  printf("patch_permissions: original=rw- actual=%s\n", perms);
  return perms[0] == 'r' && perms[1] == 'w' && perms[2] != 'x' ? 0 : 1;
}

static int near_data_reuse() {
  size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  auto *allocator = MemoryAllocator::SharedAllocator();
  auto *first = allocator->allocateDataMemoryArena(page);
  auto *second = allocator->allocateDataMemoryArena(page);
  if (!first || !second)
    return 2;
  auto *block =
      NearMemoryAllocator::SharedAllocator()->allocateNearBlockFromDefaultAllocator(16, first->addr, page, false);
  printf("near_data_reuse: first=%p second=%p block=%p\n", reinterpret_cast<void *>(first->addr),
         reinterpret_cast<void *>(second->addr), block ? reinterpret_cast<void *>(block->addr) : nullptr);
  return block && block->addr >= first->addr && block->addr + block->size <= first->end ? 0 : 1;
}

#if defined(__x86_64__)
static int loopnz_intra_prologue() {
  // LOOPNZ +2 lands at the third instruction within the stolen prologue.
  // The embedded absolute target must point into the relocated copy.
  uint8_t bytes[] = {0xe0, 0x02, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
  CodeMemBlock original(0x100000, sizeof(bytes));
  CodeMemBlock relocated;
  GenRelocateCode(bytes, &original, &relocated, true);
  if (!relocated.addr || relocated.size < 24)
    return 1;
  uint64_t target = 0;
  memcpy(&target, reinterpret_cast<void *>(relocated.addr + 16), sizeof(target));
  const uint64_t expected = relocated.addr + 24 + 2;
  printf("loopnz_intra_prologue: target=%p relocated=%p expected=%p\n", reinterpret_cast<void *>(target),
         reinterpret_cast<void *>(relocated.addr), reinterpret_cast<void *>(expected));
  return target == expected ? 0 : 1;
}
static int loopnz_address_size() {
  // 67 E0 is LOOPNZ with the 32-bit ECX counter even in 64-bit mode.
  uint8_t original[] = {0x67, 0xe0, 0x02};
  CodeBufferBase relocated;
  x86_insn_decode_t decoded = {};
  int rc = GenRelocateSingleX86Insn(0x100000, 0x200000, original, &relocated, decoded, 64);
  const uint8_t wrong_64_bit_dec[] = {0x48, 0xff, 0xc9};
  bool wrong = false;
  for (size_t i = 0; i + sizeof(wrong_64_bit_dec) <= relocated.GetBufferSize(); ++i) {
    if (memcmp(relocated.GetBuffer() + i, wrong_64_bit_dec, sizeof(wrong_64_bit_dec)) == 0)
      wrong = true;
  }
  printf("loopnz_address_size: decoded_length=%u, rc=%d, decrements_RCX_instead_of_ECX=%d\n", decoded.length, rc,
         wrong);
  return rc == RT_SUCCESS && !wrong ? 0 : 1;
}

static int loopnz_redzone() {
  // Leaf function keeps a live value at [RSP-8]. The original LOOPNZ
  // does not touch the stack; a PUSHFQ/POPFQ expansion destroys this value.
  constexpr uint64_t marker = 0x1122334455667788ULL;
  std::vector<uint8_t> code = {
      0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // movabs rax, marker
      0x48, 0x89, 0x44, 0x24, 0xf8,                               // mov [rsp-8], rax
      0x48, 0xc7, 0xc1, 0x01, 0x00, 0x00, 0x00,                   // mov rcx, 1
      0xb8, 0x01, 0x00, 0x00, 0x00,                               // mov eax, 1
      0x85, 0xc0                                                  // test eax, eax (ZF=0)
  };
  uint8_t loop[] = {0xe0, 0x02};
  CodeBufferBase relocated;
  x86_insn_decode_t insn = {};
  if (GenRelocateSingleX86Insn(0x100000, 0x200000, loop, &relocated, insn, 64) != RT_SUCCESS)
    return 2;
  auto *bytes = relocated.GetBuffer();
  code.insert(code.end(), bytes, bytes + relocated.GetBufferSize());
  code.insert(code.end(), {0x48, 0x8b, 0x44, 0x24, 0xf8, 0xc3}); // mov rax,[rsp-8]; ret
  auto *memory =
      static_cast<uint8_t *>(mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  if (memory == MAP_FAILED)
    return 2;
  memcpy(memory, code.data(), code.size());
  if (mprotect(memory, 4096, PROT_READ | PROT_EXEC) != 0)
    return 2;
  auto value = reinterpret_cast<uint64_t (*)()>(memory)();
  printf("loopnz_redzone: expected=0x%llx actual=0x%llx\n", static_cast<unsigned long long>(marker),
         static_cast<unsigned long long>(value));
  return value == marker ? 0 : 1;
}
#endif

int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  if (strcmp(argv[1], "patch3") == 0)
    return patch_three_pages();
  if (strcmp(argv[1], "permissions") == 0)
    return patch_permissions();
  if (strcmp(argv[1], "near-data") == 0)
    return near_data_reuse();
#if defined(__x86_64__)
  if (strcmp(argv[1], "loopnz-prefix") == 0)
    return loopnz_address_size();
  if (strcmp(argv[1], "loopnz-redzone") == 0)
    return loopnz_redzone();
  if (strcmp(argv[1], "loopnz-intra") == 0)
    return loopnz_intra_prologue();
#endif
  return 2;
}
