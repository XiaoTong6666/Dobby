#include "InstructionRelocation/InstructionRelocation.h"

#include "UniconEmulator.h"

int main(int argc, char **argv) {
  log_set_level(0);
  set_global_arch("x86_64");

  if (argc == 2 && strcmp(argv[1], "--unreachable-rip") == 0) {
    // A deliberately unreal low source address has no near executable
    // allocation in this host process. Return an empty relocation instead of
    // emitting a JMP [RIP] whose literal target is null.
    alignas(4) uint8_t bytes[] = {0x48, 0x8d, 0x05, 0, 0, 0, 0};
    CodeMemBlock original(0x1000, sizeof(bytes));
    CodeMemBlock relocated;
    GenRelocateCode(bytes, &original, &relocated, false);
    assert(relocated.addr == 0 && relocated.size == 0);
    return 0;
  }

  // cmp eax, eax
  // jz -0x20
  check_insn_relo("\x39\xc0\x74\xdc", 4, false, UC_X86_REG_IP, nullptr);
  // cmp eax, eax
  // jz 0x20
  check_insn_relo("\x39\xc0\x74\x1c", 4, false, UC_X86_REG_IP, nullptr);

  // jmp -0x20
  check_insn_relo("\xeb\xde", 2, false, UC_X86_REG_IP, nullptr);
  // jmp 0x20
  check_insn_relo("\xeb\x1e", 2, false, UC_X86_REG_IP, nullptr);


  // jmp -0x4000
  check_insn_relo("\xe9\xfb\xbf\xff\xff", 4, false, UC_X86_REG_IP, nullptr);
  // jmp 0x4000
  check_insn_relo("\xe9\xfb\x3f\x00\x00", 4, false, UC_X86_REG_IP, nullptr);

  // lea rax, [rip]
  check_insn_relo("\x48\x8d\x05\x00\x00\x00\x00", 7, false, UC_X86_REG_RAX, nullptr);

  // lea rax, [rip + 0x4000]
  check_insn_relo("\x48\x8d\x05\x00\x40\x00\x00", 7, false, UC_X86_REG_RAX, nullptr);

  // mov rax, [rip + 0x4000]
  check_insn_relo("\x48\x8b\x05\x00\x40\x00\x00", 7, true, -1, nullptr);

  return 0;
}
