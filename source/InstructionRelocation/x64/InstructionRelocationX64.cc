#include "platform_macro.h"

#if defined(TARGET_ARCH_X64)

#include "dobby_internal.h"

#include "InstructionRelocation/x64/InstructionRelocationX64.h"
#include "InstructionRelocation/x86/x86_insn_decode/x86_insn_decode.h"
#include "InstructionRelocation/x86/InstructionRelocationX86Shared.h"
#include <vector>

#include "core/arch/x64/registers-x64.h"
#include "core/assembler/assembler-x64.h"
#include "core/codegen/codegen-x64.h"

using namespace zz::x64;

int GenRelocateCodeFixed(void *buffer, CodeMemBlock *origin, CodeMemBlock *relocated, bool branch) {
  TurboAssembler turbo_assembler_(0);
  // Set fixed executable code chunk address
  turbo_assembler_.SetRealizedAddress((void *)relocated->addr);
#define _ turbo_assembler_.
#define __ turbo_assembler_.GetCodeBuffer()->

  auto curr_orig_ip = (addr64_t)origin->addr;
  auto curr_relo_ip = (addr64_t)relocated->addr;

  uint8_t *buffer_cursor = (uint8_t *)buffer;

  int predefined_relocate_size = origin->size;
  const addr_t original_start = origin->addr;
  std::vector<std::pair<addr_t, addr_t>> instruction_addresses;
  std::vector<X86AbsoluteBranchFixup> branch_fixups;

  while ((buffer_cursor < ((uint8_t *)buffer + predefined_relocate_size))) {
    instruction_addresses.emplace_back(curr_orig_ip, curr_relo_ip);
    x86_insn_decode_t insn = {0};
    memset(&insn, 0, sizeof(insn));
    if (GenRelocateSingleX86Insn(curr_orig_ip, curr_relo_ip, buffer_cursor, turbo_assembler_.GetCodeBuffer(), insn, 64,
                                 &branch_fixups) != RT_SUCCESS ||
        insn.length == 0)
      return RT_FAILED;

    // go next
    curr_orig_ip += insn.length;
    buffer_cursor += insn.length;
    curr_relo_ip = (addr64_t)relocated->addr + turbo_assembler_.ip_offset();
  }
  // A branch back into an overwritten entry must land at its relocated
  // instruction, never at the already-patched original entry. Reject jumps
  // into the middle of a stolen instruction.
  for (const auto &fixup : branch_fixups) {
    if (fixup.original_target < original_start || fixup.original_target >= curr_orig_ip)
      continue;
    addr_t relocated_target = 0;
    for (const auto &mapping : instruction_addresses) {
      if (mapping.first == fixup.original_target) {
        relocated_target = mapping.second;
        break;
      }
    }
    if (!relocated_target)
      return RT_FAILED;
    turbo_assembler_.GetCodeBuffer()->Store<uint64_t>(fixup.literal_offset, relocated_target);
  }

  // jmp to the origin rest instructions
  if (branch) {
    CodeGen codegen(&turbo_assembler_);
    // TODO: 6 == jmp [RIP + disp32] instruction size
    addr64_t stub_addr = curr_relo_ip + 6;
    codegen.JmpNearIndirect(stub_addr);
    turbo_assembler_.GetCodeBuffer()->Emit64(curr_orig_ip);
  }

  // update origin
  int new_origin_len = curr_orig_ip - (addr_t)origin->addr;
  origin->reset(origin->addr, new_origin_len);

  int relo_len = turbo_assembler_.GetCodeBuffer()->GetBufferSize();
  if (relo_len > relocated->size) {
    DLOG(0, "pre-alloc code chunk not enough");
    return kRelocationBufferTooSmall;
  }

  // generate executable code
  {
    auto code = AssemblyCodeBuilder::FinalizeFromTurboAssembler(&turbo_assembler_);
    if (code == nullptr)
      return RT_FAILED;
    relocated->reset(code->addr, code->size);
    delete code;
  }

  return RT_SUCCESS;
}

void GenRelocateCodeAndBranch(void *buffer, CodeMemBlock *origin, CodeMemBlock *relocated) {
  GenRelocateCode(buffer, origin, relocated, true);
}

void GenRelocateCode(void *buffer, CodeMemBlock *origin, CodeMemBlock *relocated, bool branch) {
  GenRelocateCodeX86Shared(buffer, origin, relocated, branch);
}

#endif
