/*

test_b:
b #-0x4000
b #0x4000

test_bl:
bl #-0x4000
bl #0x4000

test_cbz:
cbz x0, #-0x4000
cbz x0, #0x4000

test_ldr_liberal:
ldr x0, #-0x4000
ldr x0, #0x4000

test_adr:
adr x0, #-0x4000
adr x0, #0x4000

test_adrp:
adrp x0, #-0x4000
adrp x0, #0x4000

test_b_cond:
b.eq #-0x4000
b.eq #0x4000

test_tbz:
tbz x0, #0, #-0x4000
tbz x0, #0, #0x4000

*/

// clang -arch arm64 code_arm64.asm -o code_arm64.o

#include "InstructionRelocation/InstructionRelocation.h"

#include "UniconEmulator.h"

int main(int argc, char **argv) {
  set_global_arch("arm64");

  auto check_x17 = ^(UniconEmulator *orig, UniconEmulator *relo) {
    assert(orig->readRegister(UC_ARM64_REG_X17) == relo->readRegister(UC_ARM64_REG_X17));
    assert(orig->getFaultAddr() == relo->getFaultAddr());
  };

  if (argc == 2 && strcmp(argv[1], "--x17-branch") == 0) {
    // A taken conditional branch must not clobber an otherwise-live x17.
    // Both paths fault at the same unmapped target; compare the saved register.
    check_insn_relo("\x00\x00\x80\xd2\x1f\x00\x00\xf1\x00\x00\x02\x54", 12, false, -1, check_x17, 0,
                    0x172435465768798aULL);
    return 0;
  }
  if (argc == 2 && strcmp(argv[1], "--x17-matrix") == 0) {
    constexpr uintptr_t live = 0x172435465768798aULL;
    // Non-fallthrough B and BL, both CBZ directions, TBZ and a taken B.cond.
    check_insn_relo("\x00\x10\x00\x14", 4, false, -1, check_x17, 0, live);
    check_insn_relo("\x00\x10\x00\x94", 4, false, -1, check_x17, 0, live);
    check_insn_relo("\x00\x00\x80\xd2\x00\x00\x02\xb4", 8, false, -1, check_x17, 0, live);
    check_insn_relo("\x20\x00\x80\xd2\x00\x00\x02\xb4", 8, false, -1, check_x17, 0, live);
    check_insn_relo("\x60\x01\x80\xd2\x00\x00\x12\x36", 8, false, -1, check_x17, 0, live);
    check_insn_relo("\x00\x00\x80\xd2\x1f\x00\x00\xf1\x00\x00\x02\x54", 12, false, -1, check_x17, 0, live);
    // A faulting literal load must not alter any unrelated GPR beforehand.
    check_insn_relo("\x00\x00\x02\x58", 4, false, -1, check_x17, 0, live);
    // The raw literal instruction must preserve its destination even when it
    // is x17: the emulated access faults before any destination write.
    check_insn_relo("\x11\x00\x02\x58", 4, false, -1, check_x17, 0, live);
    return 0;
  }
  if (argc == 2 && strcmp(argv[1], "--intra-prologue") == 0) {
    // The original branch skips to a still-stolen instruction. Redirecting it
    // to the already-patched entry would recurse rather than continue.
    check_insn_relo("\x01\x00\x00\x14\x20\x00\x80\xd2", 8, false, UC_ARM64_REG_X0, nullptr);
    return 0;
  }
  if (argc == 2 && strcmp(argv[1], "--out-of-range") == 0) {
    // No scratch-register fallback: both classes must fail closed if a
    // synthetic relocated PC cannot reach the original control/data target.
    const unsigned char branch[] = {0x02, 0x00, 0x00, 0x14};
    const unsigned char literal[] = {0x40, 0x00, 0x00, 0x58};
    for (auto code : {branch, literal}) {
      CodeMemBlock original(0x10000000, 4);
      CodeMemBlock relocated(0x30000000, 0x1000);
      GenRelocateCode(const_cast<unsigned char *>(code), &original, &relocated, false);
      assert(relocated.addr == 0 && relocated.size == 0);
    }
    return 0;
  }
  if (argc == 2 && strcmp(argv[1], "--adr-backward-rejected") == 0) {
    alignas(4) const uint8_t backward_adr[] = {0x00, 0x00, 0xfe, 0x10};
    CodeMemBlock original(0x100014000, 4);
    CodeMemBlock relocated(0x100024000, 0x1000);
    GenRelocateCode(const_cast<uint8_t *>(backward_adr), &original, &relocated, false);
    assert(relocated.addr == 0 && relocated.size == 0);
    return 0;
  }
  if (argc == 2 && strcmp(argv[1], "--inline-literal") == 0) {
    const char code[] = "\x40\x00\x00\x58\xc0\x03\x5f\xd6"
                        "\x88\x77\x66\x55\x44\x33\x22\x11";
    check_insn_relo(const_cast<char *>(code), sizeof(code) - 1, false, UC_ARM64_REG_X0,
                    ^(UniconEmulator *orig, UniconEmulator *relo) {
                      assert(orig->readRegister(UC_ARM64_REG_X0) ==
                             reinterpret_cast<void *>(UINT64_C(0x1122334455667788)));
                      assert(orig->readRegister(UC_ARM64_REG_X0) == relo->readRegister(UC_ARM64_REG_X0));
                    });
    return 0;
  }

  // b #-0x4000
  check_insn_relo("\x00\xf0\xff\x17", 4, true, -1, nullptr);
  // b #0x4000
  check_insn_relo("\x00\x10\x00\x14", 4, true, -1, nullptr);

  // bl #-0x4000
  check_insn_relo("\x00\xf0\xff\x97", 4, true, -1, nullptr);
  // bl #0x4000
  check_insn_relo("\x00\x10\x00\x94", 4, true, -1, nullptr);

  // mov x0, #0
  // cbz x0, #-0x4000
  check_insn_relo("\x00\x00\x80\xd2\x00\x00\xfe\xb4", 8, true, -1, nullptr);
  // mov x0, #0
  // cbz x0, #0x4000
  check_insn_relo("\x00\x00\x80\xd2\x00\x00\x02\xb4", 8, true, -1, nullptr);

  // ldr x0, #-0x4000
  check_insn_relo("\x00\x00\xfe\x58", 4, true, -1, nullptr);
  // ldr x0, #0x4000
  check_insn_relo("\x00\x00\x02\x58", 4, true, -1, nullptr);

  // Backward ADR is deliberately rejected: its returned address can be
  // dereferenced across the stolen entry with an unknown access width.
  // adr x0, #0x4000
  check_insn_relo("\x00\x00\x02\x10", 4, false, UC_ARM64_REG_X0, nullptr);

  // adrp x0, #-0x4000
  check_insn_relo("\xe0\xff\xff\x90", 4, false, UC_ARM64_REG_X0, nullptr);
  // adrp x0, #0x4000
  check_insn_relo("\x20\x00\x00\x90", 4, false, UC_ARM64_REG_X0, nullptr);

  // mov x0, #0
  // cmp x0, #0
  // b.eq #-0x4000
  check_insn_relo("\x00\x00\x80\xd2\x1f\x00\x00\xf1\x00\x00\xfe\x54", 12, true, -1, nullptr);
  // mov x0, #0
  // cmp x0, #0
  // b.eq #0x4000
  check_insn_relo("\x00\x00\x80\xd2\x1f\x00\x00\xf1\x00\x00\x02\x54", 12, true, -1, nullptr);

  // mov x0, #0xb
  // tbz w0, 2, #-0x4000
  check_insn_relo("\x60\x01\x80\xd2\x00\x00\x16\x36", 8, true, -1, nullptr);
  // mov x0, #0xb

  // mov x0, #0xb
  // tbz w0, 2, #0x4000
  check_insn_relo("\x60\x01\x80\xd2\x00\x00\x12\x36", 8, true, -1, nullptr);

  return 0;
}
