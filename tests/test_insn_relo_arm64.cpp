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

  if (argc == 2 && strcmp(argv[1], "--x17-branch") == 0) {
    // A taken conditional branch must not clobber an otherwise-live x17.
    // Both paths fault at the same unmapped target; compare the saved register.
    check_insn_relo("\x00\x00\x80\xd2\x1f\x00\x00\xf1\x00\x00\x02\x54", 12,
                    false, -1, ^(UniconEmulator *orig, UniconEmulator *relo) {
                      assert(orig->readRegister(UC_ARM64_REG_X17) ==
                             relo->readRegister(UC_ARM64_REG_X17));
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

  // adr x0, #-0x4000
  check_insn_relo("\x00\x00\xfe\x10", 4, false, UC_ARM64_REG_X0, nullptr);
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
