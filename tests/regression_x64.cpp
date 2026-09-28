#include "InstructionRelocation/x86/InstructionRelocationX86Shared.h"

#include <cstdio>
#include <cstring>

static bool Check(const char *name, const uint8_t *original, size_t original_size,
                  const uint8_t *expected, size_t expected_size) {
  uint8_t input[16] = {};
  memcpy(input, original, original_size);
  CodeBufferBase output;
  x86_insn_decode_t decoded = {};
  GenRelocateSingleX86Insn(0x100000, 0x200000, input, &output, decoded, 64);
  const bool ok = output.GetBufferSize() == expected_size &&
                  memcmp(output.GetBuffer(), expected, expected_size) == 0;
  if (!ok) {
    fprintf(stderr, "%s: expected", name);
    for (size_t i = 0; i < expected_size; ++i) fprintf(stderr, " %02x", expected[i]);
    fprintf(stderr, "; got");
    for (size_t i = 0; i < output.GetBufferSize(); ++i) fprintf(stderr, " %02x", output.GetBuffer()[i]);
    fprintf(stderr, "\n");
  }
  return ok;
}

int main() {
  // JZ/JNZ must retain the short Jcc opcode rather than the 0F 8x near-Jcc opcode.
  const uint8_t jz[] = {0x74, 0x02};
  const uint8_t jz_expected[] = {0x74, 0x02, 0xeb, 0x0e, 0xff, 0x25, 0, 0, 0, 0, 0x04, 0x00, 0x10, 0, 0, 0, 0, 0};
  const uint8_t jnz[] = {0x75, 0xfe};
  const uint8_t jnz_expected[] = {0x75, 0x02, 0xeb, 0x0e, 0xff, 0x25, 0, 0, 0, 0, 0x00, 0x00, 0x10, 0, 0, 0, 0};
  // CALL [RIP+2]; JMP +8; literal target. A returning callee must skip the literal.
  const uint8_t call[] = {0xe8, 0, 0, 0, 0};
  const uint8_t call_expected[] = {0xff, 0x15, 0x02, 0, 0, 0, 0xeb, 0x08,
                                   0x05, 0, 0x10, 0, 0, 0, 0, 0};
  bool ok = Check("JZ rel8", jz, sizeof(jz), jz_expected, sizeof(jz_expected));
  ok = Check("JNZ rel8", jnz, sizeof(jnz), jnz_expected, sizeof(jnz_expected)) && ok;
  ok = Check("CALL rel32 return", call, sizeof(call), call_expected, sizeof(call_expected)) && ok;
  return ok ? 0 : 1;
}
