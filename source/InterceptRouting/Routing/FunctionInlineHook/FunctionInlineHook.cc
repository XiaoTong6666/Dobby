#include "dobby_internal.h"

#include "Interceptor.h"
#include "InterceptRouting/Routing/FunctionInlineHook/FunctionInlineHookRouting.h"
#include "InterceptRouting/HookFailure.h"
#include "InterceptRouting/QuiescenceGuard.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <memory>

#if !defined(BUILDING_KERNEL) && (defined(__ANDROID__) || defined(__linux__))
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#endif

namespace {

constexpr size_t kStrictEntryFingerprintBytes = 32;

enum class TargetBackingState {
  Match,
  Mismatch,
  Unverifiable,
};

#if !defined(BUILDING_KERNEL) && (defined(__ANDROID__) || defined(__linux__))
TargetBackingState CompareTargetWithBackingFile(addr_t address, size_t size) {
  if (!address || !size || size > 256 || address > UINTPTR_MAX - size)
    return TargetBackingState::Unverifiable;

  FILE *maps = fopen("/proc/self/maps", "re");
  if (!maps)
    return TargetBackingState::Unverifiable;

  TargetBackingState state = TargetBackingState::Unverifiable;
  char *line = nullptr;
  size_t line_capacity = 0;
  while (getline(&line, &line_capacity, maps) > 0) {
    unsigned long long begin = 0, end = 0, file_offset = 0, inode = 0;
    unsigned int dev_major = 0, dev_minor = 0;
    char perms[5] = {};
    int path_offset = 0;
    if (sscanf(line, "%llx-%llx %4s %llx %x:%x %llu %n", &begin, &end, perms, &file_offset, &dev_major, &dev_minor,
               &inode, &path_offset) < 7)
      continue;
    const auto map_begin = static_cast<addr_t>(begin);
    const auto map_end = static_cast<addr_t>(end);
    if (address < map_begin || address >= map_end || map_end - address < size)
      continue;
    if (perms[0] != 'r' || perms[2] != 'x' || path_offset <= 0)
      break;

    char *path = line + path_offset;
    size_t path_length = strlen(path);
    while (path_length && (path[path_length - 1] == '\n' || path[path_length - 1] == '\r' ||
                           path[path_length - 1] == ' ' || path[path_length - 1] == '\t'))
      path[--path_length] = '\0';
    constexpr char kDeletedSuffix[] = " (deleted)";
    constexpr size_t kDeletedSuffixLength = sizeof(kDeletedSuffix) - 1;
    if (!path_length || path[0] == '[' ||
        (path_length >= kDeletedSuffixLength && strcmp(path + path_length - kDeletedSuffixLength, kDeletedSuffix) == 0))
      break;

    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
      break;
    struct stat backing_stat {};
    if (fstat(fd, &backing_stat) != 0 || static_cast<unsigned long long>(backing_stat.st_ino) != inode ||
        static_cast<unsigned int>(major(backing_stat.st_dev)) != dev_major ||
        static_cast<unsigned int>(minor(backing_stat.st_dev)) != dev_minor) {
      close(fd);
      break;
    }
    std::array<uint8_t, 256> expected{};
    const off_t offset = static_cast<off_t>(file_offset + (address - map_begin));
    const ssize_t got = pread(fd, expected.data(), size, offset);
    close(fd);
    if (got != static_cast<ssize_t>(size))
      break;
    state = memcmp(reinterpret_cast<const void *>(address), expected.data(), size) == 0 ? TargetBackingState::Match
                                                                                        : TargetBackingState::Mismatch;
    break;
  }
  free(line);
  fclose(maps);
  return state;
}
#else
TargetBackingState CompareTargetWithBackingFile(addr_t, size_t) {
  return TargetBackingState::Unverifiable;
}
#endif

#if defined(TARGET_ARCH_ARM64)
bool IsArm64Bti(uint32_t instruction) {
  return (instruction & 0xffffff3fu) == 0xd503241fu;
}

bool IsArm64PacSpLandingPad(uint32_t instruction) {
  // PACIASP/PACIBSP are valid BTI-C landing pads on branch-protected ELF,
  // but unlike explicit BTI they mutate LR and are part of the function's
  // authentication semantics.  Do not skip/relocate them as if they were a
  // marker-only landing pad until Dobby has a dedicated PAuth entry scheme.
  return instruction == 0xd503233fu || instruction == 0xd503237fu;
}

bool IsArm64DirectBranch(uint32_t instruction) {
  return (instruction & 0xfc000000u) == 0x14000000u;
}

bool IsArm64Call(uint32_t instruction) {
  return (instruction & 0xfc000000u) == 0x94000000u;
}

bool IsArm64ConditionalBranch(uint32_t instruction) {
  return (instruction & 0xff000010u) == 0x54000000u;
}

bool IsArm64CompareBranch(uint32_t instruction) {
  return (instruction & 0x7e000000u) == 0x34000000u;
}

bool IsArm64TestBranch(uint32_t instruction) {
  return (instruction & 0x7e000000u) == 0x36000000u;
}

bool IsArm64IndirectBranch(uint32_t instruction) {
  return (instruction & 0xfffffc1fu) == 0xd61f0000u || (instruction & 0xfffffc1fu) == 0xd63f0000u;
}

bool IsArm64Return(uint32_t instruction) {
  return (instruction & 0xfffffc1fu) == 0xd65f0000u;
}

bool IsArm64AuthenticatedControlFlow(uint32_t instruction) {
  // RETAA / RETAB.
  if (instruction == 0xd65f0bffu || instruction == 0xd65f0fffu)
    return true;
  // ERETAA / ERETAB. These are privileged exception returns rather than
  // ordinary function returns, but they are still authenticated control flow
  // and therefore must not be treated as linear fall-through by the strict
  // verifier. Bit 10 selects key A/B.
  if ((instruction & 0xfffffbffu) == 0xd69f0bffu)
    return true;
  // BRAA/BRAB and BLRAA/BLRAB (register modifier), plus their Z variants.
  // The low register/key fields are intentionally masked: strict validation
  // only needs to know that the destination is authenticated and cannot be
  // proven statically here.
  const uint32_t class_bits = instruction & 0xffdff800u;
  return class_bits == 0xd71f0800u || class_bits == 0xd61f0800u;
}

addr_t DecodeArm64DirectBranchTarget(addr_t pc, uint32_t instruction) {
  int64_t immediate = static_cast<int64_t>(instruction & 0x03ffffffu);
  if (immediate & (int64_t{1} << 25))
    immediate |= ~((int64_t{1} << 26) - 1);
  return static_cast<addr_t>(static_cast<int64_t>(pc) + (immediate << 2));
}

addr_t DecodeArm64Imm19Target(addr_t pc, uint32_t instruction) {
  int64_t immediate = static_cast<int64_t>((instruction >> 5) & 0x7ffffu);
  if (immediate & (int64_t{1} << 18))
    immediate |= ~((int64_t{1} << 19) - 1);
  return static_cast<addr_t>(static_cast<int64_t>(pc) + (immediate << 2));
}

addr_t DecodeArm64Imm14Target(addr_t pc, uint32_t instruction) {
  int64_t immediate = static_cast<int64_t>((instruction >> 5) & 0x3fffu);
  if (immediate & (int64_t{1} << 13))
    immediate |= ~((int64_t{1} << 14) - 1);
  return static_cast<addr_t>(static_cast<int64_t>(pc) + (immediate << 2));
}

bool IsReadableAddress(addr_t address, size_t size) {
  if (!address || address > UINTPTR_MAX - size)
    return false;
  for (const auto &region : ProcessRuntimeUtility::GetProcessMemoryLayout()) {
    if (address >= region.start && address < region.end && region.end - address >= size &&
        region.permission != kNoAccess)
      return true;
  }
  return false;
}

enum class Arm64BackupValidation {
  Valid,
  Invalid,
  Unsupported,
};

Arm64BackupValidation ValidateArm64ResumeChain(addr_t resume, addr_t logical_target, uint32_t landing_pad_size,
                                               addr_t patch_begin, addr_t patch_end, addr_t replacement_address) {
  // This is deliberately a bounded control-flow-chain verifier, not a full
  // function disassembler.  Follow all immediately reachable direct branch
  // edges (including both sides of conditionals) until a normal instruction
  // forms a safe frontier.  Unknown indirect/PAuth control flow cannot be
  // proven and therefore fails closed in strict mode.
  std::array<addr_t, 32> pending{};
  std::array<addr_t, 32> visited{};
  size_t pending_count = 1;
  size_t visited_count = 0;
  pending[0] = resume;
  bool reached_safe_frontier = false;

  auto queue = [&](addr_t target) -> Arm64BackupValidation {
    if ((target >= patch_begin && target < patch_end) || target == replacement_address ||
        (landing_pad_size != 0 && target == logical_target))
      return Arm64BackupValidation::Invalid;
    for (size_t i = 0; i < visited_count; ++i) {
      if (visited[i] == target)
        return Arm64BackupValidation::Invalid;
    }
    for (size_t i = 0; i < pending_count; ++i) {
      if (pending[i] == target)
        return Arm64BackupValidation::Valid;
    }
    if (pending_count >= pending.size())
      return Arm64BackupValidation::Unsupported;
    pending[pending_count++] = target;
    return Arm64BackupValidation::Valid;
  };

  while (pending_count != 0) {
    const addr_t pc = pending[--pending_count];
    if ((pc >= patch_begin && pc < patch_end) || pc == replacement_address ||
        (landing_pad_size != 0 && pc == logical_target))
      return Arm64BackupValidation::Invalid;
    bool already_visited = false;
    for (size_t i = 0; i < visited_count; ++i) {
      if (visited[i] == pc) {
        already_visited = true;
        break;
      }
    }
    if (already_visited)
      continue;
    if (visited_count >= visited.size())
      return Arm64BackupValidation::Unsupported;
    visited[visited_count++] = pc;
    if (!IsReadableAddress(pc, sizeof(uint32_t)))
      return Arm64BackupValidation::Invalid;
    uint32_t instruction = 0;
    memcpy(&instruction, reinterpret_cast<const void *>(pc), sizeof(instruction));

    if (IsArm64AuthenticatedControlFlow(instruction) || IsArm64IndirectBranch(instruction))
      return Arm64BackupValidation::Unsupported;
    if (IsArm64Return(instruction)) {
      reached_safe_frontier = true;
      continue;
    }
    if (IsArm64DirectBranch(instruction)) {
      const addr_t target = DecodeArm64DirectBranchTarget(pc, instruction);
      if (target == pc)
        return Arm64BackupValidation::Invalid;
      const auto status = queue(target);
      if (status != Arm64BackupValidation::Valid)
        return status;
      continue;
    }
    if (IsArm64Call(instruction)) {
      const addr_t target = DecodeArm64DirectBranchTarget(pc, instruction);
      if ((target >= patch_begin && target < patch_end) || target == replacement_address)
        return Arm64BackupValidation::Invalid;
      const auto status = queue(pc + sizeof(uint32_t));
      if (status != Arm64BackupValidation::Valid)
        return status;
      continue;
    }
    if (IsArm64ConditionalBranch(instruction) || IsArm64CompareBranch(instruction) || IsArm64TestBranch(instruction)) {
      const addr_t target = IsArm64TestBranch(instruction) ? DecodeArm64Imm14Target(pc, instruction)
                                                           : DecodeArm64Imm19Target(pc, instruction);
      auto status = queue(target);
      if (status != Arm64BackupValidation::Valid)
        return status;
      status = queue(pc + sizeof(uint32_t));
      if (status != Arm64BackupValidation::Valid)
        return status;
      continue;
    }

    // A non-control-flow instruction is a safe frontier for the resume-chain
    // check.  The validator's purpose here is to reject immediate branch
    // chains back into the patched entry/replacement, not to infer arbitrary
    // whole-function CFG without symbol-size metadata.
    reached_safe_frontier = true;
  }
  return reached_safe_frontier ? Arm64BackupValidation::Valid : Arm64BackupValidation::Unsupported;
}

Arm64BackupValidation ValidateArm64Backup(const InterceptEntry *entry, dobby_dummy_func_t replacement) {
  if (!entry || !entry->origin_insn_size || !entry->relocated_addr || entry->relocated_size < sizeof(uint32_t))
    return Arm64BackupValidation::Invalid;

  if (entry->landing_pad_size != 0) {
    if (entry->landing_pad_size != sizeof(uint32_t) || entry->logical_target > UINTPTR_MAX - entry->landing_pad_size ||
        entry->patched_addr != entry->logical_target + entry->landing_pad_size ||
        !IsReadableAddress(entry->logical_target, sizeof(uint32_t)))
      return Arm64BackupValidation::Invalid;
    uint32_t landing = 0;
    memcpy(&landing, reinterpret_cast<const void *>(entry->logical_target), sizeof(landing));
    if (!IsArm64Bti(landing))
      return Arm64BackupValidation::Invalid;
  }

  const addr_t patch_begin = entry->patched_addr;
  if (patch_begin > UINTPTR_MAX - entry->origin_insn_size)
    return Arm64BackupValidation::Invalid;
  const addr_t patch_end = patch_begin + entry->origin_insn_size;
  const addr_t replacement_address = reinterpret_cast<addr_t>(replacement);
  const addr_t relocated_begin = entry->relocated_addr;
  if (relocated_begin > UINTPTR_MAX - entry->relocated_size)
    return Arm64BackupValidation::Invalid;
  const addr_t relocated_end = relocated_begin + entry->relocated_size;

  // Validate every statically reachable path through the generated backup,
  // not just its first instruction.  The common ARM64 near-hook backup is:
  //
  //   <relocated original instruction(s)>
  //   b patched_addr + stolen_size
  //
  // Looking only at instruction 0 would therefore miss exactly the broken
  // tail branch that can create replacement -> original -> replacement
  // recursion.  Keep the verifier deliberately conservative: direct control
  // flow must stay inside the relocated buffer or reach the exact resume
  // address; indirect/external branch shapes are not proven safe and fail
  // closed for callers that requested DOBBY_HOOK_VALIDATE_BACKUP.
  std::array<addr_t, 64> pending{};
  std::array<addr_t, 64> visited{};
  size_t pending_count = 1;
  size_t visited_count = 0;
  pending[0] = relocated_begin;
  bool reached_safe_terminal = false;

  auto queue = [&](addr_t target) -> Arm64BackupValidation {
    if (target == patch_end) {
      const auto resume_status = ValidateArm64ResumeChain(target, entry->logical_target, entry->landing_pad_size,
                                                          patch_begin, patch_end, replacement_address);
      if (resume_status == Arm64BackupValidation::Valid)
        reached_safe_terminal = true;
      return resume_status;
    }
    if ((target >= patch_begin && target < patch_end) || target == replacement_address)
      return Arm64BackupValidation::Invalid;
    if (target < relocated_begin || target >= relocated_end)
      return Arm64BackupValidation::Unsupported;
    for (size_t i = 0; i < visited_count; ++i) {
      if (visited[i] == target)
        return Arm64BackupValidation::Invalid;
    }
    for (size_t i = 0; i < pending_count; ++i) {
      if (pending[i] == target)
        return Arm64BackupValidation::Valid;
    }
    if (pending_count >= pending.size())
      return Arm64BackupValidation::Unsupported;
    pending[pending_count++] = target;
    return Arm64BackupValidation::Valid;
  };

  while (pending_count != 0) {
    const addr_t pc = pending[--pending_count];
    if ((pc >= patch_begin && pc < patch_end) || pc == replacement_address)
      return Arm64BackupValidation::Invalid;
    bool already_visited = false;
    for (size_t i = 0; i < visited_count; ++i) {
      if (visited[i] == pc) {
        already_visited = true;
        break;
      }
    }
    if (already_visited)
      continue;
    if (visited_count >= visited.size())
      return Arm64BackupValidation::Unsupported;
    visited[visited_count++] = pc;
    if (pc < relocated_begin || pc >= relocated_end)
      return Arm64BackupValidation::Unsupported;
    if (!IsReadableAddress(pc, sizeof(uint32_t)))
      return Arm64BackupValidation::Invalid;
    uint32_t instruction = 0;
    memcpy(&instruction, reinterpret_cast<const void *>(pc), sizeof(instruction));

    if (IsArm64DirectBranch(instruction)) {
      const addr_t target = DecodeArm64DirectBranchTarget(pc, instruction);
      if (target == pc)
        return Arm64BackupValidation::Invalid;
      const auto status = queue(target);
      if (status != Arm64BackupValidation::Valid)
        return status;
      continue;
    }

    if (IsArm64Call(instruction)) {
      const addr_t target = DecodeArm64DirectBranchTarget(pc, instruction);
      if ((target >= patch_begin && target < patch_end) || target == replacement_address ||
          (target >= relocated_begin && target < relocated_end))
        return Arm64BackupValidation::Invalid;
      const auto status = queue(pc + sizeof(uint32_t));
      if (status != Arm64BackupValidation::Valid)
        return status;
      continue;
    }

    if (IsArm64ConditionalBranch(instruction) || IsArm64CompareBranch(instruction) || IsArm64TestBranch(instruction)) {
      const addr_t target = IsArm64TestBranch(instruction) ? DecodeArm64Imm14Target(pc, instruction)
                                                           : DecodeArm64Imm19Target(pc, instruction);
      auto status = queue(target);
      if (status != Arm64BackupValidation::Valid)
        return status;
      status = queue(pc + sizeof(uint32_t));
      if (status != Arm64BackupValidation::Valid)
        return status;
      continue;
    }

    if (IsArm64AuthenticatedControlFlow(instruction))
      return Arm64BackupValidation::Unsupported;
    if (IsArm64Return(instruction)) {
      reached_safe_terminal = true;
      continue;
    }
    if (IsArm64IndirectBranch(instruction))
      return Arm64BackupValidation::Unsupported;

    const auto status = queue(pc + sizeof(uint32_t));
    if (status != Arm64BackupValidation::Valid)
      return status;
  }

  return reached_safe_terminal ? Arm64BackupValidation::Valid : Arm64BackupValidation::Invalid;
}
#endif

// All callers hold MutationMutex, including the legacy one-shot wrapper.
// Numeric tickets avoid a dangling opaque pointer after an address-based
// Destroy, Abort, or subsequent reuse of the same target address.
uint64_t g_next_transaction_id = 1;

InterceptEntry *FindTransaction(DobbyHookHandle handle) {
  if (!handle)
    return nullptr;
  auto *interceptor = Interceptor::SharedInstance();
  for (int i = 0; i < interceptor->count(); ++i) {
    auto *entry = const_cast<InterceptEntry *>(interceptor->getEntry(i));
    if (entry && entry->transaction_id == handle && entry->type == kFunctionInlineHook)
      return entry;
  }
  return nullptr;
}

bool ResetResult(DobbyHookResult *result) {
  if (!result || result->struct_size < sizeof(DobbyHookResult))
    return false;
  memset(result, 0, sizeof(*result));
  result->struct_size = sizeof(*result);
  return true;
}

int Fail(DobbyHookResult *result, DobbyHookStatus status, DobbyHookStatus cause = DOBBY_HOOK_OK) {
  if (result) {
    result->status = status;
    result->cause = cause == DOBBY_HOOK_OK ? status : cause;
  }
  return RS_FAILED;
}

DobbyHookStatus PatchCause(MemoryOperationError error) {
  switch (error) {
  case kInstructionSyncUnavailable:
    return DOBBY_HOOK_SYNC_UNAVAILABLE;
  case kInstructionSyncFailed:
    return DOBBY_HOOK_SYNC_FAILED;
  default:
    return DOBBY_HOOK_PATCH_FAILED;
  }
}

// The original branch is safe for concurrent execution only if its entire
// entry patch is one aligned atomic A64 instruction. Cross-core instruction
// synchronization is separately required by DobbyCodePatch on Linux/Android.
bool CanCommitConcurrently(const InterceptEntry *entry) {
#if defined(TARGET_ARCH_ARM64) && (defined(__ANDROID__) || defined(__linux__))
  return entry && entry->routing && entry->routing->GetTrampolineBuffer() &&
         entry->routing->GetTrampolineBuffer()->GetBufferSize() == sizeof(uint32_t) && (entry->patched_addr & 3u) == 0;
#elif defined(TARGET_ARCH_X64) && (defined(__ANDROID__) || defined(__linux__))
  return entry && entry->quiescence_acquire && entry->quiescence_release && entry->origin_insn_size &&
         entry->origin_insn_size <= sizeof(entry->origin_insns);
#else
  (void)entry;
  return false; // The x64 5-byte jump and other multi-byte patches are not atomic.
#endif
}

} // namespace

PUBLIC int DobbyPrepareHook(const DobbyHookOptions *options, DobbyHookResult *result) {
  std::lock_guard<std::recursive_mutex> mutation(Interceptor::MutationMutex());
  if (!ResetResult(result))
    return RS_FAILED;
  if (!options || options->struct_size < sizeof(DobbyHookOptions) || !options->target || !options->replacement ||
      options->reserved || options->branch_policy > DOBBY_BRANCH_FORCE_LONG ||
      (options->flags & ~(DOBBY_HOOK_REQUIRE_CONCURRENT_SAFE | DOBBY_HOOK_REQUIRE_PRISTINE_ENTRY |
                          DOBBY_HOOK_VALIDATE_BACKUP | DOBBY_HOOK_PRESERVE_LANDING_PAD)))
    return Fail(result, DOBBY_HOOK_INVALID_ARGUMENT);
  if (options->struct_size > sizeof(DobbyHookOptions) && options->struct_size < sizeof(DobbyHookOptionsQuiescentV2))
    return Fail(result, DOBBY_HOOK_INVALID_ARGUMENT);
  const auto *exclusive = options->struct_size >= sizeof(DobbyHookOptionsQuiescentV2)
                              ? reinterpret_cast<const DobbyHookOptionsQuiescentV2 *>(options)
                              : nullptr;
  if (exclusive) {
#if defined(TARGET_ARCH_X64) && (defined(__ANDROID__) || defined(__linux__))
    if (!(options->flags & DOBBY_HOOK_REQUIRE_CONCURRENT_SAFE) || !exclusive->acquire || !exclusive->release)
      return Fail(result, DOBBY_HOOK_INVALID_ARGUMENT);
#else
    return Fail(result, DOBBY_HOOK_INVALID_ARGUMENT);
#endif
  }

  void *address = options->target;
  dobby_dummy_func_t replacement = options->replacement;
#if defined(__APPLE__) && defined(__arm64__)
#if __has_feature(ptrauth_calls)
  address = ptrauth_strip(address, ptrauth_key_asia);
  replacement = ptrauth_strip(replacement, ptrauth_key_asia);
#endif
#endif

  const addr_t logical_target = reinterpret_cast<addr_t>(address);
  addr_t patch_target = logical_target;
  uint32_t landing_pad_size = 0;
#if defined(TARGET_ARCH_ARM64)
  if (options->flags & DOBBY_HOOK_PRESERVE_LANDING_PAD) {
    if (!IsReadableAddress(logical_target, sizeof(uint32_t)))
      return Fail(result, DOBBY_HOOK_TARGET_UNVERIFIABLE);
    uint32_t first = 0;
    memcpy(&first, reinterpret_cast<const void *>(logical_target), sizeof(first));
    if (IsArm64Bti(first)) {
      if (logical_target > UINTPTR_MAX - sizeof(uint32_t))
        return Fail(result, DOBBY_HOOK_TARGET_UNSUPPORTED);
      landing_pad_size = sizeof(uint32_t);
      patch_target = logical_target + landing_pad_size;
    } else if (IsArm64PacSpLandingPad(first)) {
      // PACIASP/PACIBSP are legitimate indirect-call landing pads but also
      // modify LR.  Treating them like marker-only BTI would break the
      // PAC/AUT pairing for replacement/original.  Fail closed until a
      // dedicated PAuth-aware patch/backup scheme exists.
      return Fail(result, DOBBY_HOOK_TARGET_UNSUPPORTED);
    }
  }
#else
  if (options->flags & DOBBY_HOOK_PRESERVE_LANDING_PAD)
    return Fail(result, DOBBY_HOOK_TARGET_UNSUPPORTED);
#endif

  if (Interceptor::SharedInstance()->find(logical_target) ||
      (patch_target != logical_target && Interceptor::SharedInstance()->find(patch_target)))
    return Fail(result, DOBBY_HOOK_TARGET_BUSY);
  if (!DobbyEnsureInstructionSync())
    return Fail(result, DOBBY_HOOK_SYNC_UNAVAILABLE);
  if (g_next_transaction_id == 0)
    return Fail(result, DOBBY_HOOK_INVALID_STATE); // Never reuse wrapped tickets.

  // Reject a foreign/prepatched entry before feeding its control flow into the
  // relocator. Fingerprint more than the first near-branch instruction: a
  // foreign framework may preserve the first instruction and patch the next
  // one. The exact planned range is checked again after routing.
  if (options->flags & DOBBY_HOOK_REQUIRE_PRISTINE_ENTRY) {
    const auto backing = CompareTargetWithBackingFile(logical_target, kStrictEntryFingerprintBytes);
    if (backing != TargetBackingState::Match)
      return Fail(result, backing == TargetBackingState::Mismatch ? DOBBY_HOOK_TARGET_PREPATCHED
                                                                  : DOBBY_HOOK_TARGET_UNVERIFIABLE);
  }

  std::unique_ptr<InterceptEntry> pending(new InterceptEntry(kFunctionInlineHook, logical_target));
  auto *entry = pending.get();
  entry->patched_addr = patch_target;
  entry->landing_pad_size = landing_pad_size;
  entry->transaction_id = g_next_transaction_id++;
  entry->branch_policy = options->branch_policy;
  entry->hook_flags = options->flags;
  if (exclusive) {
    entry->quiescence_user_data = exclusive->user_data;
    entry->quiescence_acquire = exclusive->acquire;
    entry->quiescence_release = exclusive->release;
  }
  auto *routing = new FunctionInlineHookRouting(entry, replacement);

  // Reserve BEFORE relocation. Another thread's Prepare or legacy DobbyHook
  // must reject this address while the caller is preparing its publication gate.
  Interceptor::SharedInstance()->add(entry);
  routing->Prepare();
  if (!routing->DispatchRouting() || !entry->relocated_addr) {
    const bool near_unavailable = routing->NearBranchUnavailable();
    Interceptor::SharedInstance()->remove(entry->patched_addr);
    return Fail(result, near_unavailable ? DOBBY_HOOK_NEAR_UNAVAILABLE : DOBBY_HOOK_RELOCATION_FAILED);
  }
  if (options->flags & DOBBY_HOOK_REQUIRE_PRISTINE_ENTRY) {
    const size_t strict_span =
        std::max(kStrictEntryFingerprintBytes, static_cast<size_t>(entry->landing_pad_size) + entry->origin_insn_size);
    const auto backing = CompareTargetWithBackingFile(entry->logical_target, strict_span);
    if (backing != TargetBackingState::Match) {
      Interceptor::SharedInstance()->remove(entry->patched_addr);
      return Fail(result, backing == TargetBackingState::Mismatch ? DOBBY_HOOK_TARGET_PREPATCHED
                                                                  : DOBBY_HOOK_TARGET_UNVERIFIABLE);
    }
  }
  if (options->flags & DOBBY_HOOK_VALIDATE_BACKUP) {
#if defined(TARGET_ARCH_ARM64)
    const auto validation = ValidateArm64Backup(entry, replacement);
    if (validation != Arm64BackupValidation::Valid) {
      Interceptor::SharedInstance()->remove(entry->patched_addr);
      return Fail(result, validation == Arm64BackupValidation::Unsupported ? DOBBY_HOOK_TARGET_UNSUPPORTED
                                                                           : DOBBY_HOOK_BACKUP_INVALID);
    }
#else
    Interceptor::SharedInstance()->remove(entry->patched_addr);
    return Fail(result, DOBBY_HOOK_TARGET_UNSUPPORTED);
#endif
  }
  if ((options->flags & DOBBY_HOOK_REQUIRE_CONCURRENT_SAFE) && !CanCommitConcurrently(entry)) {
    Interceptor::SharedInstance()->remove(entry->patched_addr);
    return Fail(result, DOBBY_HOOK_CONCURRENCY_UNSUPPORTED);
  }

  result->handle = entry->transaction_id;
  result->original = reinterpret_cast<dobby_dummy_func_t>(entry->relocated_addr);
  result->patch_size = static_cast<uint32_t>(entry->routing->GetTrampolineBuffer()->GetBufferSize());
#if defined(TARGET_ARCH_ARM64)
  result->selected_branch =
      result->patch_size == sizeof(uint32_t) ? DOBBY_BRANCH_REQUIRE_NEAR : DOBBY_BRANCH_FORCE_LONG;
#else
  result->selected_branch = DOBBY_BRANCH_FORCE_LONG;
#endif
  result->status = DOBBY_HOOK_OK;
  pending.release();
  return RS_SUCCESS;
}

PUBLIC int DobbyCommitHook(DobbyHookHandle handle, DobbyHookResult *result) {
  std::lock_guard<std::recursive_mutex> mutation(Interceptor::MutationMutex());
  if (!ResetResult(result))
    return RS_FAILED;
  auto *entry = FindTransaction(handle);
  if (!entry)
    return Fail(result, DOBBY_HOOK_INVALID_HANDLE);
  if (entry->state != InterceptEntryState::Installing)
    return Fail(result, DOBBY_HOOK_INVALID_STATE);

  result->handle = handle;
  result->original = reinterpret_cast<dobby_dummy_func_t>(entry->relocated_addr);
  result->patch_size = static_cast<uint32_t>(entry->routing->GetTrampolineBuffer()->GetBufferSize());
#if defined(TARGET_ARCH_ARM64)
  result->selected_branch =
      result->patch_size == sizeof(uint32_t) ? DOBBY_BRANCH_REQUIRE_NEAR : DOBBY_BRANCH_FORCE_LONG;
#else
  result->selected_branch = DOBBY_BRANCH_FORCE_LONG;
#endif
  DobbyScopedQuiescence exclusive(entry);
  if (!exclusive.Acquire())
    return Fail(result, exclusive.SyncUnavailable() ? DOBBY_HOOK_SYNC_UNAVAILABLE : DOBBY_HOOK_CONCURRENCY_UNSUPPORTED);
  // Prepare can outlive the caller's loader activity. Refuse to overwrite a
  // target whose original bytes were modified or unmapped in that interval.
  // The caller still owns a never-published handle and must Abort it.
  if (entry->hook_flags & DOBBY_HOOK_REQUIRE_PRISTINE_ENTRY) {
    const size_t strict_span =
        std::max(kStrictEntryFingerprintBytes, static_cast<size_t>(entry->landing_pad_size) + entry->origin_insn_size);
    const auto backing = CompareTargetWithBackingFile(entry->logical_target, strict_span);
    if (backing != TargetBackingState::Match)
      return Fail(result,
                  backing == TargetBackingState::Mismatch ? DOBBY_HOOK_TARGET_CHANGED : DOBBY_HOOK_TARGET_UNVERIFIABLE);
  }
  if (!DobbyOriginalEntryMatches(entry))
    return Fail(result, DOBBY_HOOK_TARGET_CHANGED);
  if (!entry->routing->Commit()) {
    const auto cause = PatchCause(entry->routing->LastPatchError());
    result->ever_published = DobbyLastPatchWasPublished();
    if (DobbyOriginalBytesRestored(entry)) {
      Interceptor::SharedInstance()->remove(entry->patched_addr);
      delete entry;
      result->handle = 0;
      result->original = nullptr;
      result->restored_and_synchronized = 1;
      return Fail(result, cause);
    }
    entry->state = InterceptEntryState::Removing;
    result->target_may_be_patched = 1;
    return Fail(result, DOBBY_HOOK_RECOVERY_REQUIRED, cause);
  }
  entry->state = InterceptEntryState::Active;
  result->target_may_be_patched = 1;
  result->ever_published = 1;
  result->status = DOBBY_HOOK_OK;
  return RS_SUCCESS;
}

PUBLIC int DobbyAbortHook(DobbyHookHandle handle, DobbyHookResult *result) {
  std::lock_guard<std::recursive_mutex> mutation(Interceptor::MutationMutex());
  if (!ResetResult(result))
    return RS_FAILED;
  auto *entry = FindTransaction(handle);
  if (!entry)
    return Fail(result, DOBBY_HOOK_INVALID_HANDLE);
  if (entry->state != InterceptEntryState::Installing)
    return Fail(result, DOBBY_HOOK_INVALID_STATE);
  Interceptor::SharedInstance()->remove(entry->logical_target);
  delete entry;
  result->restored_and_synchronized = 1; // Target was never patched.
  return RS_SUCCESS;
}

PUBLIC int DobbyDestroyHook(DobbyHookHandle handle, DobbyHookResult *result) {
  std::lock_guard<std::recursive_mutex> mutation(Interceptor::MutationMutex());
  if (!ResetResult(result))
    return RS_FAILED;
  auto *entry = FindTransaction(handle);
  if (!entry)
    return Fail(result, DOBBY_HOOK_INVALID_HANDLE);
  if (entry->state == InterceptEntryState::Installing)
    return Fail(result, DOBBY_HOOK_INVALID_STATE);
  if (entry->state == InterceptEntryState::Active && !DobbyInstalledEntryMatches(entry)) {
    result->handle = handle;
    result->original = reinterpret_cast<dobby_dummy_func_t>(entry->relocated_addr);
    result->target_may_be_patched = 1;
    return Fail(result, DOBBY_HOOK_TARGET_CHANGED);
  }
  const void *address = reinterpret_cast<void *>(entry->logical_target);
  if (DobbyDestroy(const_cast<void *>(address)) != RS_SUCCESS) {
    // DobbyDestroy performs a second ownership check after acquiring the
    // quiescence lease. If a foreign writer changed any byte in the complete
    // restore span between this wrapper's optimistic precheck and that lease,
    // surface TARGET_CHANGED instead of misreporting a recovery failure.
    auto *current = FindTransaction(handle);
    if (current && current->state == InterceptEntryState::Active && !DobbyInstalledEntryMatches(current)) {
      result->handle = handle;
      result->original = reinterpret_cast<dobby_dummy_func_t>(current->relocated_addr);
      result->target_may_be_patched = 1;
      return Fail(result, DOBBY_HOOK_TARGET_CHANGED);
    }
    result->handle = handle;
    result->target_may_be_patched = 1;
    const DobbyHookStatus cause =
        entry->routing ? PatchCause(entry->routing->LastPatchError()) : DOBBY_HOOK_PATCH_FAILED;
    return Fail(result, DOBBY_HOOK_RECOVERY_REQUIRED, cause);
  }
  result->restored_and_synchronized = 1;
  return RS_SUCCESS;
}

PUBLIC int DobbyRecoverHook(DobbyHookHandle handle, DobbyHookResult *result) {
  std::lock_guard<std::recursive_mutex> mutation(Interceptor::MutationMutex());
  if (!ResetResult(result))
    return RS_FAILED;
  auto *entry = FindTransaction(handle);
  if (!entry)
    return Fail(result, DOBBY_HOOK_INVALID_HANDLE);
  if (entry->state != InterceptEntryState::Removing)
    return Fail(result, DOBBY_HOOK_INVALID_STATE);
  result->struct_size = sizeof(*result);
  return DobbyDestroyHook(handle, result);
}

PUBLIC int DobbyHook(void *address, dobby_dummy_func_t replace_func, dobby_dummy_func_t *origin_func) {
  // Hold the same lock across both phases to preserve the legacy one-shot
  // ordering. Preserve the historical Dobby contract that the callable
  // original is visible to the caller before replacement code can become
  // reachable. This matters for a replacement that re-enters immediately
  // during the physical Commit path.
  std::lock_guard<std::recursive_mutex> mutation(Interceptor::MutationMutex());
  if (origin_func)
    *origin_func = nullptr;
  DobbyHookOptions options = {sizeof(options), DOBBY_BRANCH_LEGACY, 0, 0, address, replace_func};
  DobbyHookResult result = {sizeof(result)};
  if (DobbyPrepareHook(&options, &result) != RS_SUCCESS)
    return RS_FAILED;
  const auto handle = result.handle;
  if (origin_func)
    *origin_func = result.original;
  if (DobbyCommitHook(handle, &result) != RS_SUCCESS) {
    // If Commit never left a replacement reachable (or completed a fully
    // synchronized rollback), preserve the long-standing failure contract of
    // a null output. RECOVERY_REQUIRED is different: replacement code may
    // still execute, so withdrawing the already-published backup would make a
    // legacy replacement unable to call the original while Dobby retains the
    // target for explicit address-based recovery.
    if (origin_func && result.status != DOBBY_HOOK_RECOVERY_REQUIRED)
      *origin_func = nullptr;
    return RS_FAILED;
  }
  return RS_SUCCESS;
}
