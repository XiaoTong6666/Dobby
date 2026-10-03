#ifndef dobby_h
#define dobby_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

void log_set_level(int level);
void log_set_tag(const char *tag);
void log_enable_time_tag();
void log_switch_to_syslog();
void log_switch_to_file(const char *path);

typedef enum {
  kMemoryOperationSuccess,
  kMemoryOperationError,
  kNotSupportAllocateExecutableMemory,
  kNotEnough,
  kNone,
  kInstructionSyncUnavailable,
  kInstructionSyncFailed
} MemoryOperationError;

typedef uintptr_t addr_t;
typedef uint32_t addr32_t;
typedef uint64_t addr64_t;
typedef void (*dobby_dummy_func_t)();
typedef void (*asm_func_t)();

MemoryOperationError DobbyCodePatch(void *address, uint8_t *buffer, uint32_t buffer_size);

#if !defined(DISABLE_ARCH_DETECT)
#if defined(__arm__)
#define TARGET_ARCH_ARM 1
#elif defined(__arm64__) || defined(__aarch64__)
#define TARGET_ARCH_ARM64 1
#elif defined(_M_IX86) || defined(__i386__)
#define TARGET_ARCH_IA32 1
#elif defined(_M_X64) || defined(__x86_64__)
#define TARGET_ARCH_X64 1
#else
#error Target architecture was not detected as supported by Dobby
#endif
#endif

#if defined(TARGET_ARCH_ARM)
typedef struct {
  uint32_t dummy_0;
  uint32_t dummy_1;

  uint32_t dummy_2;
  uint32_t sp;

  union {
    uint32_t r[13];
    struct {
      uint32_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12;
    } regs;
  } general;

  uint32_t lr;
} DobbyRegisterContext;
#elif defined(TARGET_ARCH_ARM64)
#define ARM64_TMP_REG_NDX_0 17

typedef union _FPReg {
  __int128_t q;
  struct {
    double d1;
    double d2;
  } d;
  struct {
    float f1;
    float f2;
    float f3;
    float f4;
  } f;
} FPReg;

// register context
typedef struct {
  uint64_t dmmpy_0; // dummy placeholder
  uint64_t sp;

  uint64_t dmmpy_1; // dummy placeholder
  union {
    uint64_t x[29];
    struct {
      uint64_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18, x19, x20, x21, x22,
          x23, x24, x25, x26, x27, x28;
    } regs;
  } general;

  uint64_t fp;
  uint64_t lr;

  union {
    FPReg q[32];
    struct {
      FPReg q0, q1, q2, q3, q4, q5, q6, q7;
      // [!!! READ ME !!!]
      // for Arm64, can't access q8 - q31, unless you enable full floating-point register pack
      FPReg q8, q9, q10, q11, q12, q13, q14, q15, q16, q17, q18, q19, q20, q21, q22, q23, q24, q25, q26, q27, q28, q29,
          q30, q31;
    } regs;
  } floating;
} DobbyRegisterContext;
#elif defined(TARGET_ARCH_IA32)
typedef struct _RegisterContext {
  uint32_t dummy_0;
  uint32_t esp;

  uint32_t dummy_1;
  uint32_t flags;

  union {
    struct {
      uint32_t eax, ebx, ecx, edx, ebp, esp, edi, esi;
    } regs;
  } general;

} DobbyRegisterContext;
#elif defined(TARGET_ARCH_X64)
typedef struct {
  uint64_t dummy_0;
  uint64_t rsp;

  union {
    struct {
      uint64_t rax, rbx, rcx, rdx, rbp, rsp, rdi, rsi, r8, r9, r10, r11, r12, r13, r14, r15;
    } regs;
  } general;

  uint64_t dummy_1;
  uint64_t flags;
} DobbyRegisterContext;
#endif

#define RT_FAILED -1
#define RT_SUCCESS 0
typedef enum { RS_FAILED = -1, RS_SUCCESS = 0 } RetStatus;

// DobbyWrap <==> DobbyInstrument, so use DobbyInstrument instead of DobbyWrap
#if 0
// wrap function with pre_call and post_call
typedef void (*PreCallTy)(DobbyRegisterContext *ctx, const InterceptEntry *info);
typedef void (*PostCallTy)(DobbyRegisterContext *ctx, const InterceptEntry *info);
int DobbyWrap(void *function_address, PreCallTy pre_call, PostCallTy post_call);
#endif

// Legacy one-shot function inline hook.
//
// If origin_func is supplied, Dobby publishes the callable original trampoline
// before the physical entry patch can make replace_func reachable. On a normal
// failure it resets *origin_func to null. The exceptional failure case is a
// post-publication recovery failure: Dobby returns RS_FAILED but keeps
// *origin_func callable and retains target ownership because replace_func may
// still be reachable. Legacy callers that observe RS_FAILED with a non-null
// origin must keep that trampoline alive and call DobbyDestroy(address) to
// complete recovery before forgetting the target. New integrations should use
// DobbyPrepareHook/DobbyCommitHook and inspect DOBBY_HOOK_RECOVERY_REQUIRED.
int DobbyHook(void *address, dobby_dummy_func_t replace_func, dobby_dummy_func_t *origin_func);

// V1 transaction API. A handle is a monotonically assigned process-local ID,
// not a pointer: stale IDs never alias another hook after Abort/Destroy.
// Prepared hooks reserve their target without modifying its original entry.
// Publish the returned backup before Commit makes replacement reachable.
#define DOBBY_HOOK_TRANSACTION_API_VERSION 1
typedef uint64_t DobbyHookHandle;
typedef enum {
  DOBBY_BRANCH_LEGACY = 0,
  DOBBY_BRANCH_PREFER_NEAR = 1,
  DOBBY_BRANCH_REQUIRE_NEAR = 2,
  DOBBY_BRANCH_FORCE_LONG = 3
} DobbyHookBranchPolicy;
typedef enum {
  DOBBY_HOOK_OK = 0,
  DOBBY_HOOK_INVALID_ARGUMENT,
  DOBBY_HOOK_TARGET_BUSY,
  DOBBY_HOOK_NEAR_UNAVAILABLE,
  DOBBY_HOOK_RELOCATION_FAILED,
  DOBBY_HOOK_CONCURRENCY_UNSUPPORTED,
  DOBBY_HOOK_SYNC_UNAVAILABLE,
  DOBBY_HOOK_SYNC_FAILED,
  DOBBY_HOOK_PATCH_FAILED,
  DOBBY_HOOK_RECOVERY_REQUIRED,
  DOBBY_HOOK_INVALID_HANDLE,
  DOBBY_HOOK_INVALID_STATE,
  DOBBY_HOOK_TARGET_CHANGED
} DobbyHookStatus;
enum { DOBBY_HOOK_REQUIRE_CONCURRENT_SAFE = 1u };
typedef struct {
  uint32_t struct_size;
  uint32_t branch_policy;
  uint32_t flags;
  uint32_t reserved;
  void *target;
  dobby_dummy_func_t replacement;
} DobbyHookOptions;

// Opt-in, trusted-host protocol for x64 Linux/Android multi-byte patches.
// acquire() MUST stop every thread that could execute the target (including
// new thread creation), and verify that no saved PC lies in the entire
// overwritten instruction range. It must not call Dobby or return until that
// condition holds. release() restores execution. Dobby keeps the lease across
// write, rollback and sync-core. This does NOT make an arbitrary process with
// uncooperative threads safe; use the base options to fail closed there.
// user_data and both callbacks MUST remain valid until successful Destroy or
// explicit recovery has released the transaction. A failed Commit or Destroy
// may retain that ownership; freeing the host before cleanup is invalid.
typedef int (*DobbyQuiescenceAcquire)(void *user_data, void *target, uint32_t patch_size);
typedef void (*DobbyQuiescenceRelease)(void *user_data);
typedef struct {
  DobbyHookOptions base; // base.struct_size = sizeof(DobbyHookOptionsQuiescentV2)
  void *user_data;
  DobbyQuiescenceAcquire acquire;
  DobbyQuiescenceRelease release;
} DobbyHookOptionsQuiescentV2;
typedef struct {
  uint32_t struct_size;
  uint32_t status; // DobbyHookStatus
  uint32_t cause;  // original failure when status == RECOVERY_REQUIRED
  uint32_t reserved;
  uint32_t patch_size;         // physical entry bytes chosen by the planner
  uint32_t selected_branch;    // actual near/long routing, not the preference
  DobbyHookHandle handle;      // nonzero only while the transaction is owned
  dobby_dummy_func_t original; // callable after successful Prepare
  uint8_t target_may_be_patched;
  uint8_t restored_and_synchronized;
  uint8_t ever_published; // a branch may have been fetched before rollback
  uint8_t reserved_bytes[5];
} DobbyHookResult;

int DobbyPrepareHook(const DobbyHookOptions *options, DobbyHookResult *result);
int DobbyCommitHook(DobbyHookHandle handle, DobbyHookResult *result);
int DobbyAbortHook(DobbyHookHandle handle, DobbyHookResult *result);
int DobbyRecoverHook(DobbyHookHandle handle, DobbyHookResult *result);
int DobbyDestroyHook(DobbyHookHandle handle, DobbyHookResult *result);

// dynamic binary instruction instrument
// [!!! READ ME !!!]
// for Arm64, can't access q8 - q31, unless enable full floating-point register pack
typedef void (*dobby_instrument_callback_t)(void *address, DobbyRegisterContext *ctx);
int DobbyInstrument(void *address, dobby_instrument_callback_t pre_handler);

int DobbyDestroy(void *address);

const char *DobbyGetVersion();

void *DobbySymbolResolver(const char *image_name, const char *symbol_name);

int DobbyImportTableReplace(char *image_name, char *symbol_name, dobby_dummy_func_t fake_func,
                            dobby_dummy_func_t *orig_func);

// [!!! READ ME !!!]
// for arm, Arm64, dobby will try use b xxx instead of ldr absolute indirect branch
// for x64, dobby always use absolute indirect jump
#if defined(__arm__) || defined(__arm64__) || defined(__aarch64__) || defined(_M_IX86) || defined(__i386__) ||         \
    defined(_M_X64) || defined(__x86_64__)
void dobby_enable_near_branch_trampoline();
void dobby_disable_near_branch_trampoline();
// Require a four-byte near branch instead of falling back to a long inline
// patch. Use this when the target entry is too short for a normal trampoline.
// This is a process-wide setting; configure it before installing hooks.
void dobby_require_near_branch_trampoline(bool required);
#endif

#ifdef __cplusplus
}
#endif

#endif
