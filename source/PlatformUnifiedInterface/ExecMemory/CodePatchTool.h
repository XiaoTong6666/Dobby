#pragma once

MemoryOperationError DobbyCodePatch(void *address, uint8_t *buffer, uint32_t buffer_size);

// AArch64 Linux/Android must register the process-wide execution pipeline
// synchronization capability before preparing or publishing an inline hook.
#if defined(__aarch64__) && (defined(__ANDROID__) || defined(__linux__))
bool DobbyEnsureInstructionSync();
#else
inline bool DobbyEnsureInstructionSync() { return true; }
#endif

// A trusted external x64 quiescence lease requires process-wide SYNC_CORE
// before resuming after an executable text write. Legacy x64 patches do not
// silently acquire this guarantee.
#if defined(__x86_64__) && (defined(__ANDROID__) || defined(__linux__))
bool DobbyEnsureExclusiveInstructionSync();
void DobbySetExclusiveInstructionSync(bool required);
#else
inline bool DobbyEnsureExclusiveInstructionSync() { return false; }
inline void DobbySetExclusiveInstructionSync(bool) {}
#endif
