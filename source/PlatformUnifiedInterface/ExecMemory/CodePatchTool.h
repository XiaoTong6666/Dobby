#pragma once

MemoryOperationError DobbyCodePatch(void *address, uint8_t *buffer, uint32_t buffer_size);

// AArch64 Linux/Android must register the process-wide execution pipeline
// synchronization capability before preparing or publishing an inline hook.
#if defined(__aarch64__) && (defined(__ANDROID__) || defined(__linux__))
bool DobbyEnsureInstructionSync();
#else
inline bool DobbyEnsureInstructionSync() { return true; }
#endif
