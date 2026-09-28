# Dobby correctness review regressions

The three new counterexamples are exercised independently. A successful
near-branch test is not evidence that the normal long-patch path is correct.

## Host

Build the standalone tests and, when Capstone/Unicorn are available, the
existing instruction emulator tests:

    cmake -S . -B build-review -G Ninja -DDOBBY_GENERATE_SHARED=OFF \
      -DDOBBY_REGRESSION_TESTS=ON -DDOBBY_SELF_HOOK_REVIEW_TEST=ON \
      -DBUILD_TEST=ON
    cmake --build build-review
    ctest --test-dir build-review --output-on-failure

The review_self_hook_free and review_self_hook_mprotect tests install Hooks
on libc memory functions themselves. They assert that no invocation reaches
the replacement before the original pointer is published.
The regression_patch_large_scratch test exercises
patch metadata spanning more than 64 memory pages.

The command below is an intentional *unsafe reproducer*, not part of the
passing suite: on x64, concurrent execution during an unsynchronized long
(multi-instruction) inline patch can crash.

    build-review/dobby_regression_lifecycle execute-race-long

A registry mutex or successful build does not fix this.

## x64 cooperative execution lease (Linux and Android)

The opt-in `DobbyHookOptionsQuiescentV2` provides an exclusive, *host-proven*
lease. The host's acquire callback must block all possible entrants and new
threads, wait for in-flight calls to leave the overwritten instruction range,
and verify no saved PC is inside it. Dobby holds the lease across Commit,
rollback, cross-core sync and Destroy. The callback and user_data must outlive
any retained physical Hook until successful recovery.

The `regression_x64_exclusive_patch_lease` CTest uses a real reader/writer
gate for all fixture entrants, 150 install/destroy cycles and failure
injection after a physical patch was already published. It also verifies:
an unmanaged safe-request is rejected without writes; acquire refusal
preserves Prepared ownership; Destroy refusal retains the installed Handle;
Recover obtains another lease before restoring the original bytes; all
leases balance after cleanup.

On an x86_64 Android emulator the equivalent opt-in test is built with
`-DDOBBY_ANDROID_X64_QUIESCENCE_TEST=ON` and runs as
`dobby_android_x64_quiescence_review`. This **does not** establish generic
stop-the-world or safety for legacy `DobbyHook` in a process with unknown
entrants. In particular, a running linker or MediaProvider FUSE daemon
cannot claim a cooperative lease without owning all calling threads.

## Android ARM64

Build the opt-in fixture and run each mode in a fresh process:

    cmake -S . -B build-android-review -G Ninja \
      -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
      -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-28 \
      -DDOBBY_GENERATE_SHARED=OFF -DDOBBY_ANDROID_ARM64_REVIEW_TEST=ON
    cmake --build build-android-review --target \
      dobby_android_arm64_review dobby_android_sync_failure_review
    tests/run_android_arm64_review.sh \
      build-android-review/dobby_android_arm64_review SERIAL

Run the script separately for native AArch64 and for a translated ARM64 guest
on an x86_64 emulator. The script displays ABI and native-bridge properties.

adr-data must reject a default long Hook when preserving the returned
address would expose overwritten literal data. Both near modes must preserve
address identity and contents. literal-left-overlap checks an eight-byte
load beginning before the overwritten entry but intersecting it.
adr-left-overlap rejects a backward ADR even with a four-byte patch: ADR
has no consumer access-width metadata and the returned pointer can expose
bytes written by the Hook.

rollback-* injects failure of the original page's mprotect restore, then
checks unchanged bytes, unpublished original, successful retry and Destroy.
cross-core pins two execution threads to different CPUs and compares exact
old/new results after 160 install/remove API returns. It requires Linux
MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE; a successful local cache clear
alone is not sufficient. execute-race is separate: it only accepts old or
new values while the four-byte entry update is in flight.
sync-failure intentionally fails the cross-core barrier twice. It requires
the failed install to retain metadata even if local bytes match the original,
reject duplicate installs, and release that metadata only after explicit
Destroy successfully re-synchronizes the original instruction stream.

On AArch64 Linux/Android, this fork requires kernel sync-core membarrier
support (Linux 4.16 or a suitable vendor backport). On older kernels lacking
that capability, CodePatch intentionally fails closed rather than treating
a local cache flush as cross-core synchronization.

This establishes the synchronized single-instruction path on tested
systems, not the safety of long patches under concurrent execution or
permission to replace a native bridge's privately owned PROT_NONE mapping.
