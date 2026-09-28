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

The review_self_hook_free test installs a Hook on libc free() itself. It
asserts that no invocation reaches the replacement before the original
pointer is published. The regression_patch_large_scratch test exercises
patch metadata spanning more than 64 memory pages.

The command below is an intentional *unsafe reproducer*, not part of the
passing suite: on x64, concurrent execution during an unsynchronized long
(multi-instruction) inline patch can crash.

    build-review/dobby_regression_lifecycle execute-race-long

A registry mutex or successful build does not fix this.

## Android ARM64

Build the opt-in fixture and run each mode in a fresh process:

    cmake -S . -B build-android-review -G Ninja \
      -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
      -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-28 \
      -DDOBBY_GENERATE_SHARED=OFF -DDOBBY_ANDROID_ARM64_REVIEW_TEST=ON
    cmake --build build-android-review --target dobby_android_arm64_review
    tests/run_android_arm64_review.sh \
      build-android-review/dobby_android_arm64_review SERIAL

Run the script separately for native AArch64 and for a translated ARM64 guest
on an x86_64 emulator. The script displays ABI and native-bridge properties.

adr-data must reject a default long Hook when preserving the returned
address would expose overwritten literal data. Both near modes must preserve
address identity and contents. literal-left-overlap checks an eight-byte
load beginning before the overwritten entry but intersecting it.

rollback-* injects failure of the original page's mprotect restore, then
checks unchanged bytes, unpublished original, successful retry and Destroy.
cross-core pins two execution threads to different CPUs and compares exact
old/new results after 160 install/remove API returns. It requires Linux
MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE; a successful local cache clear
alone is not sufficient. execute-race is separate: it only accepts old or
new values while the four-byte entry update is in flight.

This establishes the synchronized single-instruction path on tested
systems, not the safety of long patches under concurrent execution or
permission to replace a native bridge's privately owned PROT_NONE mapping.
