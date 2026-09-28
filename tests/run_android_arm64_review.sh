#!/usr/bin/env bash
# Run each case in its own Android process. Select the device explicitly so a
# translated ARM64 AVD is not mistaken for a native AArch64 CPU.
set -euo pipefail
if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: $0 /path/to/dobby_android_arm64_review ADB_SERIAL [sync-failure-binary]" >&2
  exit 2
fi
binary=$1
serial=$2
if [[ $# -eq 3 ]]; then
  sync_binary=$3
else
  sync_binary="$(dirname "$binary")/dobby_android_sync_failure_review"
fi
if [[ ! -f "$sync_binary" ]]; then
  echo "Missing sync failure fixture: $sync_binary" >&2
  exit 2
fi
remote=/data/local/tmp/dobby_android_arm64_review
sync_remote=/data/local/tmp/dobby_android_sync_failure_review
adb -s "$serial" push "$binary" "$remote" >/dev/null
adb -s "$serial" push "$sync_binary" "$sync_remote" >/dev/null
adb -s "$serial" shell chmod 755 "$remote"
adb -s "$serial" shell chmod 755 "$sync_remote"
printf 'DEVICE=%s ABI=%s BRIDGE=%s\n' "$serial" \
  "$(adb -s "$serial" shell getprop ro.product.cpu.abilist | tr -d '\r')" \
  "$(adb -s "$serial" shell getprop ro.dalvik.vm.native.bridge | tr -d '\r')"
for mode in default near required adr-data adr-data-near adr-data-required \
            adr-left-overlap adr-left-overlap-near \
            literal-left-overlap literal-left-overlap-near literal-left-overlap-required \
            rollback-default rollback-near rollback-required \
            short reservation reservation-owned-gap cross-core execute-race; do
  if ! output=$(adb -s "$serial" shell "$remote" "$mode" 2>&1); then
    printf 'FAILED %s\n%s\n' "$mode" "$output" >&2
    exit 1
  fi
  if ! grep -q 'result=PASS' <<<"$output" || grep -q 'result=FAIL' <<<"$output"; then
    printf 'FAILED %s\n%s\n' "$mode" "$output" >&2
    exit 1
  fi
  printf 'PASS %-24s %s\n' "$mode" \
    "$(grep -E 'result=|adr-data:|literal-left-overlap:' <<<"$output" | tr '\n' ';')"
done
if ! output=$(adb -s "$serial" shell "$sync_remote" 2>&1); then
  printf 'FAILED sync-failure\n%s\n' "$output" >&2
  exit 1
fi
if ! grep -q 'result=PASS' <<<"$output" || grep -q 'result=FAIL' <<<"$output"; then
  printf 'FAILED sync-failure\n%s\n' "$output" >&2
  exit 1
fi
printf 'PASS %-24s %s\n' 'sync-failure' "$output"
echo "ALL_ANDROID_REVIEW_MODES_PASSED"
