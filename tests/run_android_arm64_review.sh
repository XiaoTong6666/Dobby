#!/usr/bin/env bash
# Run each case in its own Android process. Select the device explicitly so a
# translated ARM64 AVD is not mistaken for a native AArch64 CPU.
set -euo pipefail
if [[ $# -ne 2 ]]; then
  echo "Usage: $0 /path/to/dobby_android_arm64_review ADB_SERIAL" >&2
  exit 2
fi
binary=$1
serial=$2
remote=/data/local/tmp/dobby_android_arm64_review
adb -s "$serial" push "$binary" "$remote" >/dev/null
adb -s "$serial" shell chmod 755 "$remote"
printf 'DEVICE=%s ABI=%s BRIDGE=%s\n' "$serial" \
  "$(adb -s "$serial" shell getprop ro.product.cpu.abilist | tr -d '\r')" \
  "$(adb -s "$serial" shell getprop ro.dalvik.vm.native.bridge | tr -d '\r')"
for mode in default near required adr-data adr-data-near adr-data-required \
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
echo "ALL_ANDROID_REVIEW_MODES_PASSED"
