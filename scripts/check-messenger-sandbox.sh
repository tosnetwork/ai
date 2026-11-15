#!/bin/sh
# Runs messenger's attachment scanner sandbox tests and fails unless all five
# ran and passed. They skip when bubblewrap, prlimit, systemd-run or a user
# systemd manager is missing; a skip here is a failure, so a host or runner
# that cannot provide the sandbox cannot report it as covered.
#
# usage: check-messenger-sandbox.sh <go test -run pattern for pkg/attachments>
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo"
pattern=$1

if ! out=$(go test -count=1 -v -run "$pattern" ./messenger/pkg/attachments 2>&1 &&
  go test -count=1 -v -run '^TestAdmitFetchesAuthenticatesAndScansBeforeReturningText$' ./messenger/pkg/attachmentadmission 2>&1); then
  printf '%s\n' "$out"
  exit 1
fi
printf '%s\n' "$out" | grep -E '^(--- |ok|FAIL)'
if printf '%s\n' "$out" | grep -q -- '--- SKIP'; then
  echo "an attachment sandbox test skipped" >&2
  exit 1
fi
passed=$(printf '%s\n' "$out" | grep -cE '^--- PASS' || true)
if [ "$passed" != 5 ]; then
  echo "expected 5 attachment sandbox tests to pass, $passed did" >&2
  exit 1
fi
