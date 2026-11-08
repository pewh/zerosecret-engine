#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

checker=tools/check-release-permissions.sh
fixtures=tools/testdata/workflows
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failures=0

pass() {
  echo "PASS: $1"
}

fail() {
  echo "FAIL: $1"
  failures=$((failures + 1))
}

check() {
  name=$1
  want_status=$2
  want_text=$3
  shift 3
  set +e
  bash "$checker" "$@" > "$tmp/output" 2>&1
  status=$?
  set -e
  if [ "$status" -ne "$want_status" ]; then
    fail "$name: exit $status, want $want_status"
    sed 's/^/  /' "$tmp/output"
    return
  fi
  if [ -n "$want_text" ] && ! grep -Fq -- "$want_text" "$tmp/output"; then
    fail "$name: output does not contain: $want_text"
    sed 's/^/  /' "$tmp/output"
    return
  fi
  pass "$name"
}

check "good.yml exits 0" 0 "" "$fixtures/good.yml"
check "build holding id-token exits 1" 1 "check-release-permissions: build holds id-token: write" "$fixtures/build-has-id-token.yml"
check "build holding write-all exits 1" 1 "check-release-permissions: build holds write-all" "$fixtures/build-has-write-all.yml"
check "build holding id-token in a one-line mapping exits 1" 1 "check-release-permissions: build holds id-token: write" "$fixtures/build-has-flow-id-token.yml"
check "build holding a quoted id-token exits 1" 1 "check-release-permissions: build holds id-token: write" "$fixtures/build-has-quoted-id-token.yml"
check "workflow-level write-all exits 1" 1 "check-release-permissions: workflow holds write-all" "$fixtures/workflow-write-all.yml"
check "workflow-level id-token exits 1" 1 "check-release-permissions: workflow holds id-token: write" "$fixtures/workflow-has-id-token.yml"
check "ungated publish exits 1" 1 "check-release-permissions: publish is not gated" "$fixtures/publish-ungated.yml"
check "publish gated with || exits 1" 1 "check-release-permissions: publish is not gated" "$fixtures/publish-or-gate.yml"
check "publish open to a dispatch on a tag exits 1" 1 "check-release-permissions: publish is not gated" "$fixtures/publish-dispatch-gate.yml"
check "ci.yml exits 0" 0 "" ".github/workflows/ci.yml"
check "release.yml exits 0" 0 "" ".github/workflows/release.yml"
check "multiple files exit 0" 0 "" "$fixtures/good.yml" ".github/workflows/ci.yml" ".github/workflows/release.yml"

if [ "$failures" -ne 0 ]; then
  echo "check-release-permissions-test: $failures case(s) failed" >&2
  exit 1
fi
echo "check-release-permissions-test: all cases passed"
