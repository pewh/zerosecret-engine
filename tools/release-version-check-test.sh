#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

checker=tools/release-version-check.sh
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

check "tag matching the workspace version exits 0" 0 "" v0.4.0 0.4.0
check "tag above the workspace version exits 1" 1 "release: tag v0.5.0 does not match the workspace version" v0.5.0 0.4.0
check "tag without the v prefix exits 1" 1 "release: tag 0.4.0 does not match the workspace version" 0.4.0 0.4.0

if [ "$failures" -ne 0 ]; then
  echo "release-version-check-test: $failures case(s) failed" >&2
  exit 1
fi
echo "release-version-check-test: all cases passed"
