#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

guard=tools/macos-guard.sh
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
  bash "$guard" "$@" > "$tmp/output" 2>&1
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

check "public repository exits 0" 0 "" false
check "private repository exits 1" 1 "macos-guard: the engine repository is private; macOS coverage needs M1 or M2 (ADR)" true
check "empty visibility exits 1" 1 "macos-guard: unknown repository visibility" ""
check "uppercase TRUE exits 1" 1 "macos-guard: unknown repository visibility" TRUE

if [ "$failures" -ne 0 ]; then
  echo "macos-guard-test: $failures case(s) failed" >&2
  exit 1
fi
echo "macos-guard-test: all cases passed"
