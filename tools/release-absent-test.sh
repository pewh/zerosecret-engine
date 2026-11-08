#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

script=tools/release-absent.sh
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
  json=$4
  shift 4
  set +e
  printf '%s' "$json" | bash "$script" "$@" > "$tmp/output" 2>&1
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

check "no release exits 0" 0 "release: no release uses v0.4.0 yet" '[]' v0.4.0
check "only other tags exit 0" 0 "" '[{"id":1,"tag_name":"v0.3.0","draft":false}]' v0.4.0
check "an existing draft exits 1" 1 "release: a release for v0.4.0 already exists: 7 (draft: true)" \
  '[{"id":1,"tag_name":"v0.3.0","draft":false},{"id":7,"tag_name":"v0.4.0","draft":true}]' v0.4.0
check "a match on a later page exits 1" 1 "release: a release for v0.4.0 already exists: 9 (draft: false)" \
  '[{"id":1,"tag_name":"v0.3.0","draft":false}][{"id":9,"tag_name":"v0.4.0","draft":false}]' v0.4.0
check "an empty tag exits 2" 2 "usage:" '[]' ""

if [ "$failures" -ne 0 ]; then
  echo "release-absent-test: $failures case(s) failed" >&2
  exit 1
fi
echo "release-absent-test: all cases passed"
