#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

script=tools/publish-args.sh
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

if bash "$script" v0.4.0 > "$tmp/args" 2>&1; then
  args=$(cat "$tmp/args")
  if [[ "$args" != *"--draft"* ]]; then
    fail "the arguments create a draft"
  elif [[ "$args" != *"--verify-tag"* ]]; then
    fail "the arguments refuse a second run for the same tag"
  elif [[ "$args" != *"--title v0.4.0"* ]]; then
    fail "the arguments carry the tag as the title"
  elif [[ "$args" == *"--clobber"* ]]; then
    fail "the arguments must never replace existing assets"
  else
    pass "the arguments create a draft and never clobber"
  fi
else
  fail "a tag produces arguments"
  sed 's/^/  /' "$tmp/args"
fi

set +e
bash "$script" > "$tmp/empty" 2>&1
status=$?
set -e
if [ "$status" -eq 0 ]; then
  fail "an empty tag is refused"
else
  pass "an empty tag is refused"
fi

if [ "$failures" -ne 0 ]; then
  echo "publish-args-test: $failures case(s) failed" >&2
  exit 1
fi
echo "publish-args-test: all cases passed"
