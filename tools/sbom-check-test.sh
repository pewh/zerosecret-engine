#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

checker=tools/sbom-check.sh
target=x86_64-unknown-linux-gnu
tmp=$(mktemp -d)
generated=apps/zs/zs-sbom-check.cdx.json
trap 'rm -rf "$tmp"; find . -name "zs-sbom-check.cdx.json" -type f -delete' EXIT
failures=0

if ! command -v cargo-cyclonedx >/dev/null 2>&1; then
  echo "sbom-check-test: cargo-cyclonedx is required" >&2
  exit 1
fi

pass() {
  echo "PASS: $1"
}

fail() {
  echo "FAIL: $1"
  failures=$((failures + 1))
}

cargo cyclonedx --manifest-path apps/zs/Cargo.toml --format json --spec-version 1.5 \
  --target "$target" --override-filename zs-sbom-check.cdx --quiet
mv "$generated" "$tmp/fresh.cdx.json"
find . -name "zs-sbom-check.cdx.json" -type f -delete

if bash "$checker" "$tmp/fresh.cdx.json" "$target"; then
  pass "a fresh SBOM covers the dependency tree"
else
  fail "a fresh SBOM covers the dependency tree"
fi

first=$(cargo tree --locked -p zs --target "$target" -e normal,build --prefix none --format '{p}' \
  | tail -n +2 | sed -E 's/^([^ ]+) v([^ ]+).*/\1@\2/' | head -n 1)
name=${first%@*}

jq --arg name "$name" 'del(.components[] | select(.name == $name))' \
  "$tmp/fresh.cdx.json" > "$tmp/missing.cdx.json"

set +e
bash "$checker" "$tmp/missing.cdx.json" "$target" > "$tmp/output" 2>&1
status=$?
set -e

if [ "$status" -eq 0 ]; then
  fail "a removed component is reported as missing"
elif ! grep -Fq -- "$name@" "$tmp/output"; then
  fail "a removed component is reported as missing: output does not name $name"
  sed 's/^/  /' "$tmp/output"
else
  pass "a removed component is reported as missing"
fi

if [ "$failures" -ne 0 ]; then
  echo "sbom-check-test: $failures case(s) failed" >&2
  exit 1
fi
echo "sbom-check-test: all cases passed"
