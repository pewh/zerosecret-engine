#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: sbom-check.sh <cdx.json> <target>" >&2
  exit 2
fi
file=$1
target=$2
if [ ! -f "$file" ]; then
  echo "sbom-check: no such file: $file" >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "sbom-check: jq is required" >&2
  exit 1
fi

root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

jq -r '.components[] | "\(.name)@\(.version)"' "$file" | sort -u > "$tmp/sbom"

(
  cd "$root"
  cargo tree --locked -p zs --target "$target" -e normal,build --prefix none --format '{p}'
) | sed -E 's/^([^ ]+) v([^ ]+).*/\1@\2/' | tail -n +2 | sort -u > "$tmp/tree"

if [ ! -s "$tmp/tree" ]; then
  echo "sbom-check: cargo tree reported no dependency for $target" >&2
  exit 1
fi

missing=$(comm -23 "$tmp/tree" "$tmp/sbom" | head -n 1)
if [ -n "$missing" ]; then
  echo "sbom-check: $missing is missing from $file" >&2
  exit 1
fi

count=$(wc -l < "$tmp/tree" | tr -d ' ')
echo "sbom-check: $count crates for $target are in $file"
