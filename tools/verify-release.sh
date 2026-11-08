#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
  echo "usage: verify-release.sh <tag>" >&2
  exit 1
fi
tag=$1
repo=pewh/zerosecret-engine

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

gh release download "$tag" --repo "$repo" --dir "$tmp"
cd "$tmp"

sha256sum -c SHA256SUMS
echo "verify-release: SHA256SUMS matches every downloaded asset"

for file in *; do
  gh attestation verify "$file" --repo "$repo" > /dev/null
done
echo "verify-release: every asset carries an attestation"

archive=$(ls zs-*.tar.gz zs-*.zip 2>/dev/null | head -n 1)
cp "$archive" tampered
printf 'X' | dd of=tampered bs=1 seek=0 conv=notrunc status=none
if gh attestation verify tampered --repo "$repo" > /dev/null 2>&1; then
  echo "verify-release: a byte-flipped copy passed attestation verification" >&2
  exit 1
fi
echo "verify-release: a byte-flipped copy was rejected"
