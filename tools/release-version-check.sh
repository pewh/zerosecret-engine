#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: release-version-check.sh <tag> <cargo-version>" >&2
  exit 2
fi

if [ "$1" = "v$2" ]; then
  exit 0
fi

echo "release: tag $1 does not match the workspace version" >&2
exit 1
