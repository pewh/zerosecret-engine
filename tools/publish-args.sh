#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
  echo "usage: publish-args.sh <tag>" >&2
  exit 1
fi

printf '%s --draft --verify-tag --title %s --notes-from-tag dist/*\n' "$1" "$1"
