#!/usr/bin/env bash
# Reads the repository's releases as JSON on stdin (`gh api --paginate .../releases`, so
# drafts included and possibly several arrays) and fails when one already uses <tag>.
# `gh release create --draft` skips its own existing-release check, and GitHub accepts several
# drafts for one tag, so `publish` runs this before it attests anything: a second run for the
# same tag stops here instead of writing a second draft and a second set of attestations.
set -euo pipefail

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
  echo "usage: release-absent.sh <tag> < releases.json" >&2
  exit 2
fi

ids=$(jq -r --arg tag "$1" '.[] | select(.tag_name == $tag) | "\(.id) (draft: \(.draft))"')
if [ -n "$ids" ]; then
  echo "release: a release for $1 already exists: $(echo "$ids" | paste -sd ' ' -)" >&2
  echo "release: delete it before running the release again" >&2
  exit 1
fi
echo "release: no release uses $1 yet"
