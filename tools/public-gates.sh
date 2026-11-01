#!/usr/bin/env bash
# Release gates for the public tree. Run from the root of the tree.
#
#   tools/public-gates.sh [names-file]
#
# The forbidden names come from names-file, or from $FORBIDDEN_NAMES (separated by newlines,
# commas or |). They are never printed: a hit is reported by file and line only. With no names
# and SKIP_NAME_GATE=1 (a pull request from a fork, which gets no secrets), gate 1 is skipped.
set -euo pipefail

status=0
fail() {
  echo "public-gates: $*" >&2
  status=1
}

names_raw=""
if [ $# -ge 1 ]; then
  names_raw=$(cat "$1")
elif [ -n "${FORBIDDEN_NAMES:-}" ]; then
  names_raw=$FORBIDDEN_NAMES
fi
names=$(printf '%s\n' "$names_raw" | tr '|' ',' | tr ',' '\n' |
  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' |
  grep -v -e '^$' -e '^#' | paste -sd'|' - || true)

list_files() {
  find . \( -path ./.git -o -path ./target \) -prune -o -type f -print
}

# Gate 1: no forbidden name in any file or path (whole word, any case).
if [ -z "$names" ] && [ "${SKIP_NAME_GATE:-}" = "1" ]; then
  echo "public-gates: gate 1 (names) skipped: SKIP_NAME_GATE=1 and no names given"
elif [ -z "$names" ]; then
  fail "gate 1 (names): no names given; pass a file or set FORBIDDEN_NAMES"
else
  hits=$(grep -rIniwE --exclude-dir=.git --exclude-dir=target -e "$names" . | cut -d: -f1,2 || true)
  if [ -n "$hits" ]; then
    fail "gate 1 (names): a forbidden name appears at:"
    printf '%s\n' "$hits" >&2
  fi
  paths=$(find . \( -path ./.git -o -path ./target \) -prune -o -print | grep -ciwE -e "$names" || true)
  if [ "$paths" != "0" ] && [ -n "$paths" ]; then
    fail "gate 1 (names): $paths file or directory names contain a forbidden name"
  fi
fi

# Gate 2: no secret, by gitleaks, over exactly the files this tree publishes.
#
# Not `gitleaks dir .`: that also reads `target/`, where dependency test fixtures carry
# `BEGIN PRIVATE KEY` strings, so the gate failed on any tree that had been built — and a gate
# that fails after a build is one people stop running. Stage the publishable files, which is
# the same set gates 1 and 3 use, and scan the copy. The copy also isolates the scan from a
# `.git` directory that a release directory need not have.
if command -v gitleaks > /dev/null 2>&1; then
  scan=$(mktemp -d)
  trap 'rm -rf "$scan"' EXIT
  if ! list_files | sed 's|^\./||' | tar -cf - -T - | tar -xf - -C "$scan"; then
    fail "gate 2 (secrets): could not stage the tree for scanning"
  elif [ -z "$(find "$scan" -type f -print -quit)" ]; then
    fail "gate 2 (secrets): staged tree is empty; refusing to pass"
  elif ! leaks=$(cd "$scan" && gitleaks dir . --redact --no-banner --verbose 2>&1); then
    fail "gate 2 (secrets): gitleaks found a secret (values redacted):"
    printf '%s\n' "$leaks" | grep -E '^(RuleID|File|Line):' >&2 ||
      printf '%s\n' "$leaks" | tail -5 >&2
  fi
else
  fail "gate 2 (secrets): gitleaks is not installed"
fi

# Gate 3: no local secret files, no private directories, no absolute home paths.
found=$(find . \( -path ./.git -o -path ./target \) -prune -o \
  \( -name .env -o -name '.env.*' -o -name '*.zerosecret_backup_*' \
  -o -name .zs-credentials -o -name .zs-device.json \) -print)
if [ -n "$found" ]; then
  fail "gate 3 (files): local secret files present:"
  printf '%s\n' "$found" >&2
fi
for dir in control apps/control apps/zs-control-tests spikes docs/spikes docs/plans .superpowers .skills site; do
  if [ -e "$dir" ]; then
    fail "gate 3 (files): private directory present: $dir"
  fi
done
home_paths=$(grep -rInoE --exclude-dir=.git --exclude-dir=target \
  -e '/Users/[A-Za-z0-9._-]+' -e '/home/[A-Za-z0-9._-]+/' . |
  grep -vE ':/home/(u|user|runner|example)/$' | cut -d: -f1,2 || true)
if [ -n "$home_paths" ]; then
  fail "gate 3 (files): absolute home paths at:"
  printf '%s\n' "$home_paths" >&2
fi

# Gate 4: every relative Markdown link resolves inside the tree, and no file names a private path.
broken=""
while IFS= read -r file; do
  dir=$(dirname "$file")
  targets=$(grep -oE '\]\([^)[:space:]]+' "$file" | sed 's/^](//' || true)
  [ -z "$targets" ] && continue
  while IFS= read -r target; do
    case "$target" in
      http://* | https://* | mailto:* | '#'*) continue ;;
    esac
    path=${target%%#*}
    [ -z "$path" ] && continue
    case "$path" in
      /*) broken="$broken$file: $target (absolute)"$'\n'; continue ;;
    esac
    if [ ! -e "$dir/$path" ]; then
      broken="$broken$file: $target"$'\n'
    fi
  done <<< "$targets"
done < <(list_files | grep -E '\.md$')
if [ -n "$broken" ]; then
  fail "gate 4 (links): Markdown links that do not resolve:"
  printf '%s' "$broken" >&2
fi
private_refs=$(grep -rInE --exclude-dir=.git --exclude-dir=target --exclude=public-gates.sh \
  -e 'docs/STATE\.md|docs/JOURNAL|docs/plans/|docs/spikes/|\.superpowers/' \
  -e '(^|[^A-Za-z0-9_.-])spikes/' . | cut -d: -f1,2 || true)
if [ -n "$private_refs" ]; then
  fail "gate 4 (links): private paths named at:"
  printf '%s\n' "$private_refs" >&2
fi

if [ "$status" -eq 0 ]; then
  echo "public-gates: all four gates passed"
fi
exit "$status"
