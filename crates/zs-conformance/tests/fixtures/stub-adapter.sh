#!/bin/sh
set -eu
if [ -n "${STUB_ARGS_FILE:-}" ]; then
  : > "$STUB_ARGS_FILE"
  for arg in "$@"; do
    printf '%s\n' "$arg" >> "$STUB_ARGS_FILE"
  done
fi
if [ -n "${STUB_STDERR:-}" ]; then
  printf '%s\n' "$STUB_STDERR" >&2
fi
printf '{"handle":"stub-1","endpoint":"127.0.0.1:45999","env":{"PGHOST":"127.0.0.1"}}\n'
exit "${STUB_EXIT:-0}"
