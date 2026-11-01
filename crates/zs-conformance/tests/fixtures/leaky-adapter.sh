#!/bin/sh
set -eu
case "${LEAK_STREAM:-stdout}" in
  stdout) printf '%s\n' "${LEAK_SECRET:?}" ;;
  stderr) printf '%s\n' "${LEAK_SECRET:?}" >&2 ;;
esac
printf '{"handle":"leak-1","endpoint":"127.0.0.1:45998","env":{}}\n'
