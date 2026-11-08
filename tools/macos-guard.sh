#!/usr/bin/env bash
set -euo pipefail

case ${1:-} in
  false)
    exit 0
    ;;
  true)
    echo "macos-guard: the engine repository is private; macOS coverage needs M1 or M2 (ADR)" >&2
    exit 1
    ;;
  *)
    echo "macos-guard: unknown repository visibility" >&2
    exit 1
    ;;
esac
