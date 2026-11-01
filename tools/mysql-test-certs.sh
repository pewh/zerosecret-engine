#!/usr/bin/env bash
set -euo pipefail
exec "$(dirname "$0")/db-test-certs.sh" "$@"
