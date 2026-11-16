#!/bin/sh
set -eu

REDISCLI_AUTH=$ZS_ADMIN_PASSWORD
export REDISCLI_AUTH
exec redis-cli -h "$ZS_ADMIN_HOST" -p "$ZS_ADMIN_PORT" --no-auth-warning "$@"
