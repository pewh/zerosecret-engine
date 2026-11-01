#!/bin/sh
sleep 30 &
if [ -n "${STUB_PID_FILE:-}" ]; then
  printf '%s' "$!" > "$STUB_PID_FILE"
fi
wait
