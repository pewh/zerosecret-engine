#!/bin/sh
set -u

target="host=$ZS_CLIENT_HOST port=$ZS_CLIENT_PORT user=$ZS_CLIENT_USER dbname=$ZS_CLIENT_DB sslmode=disable"
table=$ZS_CLIENT_TABLE
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
failed=0

out=$(psql "$target" -X -A -t -c "SELECT count(*) FROM $table" 2>"$scratch/err")
if [ "$out" = 1 ]; then echo "read: ok rows=$out"; else echo "read: FAIL out=$out err=$(cat "$scratch/err")"; failed=1; fi

psql "$target" -X -A -t -v VERBOSITY=verbose \
  -c "INSERT INTO $table VALUES (2)" \
  -c "SET default_transaction_read_only = off" \
  -c "INSERT INTO $table VALUES (3)" \
  -c "SELECT count(*) FROM $table" >"$scratch/out" 2>"$scratch/err"
sed -n 's/^ERROR:  //p' "$scratch/err" >"$scratch/errors"
errors=$(wc -l <"$scratch/errors" | tr -d ' ')

if [ "$ZS_CLIENT_ACCESS" = read_only ]; then
  expected=1
  step=1
  for name in write switch-off write-after-switch-off; do
    line=$(sed -n "${step}p" "$scratch/errors")
    case "$line" in
      25006:*[Rr]ead[-_\ ]only*) echo "$name: refused $line" ;;
      *) echo "$name: FAIL err=$line"; failed=1 ;;
    esac
    step=$((step + 1))
  done
  [ "$errors" -eq 3 ] || { echo "errors: FAIL count=$errors"; failed=1; }
else
  expected=3
  if [ "$errors" -eq 0 ]; then
    for name in write switch-off write-after-switch-off; do echo "$name: ok"; done
  else
    echo "write: FAIL $(head -n 1 "$scratch/errors")"; failed=1
  fi
fi

rows=$(tail -n 1 "$scratch/out")
if [ "$rows" = "$expected" ]; then echo "read-after: ok rows=$rows"; else echo "read-after: FAIL rows=$rows"; failed=1; fi

psql "$target" -X -A -t -c "SHOW default_transaction_read_only" >"$scratch/out" 2>"$scratch/err"
echo "fact show-mode: out=$(cat "$scratch/out") err=$(sed -n 's/^ERROR:  //p' "$scratch/err" | head -n 1)"

exit "$failed"
