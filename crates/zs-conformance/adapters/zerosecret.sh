#!/bin/sh
set -eu

if [ "${1:-}" = "teardown" ]; then
  shift
  handle=
  while [ $# -gt 0 ]; do
    case "$1" in
      --handle)
        handle=$2
        shift 2
        ;;
      *)
        echo "unknown teardown argument: $1" >&2
        exit 2
        ;;
    esac
  done
  [ -n "$handle" ] || { echo "teardown needs --handle" >&2; exit 2; }
  home=${handle%%|*}
  pid=${handle##*|}
  if [ -n "$pid" ]; then
    pkill -P "$pid" 2>/dev/null || true
    kill "$pid" 2>/dev/null || true
  fi
  rm -rf "$home"
  exit 0
fi

if [ "${1:-}" = "presign" ]; then
  shift
  handle= url= method=GET expires=600
  while [ $# -gt 0 ]; do
    case "$1" in
      --handle) handle=$2; shift 2 ;;
      --url) url=$2; shift 2 ;;
      --method) method=$2; shift 2 ;;
      --expires) expires=$2; shift 2 ;;
      *) echo "unknown presign argument: $1" >&2; exit 2 ;;
    esac
  done
  [ -n "$handle" ] || { echo "presign needs --handle" >&2; exit 2; }
  [ -n "$url" ] || { echo "presign needs --url" >&2; exit 2; }
  home=${handle%%|*}
  endpoint=$(sed -n 's/^zs: endpoint conformance -> //p' "$home/stdout" | head -n 1)
  [ -n "$endpoint" ] || endpoint=$(sed -n 's/^zs: proxy //p' "$home/stdout" | head -n 1)
  [ -n "$endpoint" ] || { echo "no listener to presign against" >&2; exit 1; }
  now=$(date -u +%Y%m%dT%H%M%SZ)
  date8=${now%%T*}
  case "$url" in
    *\?*) separator='&' ;;
    *) separator='?' ;;
  esac
  url="${url}${separator}X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=placeholder%2F${date8}%2F${ZS_CONFORMANCE_AWS_REGION:-us-east-1}%2F${ZS_CONFORMANCE_AWS_SERVICE:-service}%2Faws4_request&X-Amz-Date=${now}&X-Amz-Expires=${expires}&X-Amz-SignedHeaders=host&X-Amz-Signature=0"
  body=$(printf '{"url":"%s","method":"%s"}' "$url" "$method")
  signed=$(curl -sS --max-time 15 --header 'Content-Type: application/json' \
    --data "$body" "http://$endpoint/.zs/presign") || exit 1
  case "$signed" in
    http://*|https://*) printf '{"url":"%s"}\n' "$signed" ;;
    *) echo "presign returned: $signed" >&2; exit 1 ;;
  esac
  exit 0
fi

[ "${1:-}" = "setup" ] || { echo "usage: $0 setup|teardown|presign" >&2; exit 2; }
shift

protocol= case_id= upstream_host= upstream_port= credential_file= upstream_ca= upstream_tls=default operations= auth_scheme= access_key_id=
while [ $# -gt 0 ]; do
  case "$1" in
    --protocol) protocol=$2; shift 2 ;;
    --case) case_id=$2; shift 2 ;;
    --upstream-host) upstream_host=$2; shift 2 ;;
    --upstream-port) upstream_port=$2; shift 2 ;;
    --credential-file) credential_file=$2; shift 2 ;;
    --upstream-ca) upstream_ca=$2; shift 2 ;;
    --upstream-tls) upstream_tls=$2; shift 2 ;;
    --operations) operations=$2; shift 2 ;;
    --auth-scheme) auth_scheme=$2; shift 2 ;;
    --access-key-id) access_key_id=$2; shift 2 ;;
    *) echo "unknown setup argument: $1" >&2; exit 2 ;;
  esac
done

[ -n "$protocol" ] || { echo "--protocol is required" >&2; exit 2; }
[ -n "$upstream_host" ] || { echo "--upstream-host is required" >&2; exit 2; }
[ -n "$upstream_port" ] || { echo "--upstream-port is required" >&2; exit 2; }
[ -n "$credential_file" ] || { echo "--credential-file is required" >&2; exit 2; }
[ -r "$credential_file" ] || { echo "cannot read the credential file" >&2; exit 2; }
command -v openssl >/dev/null 2>&1 || { echo "openssl is required to sign the local grant" >&2; exit 2; }

policy_protocol=$protocol
grant_upstream_tls=$upstream_tls
grant_local_endpoint=false
https_plaintext_fields=
if [ "$protocol" = "mongodb" ]; then
  policy_protocol=mongo
fi
if [ "$protocol" = "http" ] && [ "$case_id" = "SV-03" ]; then
  policy_protocol=https
  https_plaintext_fields='"upstream_plaintext":true,'
  grant_upstream_tls=plaintext
fi
if [ "$protocol" = "http" ] && [ "$case_id" = "SV-06" ]; then
  policy_protocol=https
  https_plaintext_fields='"upstream_plaintext":true,"local_endpoint":true,'
  grant_upstream_tls=plaintext
  grant_local_endpoint=true
fi

case "$protocol" in
  postgres) kind=postgres; host_label=db.conformance ;;
  mysql) kind=mysql; host_label=db.conformance ;;
  mongodb) kind=mongo; host_label=db.conformance ;;
  http) kind=http; host_label=${ZS_CONFORMANCE_HTTP_HOST:-example.amazonaws.com} ;;
  *) echo "unknown protocol: $protocol" >&2; exit 2 ;;
esac

here=$(cd "$(dirname "$0")" && pwd)
zs_bin=${ZS_CONFORMANCE_ZS_BIN:-$here/../../../target/debug/zs}
[ -x "$zs_bin" ] || { echo "zs binary not found at $zs_bin" >&2; exit 2; }

home=$(mktemp -d "${TMPDIR:-/tmp}/zs-conformance.XXXXXX")
pid=
cleanup() {
  if [ -n "$pid" ]; then
    pkill -P "$pid" 2>/dev/null || true
    kill "$pid" 2>/dev/null || true
  fi
  rm -rf "$home"
}
trap cleanup EXIT

mkdir -p "$home/.zs-credentials" "$home/.zs-ca"
umask 077
cp "$credential_file" "$home/.zs-credentials/conformance"

grant_id="conf-$(date +%s)-$$"
expires_at_ms=$(( $(date +%s) * 1000 + 3600000 ))

extra_fields=
if [ "$protocol" = "mongodb" ]; then
  if [ "$case_id" = "MG-02" ]; then
    mongo_user=zs_sha1
    mongo_auth_source=admin
  else
    mongo_user=zs_sha256
    mongo_auth_source=zsdb
  fi
  extra_fields=$(printf '"user":"%s","auth_source":"%s",' "$mongo_user" "$mongo_auth_source")
fi
if [ "$protocol" = "http" ] && [ "$auth_scheme" = "aws-sigv4" ]; then
  [ -n "$access_key_id" ] || { echo "--auth-scheme aws-sigv4 needs --access-key-id" >&2; exit 2; }
  auth_region=${ZS_CONFORMANCE_AWS_REGION:-us-east-1}
  auth_service=${ZS_CONFORMANCE_AWS_SERVICE:-service}
  extra_fields=$(printf '%s"auth":{"scheme":"aws-sigv4","access_key_id":"%s","region":"%s","service":"%s"},' \
    "$extra_fields" "$access_key_id" "$auth_region" "$auth_service")
fi
extra_fields="$extra_fields$https_plaintext_fields"

tls_fields=
case "$upstream_tls" in
  default) ;;
  plaintext) tls_fields='"upstream_plaintext":true,' ;;
  ca-sha256:*)
    [ -n "$upstream_ca" ] || { echo "--upstream-tls ca-sha256 needs --upstream-ca" >&2; exit 2; }
    tls_fields=$(printf '"upstream_ca":"%s",' "$upstream_ca")
    ;;
  pin-sha256:*)
    tls_fields=$(printf '"upstream_cert_sha256":"%s",' "${upstream_tls#pin-sha256:}")
    ;;
  *) echo "unknown --upstream-tls: $upstream_tls" >&2; exit 2 ;;
esac

grant_operations=${operations:-connect}
joined_operations=$(printf '%s' "$grant_operations" | tr ',' '\n' | awk 'NF' | sort | awk 'BEGIN { sep = "" } { printf "%s%s", sep, $0; sep = sprintf("%c", 29) }')

openssl genpkey -algorithm ED25519 -out "$home/signing.pem" 2>/dev/null
verifying_key_hex=$(openssl pkey -in "$home/signing.pem" -pubout -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n')

field() { printf '%s\037%s\036' "$1" "$2"; }
{
  field credential_ref conformance
  field environment development
  field expires_at_ms "$expires_at_ms"
  field grant_id "$grant_id"
  field host "$host_label"
  field local_endpoint "$grant_local_endpoint"
  field materialization retrieve
  field operations "$joined_operations"
  field protocol "$policy_protocol"
  field resource conformance
  field subject conformance
  field upstream_host "$upstream_host"
  field upstream_port "$upstream_port"
  field upstream_tls "$grant_upstream_tls"
  field workload default
} > "$home/payload"

openssl pkeyutl -sign -rawin -inkey "$home/signing.pem" -in "$home/payload" -out "$home/signature" 2>/dev/null
signature=$(openssl base64 -A -in "$home/signature")

grant=$(printf '{"grant":{"subject":"conformance","workload":"default","resource":"conformance","host":"%s","protocol":"%s","credential_ref":"conformance","operations":[%s],"environment":"development","expires_at_ms":%s,"grant_id":"%s","materialization":"retrieve","upstream_host":"%s","upstream_port":%s,"upstream_tls":"%s","local_endpoint":%s},"signature":"%s","signing_key_id":"conformance-k1"}' \
  "$host_label" "$policy_protocol" "$(printf '%s' "$grant_operations" | awk 'BEGIN { sep = "" } { n = split($0, a, ","); for (i = 1; i <= n; i++) { printf "%s\"%s\"", sep, a[i]; sep = "," } }')" \
  "$expires_at_ms" "$grant_id" "$upstream_host" "$upstream_port" "$grant_upstream_tls" "$grant_local_endpoint" "$signature")

policy=$(printf '{"bindings":[{"resource":"conformance","host":"%s","protocol":"%s","upstream_host":"%s","upstream_port":%s,%s%s"operations":[%s]}],"signing_keys":[{"key_id":"conformance-k1","verifying_key_hex":"%s"}],"grants":[%s]}' \
  "$host_label" "$policy_protocol" "$upstream_host" "$upstream_port" "$tls_fields" "$extra_fields" \
  "$(printf '%s' "$grant_operations" | awk 'BEGIN { sep = "" } { n = split($0, a, ","); for (i = 1; i <= n; i++) { printf "%s\"%s\"", sep, a[i]; sep = "," } }')" \
  "$verifying_key_hex" "$grant")

printf '%s\n' "$policy" > "$home/zs-policy.json"

USER=conformance ZS_HOME="$home" "$zs_bin" run \
  --policy "$home/zs-policy.json" \
  --credentials-dir "$home/.zs-credentials" \
  --audit "$home/audit.jsonl" \
  --ca-dir "$home/.zs-ca" \
  --as default -- sleep 86400 > "$home/stdout" 2> "$home/stderr" &
pid=$!
echo "$home|$pid" > "$home/handle"

listener=
attempts=0
while [ "$attempts" -lt 400 ]; do
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "zs run exited during setup for case $case_id" >&2
    cat "$home/stderr" >&2
    exit 1
  fi
  if [ "$case_id" = "SV-06" ]; then
    listener=$(sed -n 's/^zs: endpoint conformance -> //p' "$home/stdout" | head -n 1)
  elif [ "$kind" = "http" ]; then
    listener=$(sed -n 's/^zs: proxy //p' "$home/stdout" | head -n 1)
  else
    listener=$(sed -n "s/^zs: $kind conformance -> //p" "$home/stdout" | head -n 1)
  fi
  [ -n "$listener" ] && break
  attempts=$((attempts + 1))
  sleep 0.05
done
if [ -z "$listener" ]; then
  echo "zs run did not report a $kind listener for case $case_id" >&2
  cat "$home/stderr" >&2
  exit 1
fi
trap - EXIT

prefix=CONFORMANCE
port=${listener##*:}
listener_host=${listener%:*}
printf '{"handle":"%s","endpoint":"%s","env":{"%s_HOST":"%s","%s_PORT":"%s"%s}}\n' \
  "$(cat "$home/handle")" "$listener" "$prefix" "$listener_host" "$prefix" "$port" \
  "$(if [ "$kind" = "http" ]; then printf ',"CONFORMANCE_HTTP_HOST":"%s"' "$host_label"; fi)"
