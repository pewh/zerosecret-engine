#!/usr/bin/env bash
set -euo pipefail
dir="${1:-target/db-test-certs}"
mkdir -p "$dir"
cd "$dir"
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=zs-db-test-ca" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout ca-key.pem -out ca.pem 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=127.0.0.1" -keyout server-key.pem -out server.csr 2>/dev/null
printf '%s\n' "subjectAltName=IP:127.0.0.1" "basicConstraints=CA:FALSE" \
  "keyUsage=critical,digitalSignature,keyEncipherment" "extendedKeyUsage=serverAuth" >server.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -days 30 \
  -extfile server.ext -out server.pem 2>/dev/null
chmod 644 server-key.pem
rm -f server.csr server.ext ca.srl
echo "database test certificates in $PWD"
