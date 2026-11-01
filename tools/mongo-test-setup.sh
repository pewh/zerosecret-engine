#!/usr/bin/env bash
set -euo pipefail
local_shell() { docker compose exec -T mongo mongosh --quiet "$@"; }
root_shell() { docker compose exec -T mongo mongosh --quiet -u root -p zs-test-root --authenticationDatabase admin "$@"; }
if ! root_shell --eval 'db.adminCommand({ ping: 1 }).ok' >/dev/null 2>&1; then
  local_shell --eval 'try { rs.status().ok } catch (e) { rs.initiate({ _id: "rs0", members: [{ _id: 0, host: "127.0.0.1:27017" }] }).ok }' >/dev/null
  for _ in $(seq 1 60); do
    [ "$(local_shell --eval 'db.hello().isWritablePrimary')" = true ] && break
    sleep 1
  done
  local_shell --eval 'db.getSiblingDB("admin").createUser({ user: "root", pwd: "zs-test-root", roles: ["root"] }).ok' >/dev/null
fi
root_shell --eval '
const zs = db.getSiblingDB("zsdb");
if (!zs.getUser("zs_sha256")) zs.createUser({ user: "zs_sha256", pwd: "zs-test-sha256-password", roles: [{ role: "readWrite", db: "zsdb" }], mechanisms: ["SCRAM-SHA-256"] });
const admin = db.getSiblingDB("admin");
if (!admin.getUser("zs_sha1")) admin.createUser({ user: "zs_sha1", pwd: "zs-test-sha1-password", roles: [{ role: "readWrite", db: "zsdb" }], mechanisms: ["SCRAM-SHA-1"] });
' >/dev/null
echo "mongo test users ready"
