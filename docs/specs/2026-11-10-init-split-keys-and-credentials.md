# `zs init`: split keys, Basic pairs and credential files

Status: accepted 2026-11-10 (owner request: "fix zs init").

## Problem

`zs init` classifies one `.env` line at a time. It brokers database URLs and three HTTP APIs, so a
file that configures a database as `DB_HOST`/`DB_PASSWORD` or calls an internal service with
`<NAME>_URL` plus a client id and secret gets `"bindings": []`. When it does broker a value, it only
backs `.env` up and writes a placeholder: the credential never reaches a credential directory, and
nothing says which control-plane resources to create.

## Rules

| Id | Rule |
|---|---|
| I1 | A key `<P>_HOST` or `<P>_HOSTNAME` with a non-empty `<P>_PASSWORD` (or `_PASS`, `_PASSWD`, `_PWD`) is a database group. Its protocol comes from `--db <P>=<protocol>`, else from `<P>` (`MYSQL`, `MARIADB`; `POSTGRE`, `PSQL`, a `PG` segment; `MONGO`), else from `<P>_PORT` (3306, 5432, 27017), else from `<P>_DIALECT`, `_DRIVER`, `_CONNECTION`, `_ENGINE` or `_TYPE`. A `REDIS` prefix is reported as not brokered yet; any other is reported with the `--db` hint |
| I2 | A database group becomes one binding. The upstream port is `<P>_PORT` or the protocol default, and the listener uses the same port, so an app that never reads `<P>_PORT` still connects. `<P>_HOST` and every `<P>_*_HOST` with the same value become `127.0.0.1`; the password becomes the placeholder; ports are unchanged. A MongoDB group needs `<P>_USER` or `<P>_USERNAME`. A second group on a port already taken gets the next port from `--listen-port-start` and `<P>_PORT` is rewritten; without a `<P>_PORT` key it is reported instead |
| I3 | A key `<N>_URL` (also `<N>_BASE_URL`, `<N>_API_URL`, with `<N>` also tried without a trailing `_BASE` or `_API`) whose value is an `http(s)` URL, plus a user and a secret under the same prefix (`_CLIENT_ID`/`_CLIENT_SECRET`, `_USERNAME`/`_PASSWORD`, `_USER`/`_PASSWORD`, `_AUTH_USER`/`_AUTH_PASSWORD`, `_AUTH_USERNAME`/`_AUTH_PASSWORD`, `_ID`/`_SECRET`), becomes a Basic binding with operations `GET` and `POST`. The secret becomes the placeholder; the user stays |
| I4 | `--auth <KEY>=bearer` or `--auth <KEY>=header:<Name>` brokers `<KEY>` as a Bearer token or a named header, with the host from the matching `_URL` key |
| I5 | One credential per host: when two or more pairs or `--auth` keys target one host, none of them is brokered and each is reported, because a binding replaces the credential on every request to its host. A loopback URL (the app itself or a local service) is never brokered |
| I6 | A value that is already a placeholder (`placeholder_managed_by_zerosecret` or `zs-brokered`) is skipped |
| I7 | Every brokered value is written to `~/.zs-credentials/<project>/<resource>` (directory 0700, file 0600, created exclusively, symlinks refused), and the policy's `run.credentials_dir` names that directory. An existing file with another value stops `zs init` before `.env` changes. `--dry-run` writes nothing and names the files it would write |
| I8 | The report lists, per binding, the control-plane resource an admin creates: name, host, protocol, operations and `credential_ref` |

No message names a value; key names, hosts and ports only.
