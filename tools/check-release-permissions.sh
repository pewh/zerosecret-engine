#!/usr/bin/env bash
# Checks that only the `publish` job of a workflow can write, and that `publish` runs only for
# a pushed `v*` tag while the owner's `ZS_RELEASE_BINARIES` variable is true (ADR-0055).
#
# Write grants are read from the workflow-level `permissions:` (which every job inherits) and
# from each job's `permissions:`, in block form, one-line `{ ... }` form, `write-all`, and with
# quoted values. The parser tracks jobs by their two-space key under `jobs:`; the workflows keep
# that layout.
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: check-release-permissions.sh <workflow.yml>..." >&2
  exit 2
fi

status=0
for workflow in "$@"; do
  if [ ! -f "$workflow" ]; then
    echo "check-release-permissions: no such file: $workflow" >&2
    status=1
    continue
  fi
  awk '
    function trim(s) {
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      return s
    }

    # A scalar value without its trailing comment and its quotes.
    function scalar(s) {
      sub(/[[:space:]]+#.*$/, "", s)
      s = trim(s)
      if (s ~ /^".*"$/ || s ~ /^\047.*\047$/) s = substr(s, 2, length(s) - 2)
      return s
    }

    function report(owner, permission) {
      print "check-release-permissions: " owner " holds " permission > "/dev/stderr"
      status = 1
    }

    # One `name: value` grant; `owner` is "workflow" or a job name.
    function grant(owner, entry,    name, value) {
      if (entry !~ /:/) return
      name = trim(substr(entry, 1, index(entry, ":") - 1))
      value = scalar(substr(entry, index(entry, ":") + 1))
      if (value != "write") return
      if (owner != "publish") report(owner, name ": write")
    }

    # The value after `permissions:`: write-all, a one-line mapping, or empty for a block.
    function permissions_value(owner, value,    body, count, entries, i) {
      value = scalar(value)
      if (value == "write-all") {
        if (owner != "publish") report(owner, "write-all")
        return 0
      }
      if (value ~ /^\{.*\}$/) {
        body = substr(value, 2, length(value) - 2)
        count = split(body, entries, ",")
        for (i = 1; i <= count; i++) grant(owner, entries[i])
        return 0
      }
      return value == ""
    }

    function finish_job(    gate) {
      if (job == "publish") {
        gate = publish_if
        if (gate ~ /\|\|/ ||
            gate !~ /refs\/tags\/v/ ||
            gate !~ /github\.event_name[[:space:]]*==[[:space:]]*\047push\047/ ||
            gate !~ /vars\.ZS_RELEASE_BINARIES[[:space:]]*==[[:space:]]*\047true\047/) {
          print "check-release-permissions: publish is not gated" > "/dev/stderr"
          status = 1
        }
      }
      job = ""
      in_if = 0
      publish_if = ""
      job_perms = 0
    }

    # A blank line or a comment never ends a block.
    /^[[:space:]]*(#.*)?$/ { next }

    # A top-level key ends the job list and any workflow permissions block.
    /^[^[:space:]]/ {
      if (in_jobs && job != "") finish_job()
      in_jobs = ($0 ~ /^jobs:[[:space:]]*(#.*)?$/)
      top_perms = 0
      if ($0 ~ /^permissions:/) {
        value = $0
        sub(/^permissions:/, "", value)
        top_perms = permissions_value("workflow", value)
      }
      next
    }

    top_perms {
      grant("workflow", $0)
      next
    }

    in_jobs && /^  [A-Za-z0-9_-]+:[[:space:]]*(#.*)?$/ {
      if (job != "") finish_job()
      job = $0
      sub(/^  /, "", job)
      sub(/:.*/, "", job)
      next
    }

    in_if {
      if ($0 ~ /^      /) {
        publish_if = publish_if " " $0
        next
      }
      in_if = 0
    }

    job_perms {
      if ($0 ~ /^      /) {
        grant(job, $0)
        next
      }
      job_perms = 0
    }

    in_jobs && job != "" && /^    permissions:/ {
      value = $0
      sub(/^    permissions:/, "", value)
      job_perms = permissions_value(job, value)
      next
    }

    in_jobs && job == "publish" && /^    if:/ {
      in_if = 1
      value = $0
      sub(/^    if:[[:space:]]*/, "", value)
      if (value ~ /^[|>][-+]?[[:space:]]*(#.*)?$/) value = ""
      publish_if = publish_if " " value
      next
    }

    END {
      if (in_jobs && job != "") finish_job()
      exit status
    }
  ' "$workflow" || status=1
done

exit "$status"
