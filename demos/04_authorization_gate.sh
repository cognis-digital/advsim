#!/usr/bin/env bash
# Demo 4: prove the authorization gate. Without --authorized (and no env/config
# grant), advsim REFUSES to run and exits non-zero.
set -uo pipefail
echo "== advsim: attempt to run WITHOUT authorization (expected: refusal) =="
if advsim run discovery.system_info --config /nonexistent/advsim.yaml; then
  echo "ERROR: advsim ran without authorization — this must never happen" >&2
  exit 1
else
  echo
  echo "OK: advsim refused to run without an explicit authorization gate."
fi
