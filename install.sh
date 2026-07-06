#!/usr/bin/env bash
# advsim installer for Linux / macOS.
set -euo pipefail
cd "$(dirname "$0")"

PY=${PYTHON:-python3}
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "error: $PY not found. Install Python 3.9+ first." >&2
  exit 1
fi

echo "Installing advsim with $PY ..."
"$PY" -m pip install --upgrade pip >/dev/null
"$PY" -m pip install .

echo
echo "Installed. Try:  advsim list"
echo "Reminder: advsim is AUTHORIZED-USE-ONLY. See SECURITY_SCOPE.md."
