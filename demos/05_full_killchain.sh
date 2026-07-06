#!/usr/bin/env bash
# Demo 5: the end-to-end benign kill chain across many ATT&CK tactics, rendered
# to a full Markdown report. Everything is sandboxed and reversible.
set -euo pipefail
mkdir -p out
export ADVSIM_AUTHORIZED=1
echo "== advsim: full benign kill-chain scenario =="
advsim scenario full_killchain --format markdown -o out/full_killchain.md
echo "wrote out/full_killchain.md"
head -30 out/full_killchain.md
advsim cleanup
