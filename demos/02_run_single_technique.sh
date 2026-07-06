#!/usr/bin/env bash
# Demo 2: run one benign technique (System Information Discovery, T1082) and get
# a Markdown detection-validation report. Authorization is required.
set -euo pipefail
echo "== advsim: emulate T1082 (benign) and produce a detection-validation report =="
advsim run discovery.system_info --authorized --format markdown
echo
echo "== cleaning up any sandbox residue =="
advsim cleanup
