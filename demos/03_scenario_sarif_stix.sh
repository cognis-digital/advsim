#!/usr/bin/env bash
# Demo 3: run a chained scenario and emit machine-readable SARIF + STIX for your
# detection pipeline / threat-intel platform.
set -euo pipefail
mkdir -p out
echo "== advsim: run the recon_and_beacon scenario (benign) =="
advsim scenario recon_and_beacon --authorized --format sarif -o out/recon_and_beacon.sarif
advsim scenario recon_and_beacon --authorized --format stix  -o out/recon_and_beacon.stix.json
echo "wrote out/recon_and_beacon.sarif and out/recon_and_beacon.stix.json"
echo
echo "== SARIF result count =="
python -c "import json;d=json.load(open('out/recon_and_beacon.sarif'));print(len(d['runs'][0]['results']),'results')"
echo "== STIX object types =="
python -c "import json;d=json.load(open('out/recon_and_beacon.stix.json'));print(sorted({o['type'] for o in d['objects']}))"
advsim cleanup
