#!/usr/bin/env python3
"""Cross-platform demo driver: exercises the whole advsim surface and exits 0.

Runs on Windows, macOS and Linux (no bash required). Each step calls the advsim
CLI in-process and asserts benign, expected behavior.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

from advsim import cli


def _run(argv):
    print(f"\n$ advsim {' '.join(argv)}")
    rc = cli.main(argv)
    print(f"[exit {rc}]")
    return rc


def main() -> int:
    outdir = Path(tempfile.mkdtemp(prefix="advsim-demo-"))

    # 1. list
    assert _run(["list"]) == 0

    # 2. authorization gate refuses (no grant)
    os.environ.pop("ADVSIM_AUTHORIZED", None)
    assert _run(["run", "discovery.system_info", "--config", str(outdir / "none.yaml")]) == 2, \
        "advsim must refuse without authorization"
    print("OK: refused without authorization")

    # 3. run a single technique with explicit flag
    assert _run(["run", "discovery.system_info", "--authorized", "--format", "json"]) == 0

    # 4. env-based authorization + scenario + SARIF/STIX
    os.environ["ADVSIM_AUTHORIZED"] = "1"
    sarif = outdir / "scenario.sarif"
    stix = outdir / "scenario.stix.json"
    md = outdir / "killchain.md"
    assert _run(["scenario", "recon_and_beacon", "--format", "sarif", "-o", str(sarif)]) == 0
    assert _run(["scenario", "recon_and_beacon", "--format", "stix", "-o", str(stix)]) == 0
    assert _run(["scenario", "full_killchain", "--format", "markdown", "-o", str(md)]) == 0

    assert json.loads(sarif.read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert json.loads(stix.read_text(encoding="utf-8"))["type"] == "bundle"
    assert "detection-validation report" in md.read_text(encoding="utf-8")
    print("OK: SARIF/STIX/Markdown generated and valid")

    # 5. report re-render + cleanup
    assert _run(["report", "--format", "json"]) == 0
    assert _run(["cleanup"]) == 0

    print("\nAll demos completed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
