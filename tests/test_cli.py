"""End-to-end CLI behavior."""

import json

import pytest

from advsim import cli


def test_list_json(capsys):
    rc = cli.main(["list", "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data["techniques"]) >= 15
    assert len(data["scenarios"]) >= 3


def test_list_human(capsys):
    rc = cli.main(["list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Techniques:" in out
    assert "Scenarios:" in out


def test_run_with_authorized_flag(capsys):
    rc = cli.main(["run", "discovery.system_info", "--authorized", "--format", "json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["runs"][0]["technique_id"] == "discovery.system_info"


def test_run_env_authorization(monkeypatch, capsys):
    monkeypatch.setenv("ADVSIM_AUTHORIZED", "1")
    rc = cli.main(["run", "T1082", "--format", "json"])
    assert rc == 0


def test_run_unknown_technique(capsys):
    rc = cli.main(["run", "does.not.exist", "--authorized"])
    assert rc == 1
    assert "not found" in capsys.readouterr().out


def test_scenario_and_report_roundtrip(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("ADVSIM_AUTHORIZED", "1")
    out_file = tmp_path / "report.sarif"
    rc = cli.main(
        ["scenario", "recon_and_beacon", "--format", "sarif", "-o", str(out_file)]
    )
    assert rc == 0
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"

    # `advsim report` re-renders the last run.
    capsys.readouterr()
    rc = cli.main(["report", "--format", "stix"])
    assert rc == 0
    stix = json.loads(capsys.readouterr().out)
    assert stix["type"] == "bundle"


def test_cleanup(monkeypatch, capsys):
    monkeypatch.setenv("ADVSIM_AUTHORIZED", "1")
    cli.main(["run", "collection.local_staging", "--authorized", "--no-cleanup",
              "--format", "json"])
    capsys.readouterr()
    rc = cli.main(["cleanup"])
    assert rc == 0
    assert "sandbox" in capsys.readouterr().out
