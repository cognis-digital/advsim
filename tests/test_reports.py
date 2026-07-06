"""Report renderers produce valid JSON / SARIF 2.1.0 / STIX 2.1 / Markdown."""

import json

import pytest

from advsim import library, report
from advsim.runner import Runner


@pytest.fixture
def sample_report():
    runner = Runner(authorized=True)
    scen = library.scenario_index()["recon_and_beacon"]
    return runner.run_scenario(scen, library.technique_index())


def test_json_roundtrips(sample_report):
    text = report.to_json(sample_report)
    data = json.loads(text)
    assert data["tool"] == "advsim"
    assert len(data["runs"]) == 5


def test_markdown_has_coverage_table(sample_report):
    md = report.to_markdown(sample_report)
    assert "# advsim detection-validation report" in md
    assert "## ATT&CK coverage" in md
    assert "attack.mitre.org/techniques/T1082" in md
    assert "authorized-use-only" in md.lower()


def test_sarif_is_valid_2_1_0(sample_report):
    data = json.loads(report.to_sarif(sample_report))
    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "advsim"
    assert run["results"], "SARIF should contain results"
    for res in run["results"]:
        assert res["level"] == "note"  # benign/informational
        assert res["ruleId"]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for res in run["results"]:
        assert res["ruleId"] in rule_ids


def test_stix_is_valid_2_1(sample_report):
    data = json.loads(report.to_stix(sample_report))
    assert data["type"] == "bundle"
    types = {o["type"] for o in data["objects"]}
    assert "attack-pattern" in types
    assert "identity" in types
    assert "report" in types
    for obj in data["objects"]:
        assert obj.get("spec_version") == "2.1" or obj["type"] == "bundle"
    aps = [o for o in data["objects"] if o["type"] == "attack-pattern"]
    for ap in aps:
        assert ap["external_references"][0]["source_name"] == "mitre-attack"
        assert ap["kill_chain_phases"][0]["kill_chain_name"] == "mitre-attack"


def test_render_dispatch(sample_report):
    for fmt in ("json", "md", "markdown", "sarif", "stix"):
        assert report.render(sample_report, fmt)
    with pytest.raises(ValueError):
        report.render(sample_report, "nope")
