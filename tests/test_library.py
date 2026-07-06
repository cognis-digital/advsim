"""Every shipped technique and scenario loads, validates, and is well-formed."""

import re

import pytest

from advsim import library

ATTACK_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def test_techniques_load():
    techniques = library.load_all_techniques()
    assert len(techniques) >= 15, "seed library should ship 15-20 techniques"


def test_scenarios_load():
    scenarios = library.load_all_scenarios()
    assert len(scenarios) >= 3


@pytest.mark.parametrize("tech", library.load_all_techniques(), ids=lambda t: t.id)
def test_technique_wellformed(tech):
    assert tech.id
    assert ATTACK_ID_RE.match(tech.attack_id), f"{tech.id}: bad ATT&CK id {tech.attack_id}"
    assert tech.tactic
    assert tech.expected_telemetry, f"{tech.id}: must document expected telemetry"
    assert tech.simulate, f"{tech.id}: must have simulate steps"
    # Every technique that creates artifacts must have a cleanup.
    creates = any(
        a.kind
        in {
            "write_marker_file",
            "write_sandbox_registry_marker",
            "write_scheduled_task_marker",
            "log_event",
        }
        for a in tech.simulate
    )
    if creates:
        assert tech.cleanup, f"{tech.id}: creates artifacts but has no cleanup"
    # Validate passes the safety scope checks.
    tech.validate()


@pytest.mark.parametrize("tech", library.load_all_techniques(), ids=lambda t: t.id)
def test_technique_actions_are_known(tech):
    from advsim.actions import ACTIONS

    for act in tech.simulate + tech.cleanup:
        assert act.kind in ACTIONS, f"{tech.id}: unknown action {act.kind}"


def test_scenario_techniques_exist():
    idx = library.technique_index()
    for scen in library.load_all_scenarios():
        for tid in scen.techniques:
            assert tid in idx, f"scenario {scen.id} references missing technique {tid}"


def test_find_by_attack_id():
    tech = library.find_technique("T1082")
    assert tech is not None
    assert tech.id == "discovery.system_info"


def test_attack_coverage_is_broad():
    tactics = {t.tactic for t in library.load_all_techniques()}
    # Purple-team value comes from breadth across tactics.
    for expected in ("Discovery", "Persistence", "Defense Evasion", "Command and Control"):
        assert expected in tactics
