"""Every emulation runs and cleans up in the sandbox, leaving no residue."""

import pytest

from advsim import library
from advsim.runner import Runner, run_single
from advsim.safety import AuthorizationError, sandbox_root


def test_runner_requires_authorization():
    with pytest.raises(AuthorizationError):
        Runner(authorized=False)


@pytest.mark.parametrize("tech", library.load_all_techniques(), ids=lambda t: t.id)
def test_every_technique_runs_and_cleans(tech):
    report = run_single(tech, authorized=True, do_cleanup=True)
    run = report.runs[0]
    assert run.status in ("ran", "cleaned", "skipped"), run.message
    if run.status == "skipped":
        pytest.skip(run.message)
    # Simulate steps all succeeded (a spawn may fail benignly if a binary is
    # absent on the CI image, but should never raise).
    for step in run.simulate_steps:
        assert step.error is None or step.kind == "spawn_benign_process"


def test_sandbox_empty_after_cleanup():
    """After running the full kill chain with cleanup, nothing remains but the
    sandbox root itself (each technique cleans its own artifacts)."""
    runner = Runner(authorized=True)
    scen = library.scenario_index()["full_killchain"]
    runner.run_scenario(scen, library.technique_index(), do_cleanup=True)
    # activity.log and markers should be gone; sandbox may still exist empty.
    residue = [
        p
        for p in sandbox_root().rglob("*")
        if p.is_file()
    ]
    assert residue == [], f"cleanup left residue: {residue}"


def test_cleanup_all_removes_sandbox():
    runner = Runner(authorized=True)
    tech = library.find_technique("collection.local_staging")
    runner.run_technique(tech, do_cleanup=False)  # leave residue on purpose
    assert any(sandbox_root().rglob("*"))
    result = runner.cleanup_all()
    assert result["removed"] is True
    assert not sandbox_root().exists() or not any(sandbox_root().rglob("*"))


def test_scenario_runs_all_steps():
    runner = Runner(authorized=True)
    scen = library.scenario_index()["recon_and_beacon"]
    report = runner.run_scenario(scen, library.technique_index())
    assert len(report.runs) == len(scen.techniques)
    assert all(r.status != "error" for r in report.runs)
