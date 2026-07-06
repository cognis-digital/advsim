"""The execution engine: run a technique or a chained scenario, benignly.

The runner is the single place emulations are executed. Before *any* step
runs, it re-validates the technique against the safety scope (capabilities +
static command checks), refuses if unauthorized, and skips techniques that do
not support the current platform. It records exactly what observably happened
so the reporter can tell the operator which detections to verify.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from . import actions
from .model import Scenario, Technique, current_platform
from .safety import AuthorizationError, ScopeViolation, sandbox_root


@dataclass
class StepRecord:
    kind: str
    ok: bool
    detail: str
    observed: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass
class TechniqueRun:
    technique_id: str
    attack_id: str
    attack_name: str
    tactic: str
    name: str
    status: str  # "ran", "cleaned", "skipped", "error", "refused"
    platform: str
    started: str
    finished: str
    expected_telemetry: list[str] = field(default_factory=list)
    simulate_steps: list[StepRecord] = field(default_factory=list)
    cleanup_steps: list[StepRecord] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RunReport:
    tool_version: str
    generated: str
    platform: str
    sandbox: str
    scenario_id: str | None
    runs: list[TechniqueRun] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "advsim",
            "tool_version": self.tool_version,
            "generated": self.generated,
            "platform": self.platform,
            "sandbox": self.sandbox,
            "scenario_id": self.scenario_id,
            "runs": [r.to_dict() for r in self.runs],
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Runner:
    """Executes techniques/scenarios under the benign-only contract."""

    def __init__(self, authorized: bool):
        if not authorized:
            raise AuthorizationError(
                "advsim refuses to run: authorization gate not set. "
                "Re-run with --authorized (or authorized: true in config) and "
                "only against systems you are explicitly authorized to test."
            )
        self.authorized = authorized

    def run_technique(self, technique: Technique, do_cleanup: bool = True) -> TechniqueRun:
        plat = current_platform()
        started = _now()
        record = TechniqueRun(
            technique_id=technique.id,
            attack_id=technique.attack_id,
            attack_name=technique.attack_name,
            tactic=technique.tactic,
            name=technique.name,
            status="skipped",
            platform=plat,
            started=started,
            finished=started,
            expected_telemetry=list(technique.expected_telemetry),
            references=list(technique.references),
        )

        # Re-validate scope right before running (defense-in-depth).
        try:
            technique.validate()
        except ScopeViolation as exc:
            record.status = "refused"
            record.message = str(exc)
            record.finished = _now()
            return record

        if not technique.supported_here(plat):
            record.status = "skipped"
            record.message = (
                f"technique targets {technique.platforms}; current platform is {plat}"
            )
            record.finished = _now()
            return record

        # Simulate.
        try:
            for act in technique.simulate:
                res = actions.run_action(act, technique.id)
                record.simulate_steps.append(_to_step(res))
            record.status = "ran"
        except ScopeViolation as exc:
            record.status = "refused"
            record.message = str(exc)
            record.finished = _now()
            return record

        # Cleanup (always attempt, so the system is left as found).
        if do_cleanup:
            try:
                for act in technique.cleanup:
                    res = actions.run_action(act, technique.id)
                    record.cleanup_steps.append(_to_step(res))
                if technique.cleanup:
                    record.status = "cleaned"
            except ScopeViolation as exc:
                record.message = f"cleanup refused: {exc}"

        record.finished = _now()
        return record

    def run_scenario(
        self,
        scenario: Scenario,
        technique_index: dict[str, Technique],
        do_cleanup: bool = True,
    ) -> RunReport:
        from . import __version__

        report = RunReport(
            tool_version=__version__,
            generated=_now(),
            platform=current_platform(),
            sandbox=str(sandbox_root()),
            scenario_id=scenario.id,
        )
        for tech_id in scenario.techniques:
            tech = technique_index.get(tech_id)
            if tech is None:
                missing = TechniqueRun(
                    technique_id=tech_id,
                    attack_id="",
                    attack_name="",
                    tactic="",
                    name=tech_id,
                    status="error",
                    platform=current_platform(),
                    started=_now(),
                    finished=_now(),
                    message=f"technique {tech_id!r} not found in library",
                )
                report.runs.append(missing)
                continue
            report.runs.append(self.run_technique(tech, do_cleanup=do_cleanup))
        return report

    def cleanup_all(self) -> dict[str, Any]:
        """Remove the entire sandbox tree, leaving no residue."""
        import shutil

        root = sandbox_root()
        removed = root.exists()
        if removed:
            shutil.rmtree(root, ignore_errors=True)
        return {"sandbox": str(root), "removed": removed}


def _to_step(res: actions.ActionResult) -> StepRecord:
    return StepRecord(
        kind=res.kind,
        ok=res.ok,
        detail=res.detail,
        observed=res.observed,
        error=res.error,
    )


def run_single(
    technique: Technique, authorized: bool, do_cleanup: bool = True
) -> RunReport:
    """Convenience: run one technique and wrap it in a RunReport."""
    from . import __version__

    runner = Runner(authorized=authorized)
    report = RunReport(
        tool_version=__version__,
        generated=_now(),
        platform=current_platform(),
        sandbox=str(sandbox_root()),
        scenario_id=None,
    )
    report.runs.append(runner.run_technique(technique, do_cleanup=do_cleanup))
    return report
