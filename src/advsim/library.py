"""Load the seed technique and scenario library shipped inside the package."""

from __future__ import annotations

from importlib import resources
from pathlib import Path

from .model import Scenario, Technique, load_scenario_file, load_technique_file


def _package_dir(subdir: str) -> Path:
    return Path(resources.files("advsim") / subdir)


def technique_dir() -> Path:
    return _package_dir("techniques")


def scenario_dir() -> Path:
    return _package_dir("scenarios")


def load_all_techniques() -> list[Technique]:
    techniques: list[Technique] = []
    for path in sorted(technique_dir().glob("*.yaml")):
        techniques.append(load_technique_file(path))
    return techniques


def load_all_scenarios() -> list[Scenario]:
    scenarios: list[Scenario] = []
    for path in sorted(scenario_dir().glob("*.yaml")):
        scenarios.append(load_scenario_file(path))
    return scenarios


def technique_index() -> dict[str, Technique]:
    return {t.id: t for t in load_all_techniques()}


def scenario_index() -> dict[str, Scenario]:
    return {s.id: s for s in load_all_scenarios()}


def find_technique(ident: str) -> Technique | None:
    """Look up a technique by advsim id or by MITRE ATT&CK id (e.g. T1082)."""
    idx = technique_index()
    if ident in idx:
        return idx[ident]
    for tech in idx.values():
        if tech.attack_id.lower() == ident.lower():
            return tech
    return None
