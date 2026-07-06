"""Declarative technique / scenario model.

A *technique* maps to a single MITRE ATT&CK technique id and describes a set
of benign, reversible actions (its ``simulate`` steps) plus the ``cleanup``
that reverts them, the telemetry a defender should expect to observe, and the
platform guards that decide whether it can run here.

Techniques are defined declaratively in YAML (see ``techniques/*.yaml``) and
loaded into these dataclasses. The declarative form uses a small, safe action
vocabulary implemented in ``actions.py`` — there is no arbitrary code eval.
"""

from __future__ import annotations

import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .safety import ScopeViolation, assert_capabilities_allowed


def current_platform() -> str:
    """Return advsim's platform token: ``windows``, ``macos`` or ``linux``."""
    sysname = platform.system().lower()
    if sysname.startswith("win"):
        return "windows"
    if sysname == "darwin":
        return "macos"
    return "linux"


@dataclass
class Action:
    """A single benign step within a technique's simulate or cleanup list."""

    kind: str
    params: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Action":
        data = dict(data)
        kind = data.pop("action", None)
        if not kind:
            raise ValueError("action entry missing required 'action' key")
        return cls(kind=kind, params=data)


@dataclass
class Technique:
    """A benign emulation of a single MITRE ATT&CK technique."""

    id: str  # advsim technique id, e.g. "discovery.system_info"
    name: str
    attack_id: str  # MITRE ATT&CK id, e.g. "T1082"
    attack_name: str
    tactic: str
    description: str
    platforms: list[str]
    capabilities: list[str]
    expected_telemetry: list[str]
    simulate: list[Action]
    cleanup: list[Action] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    source_path: Path | None = None

    def supported_here(self, plat: str | None = None) -> bool:
        plat = plat or current_platform()
        return "all" in self.platforms or plat in self.platforms

    def validate(self) -> None:
        """Run the static scope checks that guarantee this technique is benign."""
        assert_capabilities_allowed(self.capabilities, self.id)
        if not self.attack_id:
            raise ScopeViolation(f"{self.id}: missing MITRE ATT&CK id")
        if not self.simulate:
            raise ScopeViolation(f"{self.id}: has no simulate steps")

    @classmethod
    def from_dict(cls, data: dict[str, Any], source_path: Path | None = None) -> "Technique":
        try:
            return cls(
                id=data["id"],
                name=data["name"],
                attack_id=data["attack_id"],
                attack_name=data.get("attack_name", ""),
                tactic=data["tactic"],
                description=data.get("description", ""),
                platforms=list(data.get("platforms", ["all"])),
                capabilities=list(data.get("capabilities", [])),
                expected_telemetry=list(data.get("expected_telemetry", [])),
                simulate=[Action.from_dict(a) for a in data.get("simulate", [])],
                cleanup=[Action.from_dict(a) for a in data.get("cleanup", [])],
                references=list(data.get("references", [])),
                source_path=source_path,
            )
        except KeyError as exc:  # pragma: no cover - defensive
            raise ValueError(f"technique missing required field: {exc}") from exc


@dataclass
class Scenario:
    """An ordered chain of technique ids emulating an adversary playbook."""

    id: str
    name: str
    description: str
    techniques: list[str]
    references: list[str] = field(default_factory=list)
    source_path: Path | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any], source_path: Path | None = None) -> "Scenario":
        return cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            techniques=list(data["techniques"]),
            references=list(data.get("references", [])),
            source_path=source_path,
        )


def load_technique_file(path: str | Path) -> Technique:
    path = Path(path)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    technique = Technique.from_dict(data, source_path=path)
    technique.validate()
    return technique


def load_scenario_file(path: str | Path) -> Scenario:
    path = Path(path)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return Scenario.from_dict(data, source_path=path)
