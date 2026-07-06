"""Detection-validation reporting: Markdown, JSON, SARIF 2.1.0, STIX 2.1.

The report answers one question for a blue team: *for each technique we
emulated, what telemetry should your SIEM/EDR have produced, and did your
detections fire?* It is guidance, not a verdict — advsim tells you what to go
check.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from .runner import RunReport, TechniqueRun

_ATTACK_URL = "https://attack.mitre.org/techniques/"


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def to_json(report: RunReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def _attack_link(attack_id: str) -> str:
    if not attack_id:
        return ""
    slug = attack_id.replace(".", "/")
    return f"[{attack_id}]({_ATTACK_URL}{slug}/)"


def to_markdown(report: RunReport) -> str:
    lines: list[str] = []
    lines.append("# advsim detection-validation report")
    lines.append("")
    lines.append(
        "> advsim emulates the **observable telemetry** of MITRE ATT&CK techniques "
        "using benign, reversible, sandbox-scoped actions. Nothing below performed "
        "real harm. Use this report to confirm your detections fired."
    )
    lines.append("")
    lines.append(f"- **Generated:** {report.generated}")
    lines.append(f"- **Platform:** {report.platform}")
    lines.append(f"- **Sandbox:** `{report.sandbox}`")
    lines.append(f"- **advsim version:** {report.tool_version}")
    if report.scenario_id:
        lines.append(f"- **Scenario:** `{report.scenario_id}`")
    lines.append("")

    ran = [r for r in report.runs if r.status in ("ran", "cleaned")]
    skipped = [r for r in report.runs if r.status == "skipped"]
    problems = [r for r in report.runs if r.status in ("error", "refused")]

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Techniques emulated: **{len(ran)}**")
    lines.append(f"- Skipped (platform/guard): **{len(skipped)}**")
    lines.append(f"- Errors / refused: **{len(problems)}**")
    lines.append("")

    lines.append("## ATT&CK coverage")
    lines.append("")
    lines.append("| ATT&CK | Technique | Tactic | Status |")
    lines.append("|---|---|---|---|")
    for r in report.runs:
        lines.append(
            f"| {_attack_link(r.attack_id)} | {r.name} | {r.tactic} | {r.status} |"
        )
    lines.append("")

    lines.append("## What to verify in your SIEM / EDR")
    lines.append("")
    for r in ran:
        lines.append(f"### {r.name} ({_attack_link(r.attack_id)})")
        lines.append("")
        lines.append(f"- **advsim technique id:** `{r.technique_id}`")
        lines.append(f"- **Tactic:** {r.tactic}")
        lines.append(f"- **Window:** {r.started} → {r.finished}")
        if r.expected_telemetry:
            lines.append("- **Expected telemetry (confirm a detection fired):**")
            for t in r.expected_telemetry:
                lines.append(f"  - {t}")
        observed = _observed_lines(r)
        if observed:
            lines.append("- **Observed benign actions:**")
            for o in observed:
                lines.append(f"  - {o}")
        if r.references:
            lines.append("- **References:**")
            for ref in r.references:
                lines.append(f"  - {ref}")
        lines.append("")

    if skipped:
        lines.append("## Skipped")
        lines.append("")
        for r in skipped:
            lines.append(f"- `{r.technique_id}` — {r.message}")
        lines.append("")

    if problems:
        lines.append("## Errors / refused")
        lines.append("")
        for r in problems:
            lines.append(f"- `{r.technique_id}` ({r.status}) — {r.message}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "_advsim is an authorized-use-only tool. Emulations are benign and "
        "reversible; run `advsim cleanup` to remove any sandbox residue._"
    )
    return "\n".join(lines)


def _observed_lines(run: TechniqueRun) -> list[str]:
    out: list[str] = []
    for step in run.simulate_steps:
        out.append(f"{step.kind}: {step.detail}")
    return out


# ---------------------------------------------------------------------------
# SARIF 2.1.0
# ---------------------------------------------------------------------------


def to_sarif(report: RunReport) -> str:
    """Emit a SARIF 2.1.0 log. Each emulated technique is a result whose rule is
    the ATT&CK technique; the message tells the operator what telemetry to
    verify. Severity is informational — these are benign emulations."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for run in report.runs:
        if run.status not in ("ran", "cleaned"):
            continue
        rule_id = run.attack_id or run.technique_id
        if rule_id not in rules:
            help_text = "Expected telemetry:\n" + "\n".join(
                f"- {t}" for t in run.expected_telemetry
            )
            rule: dict[str, Any] = {
                "id": rule_id,
                "name": run.name.replace(" ", ""),
                "shortDescription": {"text": run.name},
                "fullDescription": {
                    "text": f"Benign emulation of ATT&CK {run.attack_id} ({run.tactic})."
                },
                "helpUri": f"{_ATTACK_URL}{run.attack_id.replace('.', '/')}/"
                if run.attack_id
                else "https://attack.mitre.org/",
                "help": {"text": help_text},
                "properties": {
                    "tags": ["adversary-emulation", "detection-validation", run.tactic],
                    "attack_id": run.attack_id,
                    "tactic": run.tactic,
                },
                "defaultConfiguration": {"level": "note"},
            }
            rules[rule_id] = rule

        message = (
            f"Emulated {run.name} ({run.attack_id}). "
            f"Verify your detections produced: "
            + "; ".join(run.expected_telemetry)
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": "note",
                "message": {"text": message},
                "properties": {
                    "advsim_technique": run.technique_id,
                    "status": run.status,
                    "started": run.started,
                    "finished": run.finished,
                },
            }
        )

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "advsim",
                        "informationUri": "https://github.com/cognis-digital/advsim",
                        "version": report.tool_version,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


# ---------------------------------------------------------------------------
# STIX 2.1
# ---------------------------------------------------------------------------


def _deterministic_id(prefix: str, seed: str) -> str:
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return f"{prefix}--{uuid.UUID(digest[:32])}"


def to_stix(report: RunReport) -> str:
    """Emit a STIX 2.1 bundle of the emulated TTPs as attack-pattern SDOs, tied
    to an identity (advsim) via a report SDO."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    objects: list[dict[str, Any]] = []

    identity_id = _deterministic_id("identity", "advsim-tool")
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": "advsim",
        "identity_class": "system",
        "description": "advsim benign adversary-emulation harness (authorized use only).",
    }
    objects.append(identity)

    pattern_ids: list[str] = []
    for run in report.runs:
        if run.status not in ("ran", "cleaned") or not run.attack_id:
            continue
        ap_id = _deterministic_id("attack-pattern", run.attack_id)
        if ap_id in pattern_ids:
            continue
        pattern_ids.append(ap_id)
        attack_pattern = {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": ap_id,
            "created": now,
            "modified": now,
            "created_by_ref": identity_id,
            "name": run.attack_name or run.name,
            "description": (
                f"Benignly emulated by advsim. Expected telemetry: "
                + "; ".join(run.expected_telemetry)
            ),
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": run.attack_id,
                    "url": f"{_ATTACK_URL}{run.attack_id.replace('.', '/')}/",
                }
            ],
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": run.tactic.lower().replace(" ", "-"),
                }
            ],
        }
        objects.append(attack_pattern)

    report_seed = report.generated + (report.scenario_id or "single")
    report_sdo = {
        "type": "report",
        "spec_version": "2.1",
        "id": _deterministic_id("report", report_seed),
        "created": now,
        "modified": now,
        "created_by_ref": identity_id,
        "name": f"advsim emulation report ({report.scenario_id or 'ad-hoc'})",
        "description": "TTPs benignly emulated by advsim for detection validation.",
        "published": now,
        "report_types": ["attack-pattern"],
        "object_refs": [identity_id] + pattern_ids,
    }
    objects.append(report_sdo)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
    return json.dumps(bundle, indent=2)


FORMATTERS = {
    "json": to_json,
    "markdown": to_markdown,
    "md": to_markdown,
    "sarif": to_sarif,
    "stix": to_stix,
}


def render(report: RunReport, fmt: str) -> str:
    fmt = fmt.lower()
    if fmt not in FORMATTERS:
        raise ValueError(f"unknown report format {fmt!r}; choose from {sorted(FORMATTERS)}")
    return FORMATTERS[fmt](report)
