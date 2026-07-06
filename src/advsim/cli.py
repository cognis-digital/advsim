"""advsim command-line interface.

Commands:
    advsim list                         list techniques / scenarios
    advsim run <technique> --authorized run one technique benignly
    advsim scenario <file> --authorized run a chained scenario benignly
    advsim report [--format ...]        (re)render the last run report
    advsim cleanup                      remove the sandbox tree

The --authorized gate (or ADVSIM_AUTHORIZED=1 / advsim.yaml) is mandatory for
anything that runs an emulation.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# On Windows the default console encoding is often cp1252, which cannot render
# the box glyphs / arrows we print. Reconfigure stdout/stderr to UTF-8 so output
# is consistent across platforms.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass

from . import __version__, library, report
from .config import resolve_authorization
from .model import current_platform, load_scenario_file
from .runner import Runner, run_single
from .safety import AuthorizationError, ScopeViolation, sandbox_root

SCOPE_NOTICE = (
    "advsim is an AUTHORIZED-USE-ONLY adversary-emulation tool.\n"
    "It performs only BENIGN, reversible, sandbox-scoped actions to help you\n"
    "validate detections. Run it ONLY against systems you are explicitly\n"
    "authorized to test. Re-run with --authorized to confirm you have that\n"
    "authorization (or set ADVSIM_AUTHORIZED=1, or authorized: true in advsim.yaml)."
)

_LAST_REPORT = sandbox_root().parent / "advsim-last-report.json"


def _print(msg: str) -> None:
    sys.stdout.write(msg + "\n")


def cmd_list(args: argparse.Namespace) -> int:
    techniques = library.load_all_techniques()
    scenarios = library.load_all_scenarios()
    plat = current_platform()
    if args.json:
        payload = {
            "techniques": [
                {
                    "id": t.id,
                    "attack_id": t.attack_id,
                    "attack_name": t.attack_name,
                    "name": t.name,
                    "tactic": t.tactic,
                    "platforms": t.platforms,
                    "supported_here": t.supported_here(plat),
                    "capabilities": t.capabilities,
                }
                for t in techniques
            ],
            "scenarios": [
                {"id": s.id, "name": s.name, "techniques": s.techniques}
                for s in scenarios
            ],
        }
        _print(json.dumps(payload, indent=2))
        return 0

    _print(f"advsim {__version__} — benign adversary-emulation techniques")
    _print(f"platform: {plat}   sandbox: {sandbox_root()}")
    _print("")
    _print("Techniques:")
    for t in techniques:
        mark = "•" if t.supported_here(plat) else "-"
        _print(
            f"  {mark} {t.id:<34} {t.attack_id:<10} {t.tactic:<20} {t.name}"
        )
    _print("")
    _print("Scenarios:")
    for s in scenarios:
        _print(f"    {s.id:<28} {s.name}  ({len(s.techniques)} techniques)")
    _print("")
    _print("Legend: •=runs on this platform  -=guarded/skipped here")
    return 0


def _write_last_report(rep) -> None:
    try:
        _LAST_REPORT.write_text(report.to_json(rep), encoding="utf-8")
    except OSError:
        pass


def _emit(rep, args) -> None:
    text = report.render(rep, args.format)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        _print(f"wrote {args.format} report to {args.output}")
    else:
        _print(text)


def cmd_run(args: argparse.Namespace) -> int:
    authorized = resolve_authorization(args.authorized, args.config)
    if not authorized:
        _print(SCOPE_NOTICE)
        return 2
    tech = library.find_technique(args.technique)
    if tech is None:
        _print(f"error: technique {args.technique!r} not found (try `advsim list`)")
        return 1
    try:
        rep = run_single(tech, authorized=authorized, do_cleanup=not args.no_cleanup)
    except AuthorizationError as exc:
        _print(str(exc))
        return 2
    except ScopeViolation as exc:
        _print(f"scope violation: {exc}")
        return 3
    _write_last_report(rep)
    _emit(rep, args)
    return 0


def cmd_scenario(args: argparse.Namespace) -> int:
    authorized = resolve_authorization(args.authorized, args.config)
    if not authorized:
        _print(SCOPE_NOTICE)
        return 2

    # Accept a shipped scenario id or a path to a scenario file.
    scenarios = library.scenario_index()
    if args.scenario in scenarios:
        scenario = scenarios[args.scenario]
    else:
        path = Path(args.scenario)
        if not path.exists():
            _print(f"error: scenario {args.scenario!r} not found as id or file")
            return 1
        scenario = load_scenario_file(path)

    try:
        runner = Runner(authorized=authorized)
        rep = runner.run_scenario(
            scenario, library.technique_index(), do_cleanup=not args.no_cleanup
        )
    except AuthorizationError as exc:
        _print(str(exc))
        return 2
    _write_last_report(rep)
    _emit(rep, args)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    if not _LAST_REPORT.exists():
        _print("no previous run found; run a technique or scenario first")
        return 1
    data = json.loads(_LAST_REPORT.read_text(encoding="utf-8"))
    rep = _report_from_dict(data)
    _emit(rep, args)
    return 0


def cmd_cleanup(args: argparse.Namespace) -> int:
    # Cleanup is always safe to run and needs no authorization: it only removes
    # advsim's own sandbox tree.
    runner = Runner.__new__(Runner)  # cleanup does not require authorization
    result = runner.cleanup_all()
    if _LAST_REPORT.exists():
        try:
            _LAST_REPORT.unlink()
        except OSError:
            pass
    _print(
        f"sandbox {result['sandbox']} "
        + ("removed" if result["removed"] else "was already clean")
    )
    return 0


def _report_from_dict(data: dict):
    from .runner import RunReport, StepRecord, TechniqueRun

    runs = []
    for r in data.get("runs", []):
        runs.append(
            TechniqueRun(
                technique_id=r["technique_id"],
                attack_id=r["attack_id"],
                attack_name=r["attack_name"],
                tactic=r["tactic"],
                name=r["name"],
                status=r["status"],
                platform=r["platform"],
                started=r["started"],
                finished=r["finished"],
                expected_telemetry=r.get("expected_telemetry", []),
                simulate_steps=[StepRecord(**s) for s in r.get("simulate_steps", [])],
                cleanup_steps=[StepRecord(**s) for s in r.get("cleanup_steps", [])],
                references=r.get("references", []),
                message=r.get("message", ""),
            )
        )
    return RunReport(
        tool_version=data.get("tool_version", __version__),
        generated=data.get("generated", ""),
        platform=data.get("platform", ""),
        sandbox=data.get("sandbox", ""),
        scenario_id=data.get("scenario_id"),
        runs=runs,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="advsim",
        description=(
            "Benign, authorized-use-only adversary-emulation harness for "
            "detection validation (MITRE ATT&CK)."
        ),
        epilog=SCOPE_NOTICE,
    )
    parser.add_argument("--version", action="version", version=f"advsim {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_report_opts(p):
        p.add_argument(
            "--format",
            default="markdown",
            choices=sorted(report.FORMATTERS),
            help="report format (default: markdown)",
        )
        p.add_argument("--output", "-o", help="write report to a file instead of stdout")

    def add_auth_opts(p):
        p.add_argument(
            "--authorized",
            action="store_true",
            help="confirm you are authorized to test the target (required gate)",
        )
        p.add_argument("--config", help="path to advsim.yaml (default: ./advsim.yaml)")
        p.add_argument(
            "--no-cleanup",
            action="store_true",
            help="leave sandbox residue in place (default: auto-clean each technique)",
        )

    p_list = sub.add_parser("list", help="list available techniques and scenarios")
    p_list.add_argument("--json", action="store_true", help="emit JSON")
    p_list.set_defaults(func=cmd_list)

    p_run = sub.add_parser("run", help="run one benign technique emulation")
    p_run.add_argument("technique", help="advsim technique id or MITRE ATT&CK id")
    add_auth_opts(p_run)
    add_report_opts(p_run)
    p_run.set_defaults(func=cmd_run)

    p_scen = sub.add_parser("scenario", help="run a chained scenario emulation")
    p_scen.add_argument("scenario", help="scenario id or path to a scenario YAML")
    add_auth_opts(p_scen)
    add_report_opts(p_scen)
    p_scen.set_defaults(func=cmd_scenario)

    p_rep = sub.add_parser("report", help="re-render the last run's report")
    add_report_opts(p_rep)
    p_rep.set_defaults(func=cmd_report)

    p_clean = sub.add_parser("cleanup", help="remove the advsim sandbox tree")
    p_clean.set_defaults(func=cmd_cleanup)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
