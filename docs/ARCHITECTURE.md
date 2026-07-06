# Architecture

advsim is a small, layered Python package. Every layer that can *act* routes
through the safety layer, so there is a single, auditable place where the
benign-only contract is enforced.

```
                 ┌──────────────────────────────────────────┐
   CLI (cli.py)  │  list / run / scenario / report / cleanup  │
                 └───────────────┬────────────────────────────┘
                                 │ authorization gate (config.py)
                 ┌───────────────▼────────────┐
   Runner        │  validates scope, guards    │  produces RunReport
   (runner.py)   │  platform, runs simulate +  │────────────────────┐
                 │  cleanup, records telemetry │                    │
                 └───────────────┬─────────────┘                    │
                                 │                                   ▼
        ┌────────────────────────▼─────────┐        ┌──────────────────────────┐
  Model │ Technique / Scenario / Action     │  Report│ markdown / json / SARIF   │
 (model)│ loaded from declarative YAML      │(report)│ 2.1.0 / STIX 2.1          │
        └────────────────────────┬──────────┘        └──────────────────────────┘
                                 │ dispatch
                 ┌───────────────▼─────────────┐
  Actions        │ closed, audited vocabulary   │
 (actions.py)    │ of benign primitives         │
                 └───────────────┬──────────────┘
                                 │ EVERY primitive calls ↓
                 ┌───────────────▼──────────────┐
  Safety         │ capability allow/deny lists,  │  ← the single scope boundary
 (safety.py)     │ destructive-cmd gate, sandbox │
                 │ containment, sink-host gate   │
                 └───────────────────────────────┘
```

## Modules

- **`safety.py`** — the load-bearing guardrail. Defines the sandbox root, the
  forbidden/allowed capability sets, the destructive-command patterns, and the
  sink-host allow-list, plus the `assert_*` functions every action calls. If you
  read one file, read this one.
- **`model.py`** — dataclasses for `Technique`, `Scenario`, `Action`, plus YAML
  loading and per-technique `validate()`. Platform detection lives here.
- **`actions.py`** — the closed vocabulary of benign primitives
  (`write_marker_file`, `spawn_benign_process`, `dns_lookup`,
  `network_connect_sink`, `write_sandbox_registry_marker`, …). New actions must
  be added to the audited set in the scope-guard test.
- **`library.py`** — loads the shipped `techniques/*.yaml` and `scenarios/*.yaml`.
- **`runner.py`** — the only place emulations execute. Enforces authorization,
  re-validates scope before each run, applies platform guards, runs `simulate`
  then always attempts `cleanup`, and records exactly what happened.
- **`report.py`** — renders a `RunReport` to Markdown, JSON, SARIF 2.1.0, or
  STIX 2.1.
- **`config.py`** — resolves the authorization signal (flag / env / config).
- **`cli.py`** — argparse front end.

## Why declarative techniques

Techniques are data (YAML), not code. A technique can only compose actions that
already exist in the audited vocabulary, so adding a technique cannot introduce
new behavior — it can only *arrange* already-benign primitives. This keeps the
attack surface tiny and the scope guarantee tractable.

## Data flow of a run

1. CLI resolves authorization; refuses if absent.
2. Library loads and validates the requested technique(s).
3. Runner checks platform support, then dispatches each `simulate` action
   through `actions.run_action`, which calls the registered primitive; each
   primitive calls the relevant `safety.assert_*` before doing anything.
4. Runner runs `cleanup` the same way.
5. The `RunReport` of observed steps + expected telemetry is rendered.

## Reports as detection-validation artifacts

- **Markdown** — human report: coverage table + "what to verify in your SIEM/EDR".
- **JSON** — machine-readable full record (used by `advsim report`).
- **SARIF 2.1.0** — each ATT&CK technique is a rule; each emulation a `note`-level
  result. Drops into code-scanning / detection-pipeline tooling that speaks SARIF.
- **STIX 2.1** — a bundle of `attack-pattern` SDOs (with ATT&CK external refs and
  kill-chain phases) tied to an `identity` and a `report` SDO, for threat-intel
  platforms.
