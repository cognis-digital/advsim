"""The benign action vocabulary.

Techniques are declared as sequences of these small, audited primitives. There
is no arbitrary code execution: a YAML technique can only invoke actions that
appear in ``ACTIONS`` below, and each one routes through ``advsim.safety`` so
it can only ever touch the sandbox, spawn clearly-labeled benign processes, or
resolve/connect to non-routable documentation sink hosts.

Each action returns an ``ActionResult`` describing what observably happened so
the reporter can tell the operator what telemetry to look for.
"""

from __future__ import annotations

import json
import os
import platform
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from . import safety
from .safety import ScopeViolation


@dataclass
class ActionResult:
    kind: str
    ok: bool
    detail: str
    observed: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


# A registry populated by the @action decorator.
ACTIONS: dict[str, Callable[..., ActionResult]] = {}


def action(name: str):
    def register(fn: Callable[..., ActionResult]) -> Callable[..., ActionResult]:
        ACTIONS[name] = fn
        return fn

    return register


def _sandbox_path(rel: str, technique_id: str) -> Path:
    """Resolve a sandbox-relative path and verify it stays in the sandbox."""
    if not rel:
        raise ScopeViolation(f"{technique_id}: empty path")
    # Reject absolute paths / traversal outright; everything is sandbox-relative.
    candidate = (safety.sandbox_root() / rel).resolve()
    return safety.assert_path_sandboxed(candidate, technique_id)


# ---------------------------------------------------------------------------
# File-marker actions (sandbox only)
# ---------------------------------------------------------------------------


@action("write_marker_file")
def write_marker_file(technique_id: str, **params: Any) -> ActionResult:
    """Write a labeled marker file under the sandbox to generate FS telemetry."""
    rel = params.get("path", "marker.txt")
    content = params.get("content", "advsim benign marker")
    path = _sandbox_path(rel, technique_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).isoformat()
    body = f"# advsim benign emulation marker\n# technique: {technique_id}\n# created: {stamp}\n{content}\n"
    path.write_text(body, encoding="utf-8")
    return ActionResult(
        kind="write_marker_file",
        ok=True,
        detail=f"wrote marker file {path}",
        observed={"path": str(path), "bytes": len(body)},
    )


@action("read_file")
def read_file(technique_id: str, **params: Any) -> ActionResult:
    """Read a sandbox file (benign observable file-access telemetry)."""
    rel = params.get("path", "marker.txt")
    path = _sandbox_path(rel, technique_id)
    data = path.read_text(encoding="utf-8") if path.exists() else ""
    return ActionResult(
        kind="read_file",
        ok=True,
        detail=f"read {path}",
        observed={"path": str(path), "bytes": len(data)},
    )


@action("delete_marker_file")
def delete_marker_file(technique_id: str, **params: Any) -> ActionResult:
    """Delete a sandbox marker file (used by cleanup only)."""
    rel = params.get("path", "marker.txt")
    path = _sandbox_path(rel, technique_id)
    existed = path.exists()
    if existed:
        path.unlink()
    return ActionResult(
        kind="delete_marker_file",
        ok=True,
        detail=f"removed {path}" if existed else f"{path} already absent",
        observed={"path": str(path), "existed": existed},
    )


# ---------------------------------------------------------------------------
# Benign process spawn
# ---------------------------------------------------------------------------

# Only these read-only, harmless discovery binaries may be spawned. They are
# chosen because their *invocation* is what a detection keys on, while their
# effect is nil.
_SAFE_BINARIES = {
    "windows": {
        "whoami": ["whoami"],
        "hostname": ["hostname"],
        "systeminfo": ["cmd", "/c", "ver"],
        "ipconfig": ["ipconfig"],
        "tasklist": ["tasklist"],
        "net_view": ["cmd", "/c", "echo advsim benign net enumeration marker"],
        "reg_query": ["cmd", "/c", "echo advsim benign reg query marker"],
    },
    "linux": {
        "whoami": ["whoami"],
        "hostname": ["hostname"],
        "id": ["id"],
        "uname": ["uname", "-a"],
        "ps": ["ps", "-e"],
        "ifconfig": ["sh", "-c", "echo advsim benign net enumeration marker"],
    },
    "macos": {
        "whoami": ["whoami"],
        "hostname": ["hostname"],
        "id": ["id"],
        "uname": ["uname", "-a"],
        "ps": ["ps", "-A"],
        "ifconfig": ["sh", "-c", "echo advsim benign net enumeration marker"],
    },
}


@action("spawn_benign_process")
def spawn_benign_process(technique_id: str, **params: Any) -> ActionResult:
    """Spawn a labeled, read-only discovery process from a fixed allow-list."""
    plat = _plat()
    name = params.get("binary", "whoami")
    table = _SAFE_BINARIES.get(plat, {})
    if name not in table:
        return ActionResult(
            kind="spawn_benign_process",
            ok=False,
            detail=f"binary {name!r} not available/allowed on {plat}",
            error="unsupported_binary",
        )
    cmd = table[name]
    # Defense-in-depth: verify the resolved command is benign.
    safety.assert_command_benign(" ".join(cmd), technique_id)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        return ActionResult(
            kind="spawn_benign_process",
            ok=True,
            detail=f"spawned benign process: {' '.join(cmd)}",
            observed={
                "process": name,
                "argv": cmd,
                "returncode": proc.returncode,
                "stdout_bytes": len(proc.stdout or ""),
            },
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return ActionResult(
            kind="spawn_benign_process",
            ok=False,
            detail=f"could not spawn {name}",
            error=str(exc),
        )


# ---------------------------------------------------------------------------
# DNS / network sink actions
# ---------------------------------------------------------------------------


@action("dns_lookup")
def dns_lookup(technique_id: str, **params: Any) -> ActionResult:
    """Resolve a non-routable documentation/sink hostname to make DNS telemetry."""
    host = params.get("host", "advsim-c2-emulation.example.com")
    safety.assert_sink_host(host, technique_id)
    resolved: str | None = None
    err: str | None = None
    try:
        resolved = socket.gethostbyname(host)
    except OSError as exc:
        # Expected for .invalid / documentation names; the *query* is the point.
        err = str(exc)
    return ActionResult(
        kind="dns_lookup",
        ok=True,
        detail=f"issued DNS lookup for sink host {host}",
        observed={"host": host, "resolved": resolved, "resolve_error": err},
    )


@action("network_connect_sink")
def network_connect_sink(technique_id: str, **params: Any) -> ActionResult:
    """Attempt a short TCP connect to a non-routable sink (beacon telemetry)."""
    host = params.get("host", "192.0.2.1")  # RFC 5737 - not routable
    port = int(params.get("port", 8443))
    safety.assert_sink_host(host, technique_id)
    connected = False
    err: str | None = None
    try:
        with socket.create_connection((host, port), timeout=1.5):
            connected = True
    except OSError as exc:
        err = str(exc)  # Expected; the outbound attempt is the observable.
    return ActionResult(
        kind="network_connect_sink",
        ok=True,
        detail=f"attempted outbound connect to sink {host}:{port}",
        observed={"host": host, "port": port, "connected": connected, "error": err},
    )


# ---------------------------------------------------------------------------
# Sandbox "registry" / persistence-marker actions (cross-platform files)
# ---------------------------------------------------------------------------


@action("write_sandbox_registry_marker")
def write_sandbox_registry_marker(technique_id: str, **params: Any) -> ActionResult:
    """Emulate a persistence registry/autostart write inside the sandbox.

    On every platform this writes a JSON marker under the sandbox representing
    the key/value an adversary *would* set for autostart persistence. It never
    touches the real registry, LaunchAgents, or crontab.
    """
    key = params.get("key", "HKCU/Software/Microsoft/Windows/CurrentVersion/Run")
    value_name = params.get("value_name", "advsim-benign-autostart")
    value = params.get("value", "C:/advsim-sandbox/benign-marker.txt")
    rel = params.get("path", "registry/run_key.json")
    path = _sandbox_path(rel, technique_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "note": "advsim benign emulation - NOT a real registry/autostart write",
        "technique": technique_id,
        "emulated_key": key,
        "value_name": value_name,
        "value": value,
        "created": datetime.now(timezone.utc).isoformat(),
    }
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return ActionResult(
        kind="write_sandbox_registry_marker",
        ok=True,
        detail=f"wrote emulated persistence marker for {key}",
        observed={"path": str(path), "emulated_key": key, "value_name": value_name},
    )


@action("write_scheduled_task_marker")
def write_scheduled_task_marker(technique_id: str, **params: Any) -> ActionResult:
    """Emulate a scheduled-task/cron persistence write inside the sandbox."""
    name = params.get("task_name", "advsim-benign-task")
    schedule = params.get("schedule", "ONLOGON")
    rel = params.get("path", "scheduled_tasks/task.json")
    path = _sandbox_path(rel, technique_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "note": "advsim benign emulation - NOT a real scheduled task/cron entry",
        "technique": technique_id,
        "task_name": name,
        "schedule": schedule,
        "action": "echo advsim benign marker",
        "created": datetime.now(timezone.utc).isoformat(),
    }
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return ActionResult(
        kind="write_scheduled_task_marker",
        ok=True,
        detail=f"wrote emulated scheduled-task marker {name}",
        observed={"path": str(path), "task_name": name, "schedule": schedule},
    )


# ---------------------------------------------------------------------------
# Read-only local enumeration
# ---------------------------------------------------------------------------


@action("enumerate_environment")
def enumerate_environment(technique_id: str, **params: Any) -> ActionResult:
    """Read a small, non-sensitive slice of environment/system info (read only)."""
    keys = params.get("keys", ["PATH", "PROCESSOR_ARCHITECTURE", "SHELL", "OS"])
    observed = {k: (k in os.environ) for k in keys}
    observed["platform"] = platform.platform()
    observed["python"] = sys.version.split()[0]
    return ActionResult(
        kind="enumerate_environment",
        ok=True,
        detail="read non-sensitive environment/system metadata",
        observed=observed,
    )


@action("log_event")
def log_event(technique_id: str, **params: Any) -> ActionResult:
    """Append a benign event line to the sandbox activity log."""
    message = params.get("message", "advsim benign event")
    rel = params.get("path", "activity.log")
    path = _sandbox_path(rel, technique_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    line = f"{datetime.now(timezone.utc).isoformat()} {technique_id} {message}\n"
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line)
    return ActionResult(
        kind="log_event",
        ok=True,
        detail=f"logged benign event to {path}",
        observed={"path": str(path), "message": message},
    )


def _plat() -> str:
    from .model import current_platform

    return current_platform()


def run_action(act, technique_id: str) -> ActionResult:
    """Dispatch a model.Action to its registered benign implementation."""
    fn = ACTIONS.get(act.kind)
    if fn is None:
        return ActionResult(
            kind=act.kind,
            ok=False,
            detail=f"unknown action {act.kind!r}",
            error="unknown_action",
        )
    try:
        return fn(technique_id, **act.params)
    except ScopeViolation:
        raise
    except Exception as exc:  # pragma: no cover - defensive
        return ActionResult(
            kind=act.kind,
            ok=False,
            detail=f"action {act.kind} raised",
            error=str(exc),
        )
