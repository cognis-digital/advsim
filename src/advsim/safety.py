"""Safety and scope enforcement for advsim.

This module is the load-bearing guardrail of the whole tool. Every emulation
is validated against a *deny-list of destructive / real-harm capabilities*
before it is ever allowed to run. The scope-guard test (tests/test_scope_guard.py)
asserts that no shipped technique can pass a harmful action through this gate,
so any attempt to add a real-harm capability fails CI.

The philosophy: advsim only ever produces the *telemetry a detection should
catch*. It writes marker files under a sandbox, spawns clearly-labeled benign
processes, resolves DNS names to sink hosts, and touches sandbox-scoped keys.
It must never do anything irreversible, destructive, exfiltrating, or kinetic.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path


class ScopeViolation(Exception):
    """Raised when an action would exceed advsim's benign, authorized scope."""


class AuthorizationError(Exception):
    """Raised when advsim is invoked without an explicit authorization gate."""


# ---------------------------------------------------------------------------
# Sandbox
# ---------------------------------------------------------------------------

SANDBOX_MARKER = "advsim-sandbox"


def sandbox_root() -> Path:
    """Return the single directory tree advsim is permitted to write to.

    Everything advsim creates lives under here, is clearly labeled, and is
    removed by cleanup. It lives under the OS temp dir, never in a real
    system, user data, or config location.
    """
    root = Path(tempfile.gettempdir()) / SANDBOX_MARKER
    root.mkdir(parents=True, exist_ok=True)
    return root


def is_within_sandbox(path: os.PathLike | str) -> bool:
    """True only if *path* resolves inside the advsim sandbox tree."""
    try:
        target = Path(path).resolve()
        root = sandbox_root().resolve()
    except (OSError, ValueError):
        return False
    return target == root or root in target.parents


# ---------------------------------------------------------------------------
# Hard deny-list — the non-negotiable scope boundary
# ---------------------------------------------------------------------------

# Capability categories advsim will NEVER implement. Techniques declare the
# capabilities they touch; anything intersecting this set is refused.
FORBIDDEN_CAPABILITIES = frozenset(
    {
        "real_malware",
        "destructive_action",
        "data_exfiltration",
        "denial_of_service",
        "mass_targeting",
        "self_propagation",
        "credential_theft",
        "kinetic",
        "ransomware",
        "privilege_escalation_exploit",
        "lateral_movement_exploit",
        "remote_code_execution",
    }
)

# Only these benign capability tokens are permitted for a shipped technique.
ALLOWED_CAPABILITIES = frozenset(
    {
        "sandbox_file_write",
        "sandbox_registry_write",
        "benign_process_spawn",
        "dns_lookup_sink",
        "local_enumeration",
        "read_only_query",
        "network_connect_sink",
        "sandbox_scheduled_task",
        "log_event",
        "environment_read",
    }
)

# Destructive shell/command patterns that must never appear in an emulation's
# resolved command. Used as a defense-in-depth static check.
DESTRUCTIVE_PATTERNS = [
    re.compile(r"\brm\s+-rf\s+/", re.IGNORECASE),
    re.compile(r"\bmkfs\b", re.IGNORECASE),
    re.compile(r"\bdd\s+if=.*of=/dev/", re.IGNORECASE),
    re.compile(r"\bformat\s+[a-z]:", re.IGNORECASE),
    re.compile(r"\bdel\s+/[sq]\b", re.IGNORECASE),
    re.compile(r"Remove-Item.*-Recurse.*-Force.*[A-Za-z]:\\", re.IGNORECASE),
    re.compile(r"\bcipher\s+/w", re.IGNORECASE),
    re.compile(r"\bvssadmin\b.*\bdelete\b", re.IGNORECASE),
    re.compile(r"\bwbadmin\b.*\bdelete\b", re.IGNORECASE),
    re.compile(r"\bshutdown\b", re.IGNORECASE),
    re.compile(r"\bhalt\b|\breboot\b", re.IGNORECASE),
    re.compile(r"\bnet\s+user\s+\S+\s+\S+\s+/add", re.IGNORECASE),
    re.compile(r":\(\)\s*\{.*\|.*&\s*\}", re.IGNORECASE),  # fork bomb
    re.compile(r"\bcurl\b.*\|\s*(ba)?sh", re.IGNORECASE),  # pipe-to-shell
    re.compile(r"\bInvoke-Expression\b|\biex\b", re.IGNORECASE),
]

# Hosts we will resolve/connect to are constrained to documentation / sink
# ranges that cannot cause harm (RFC 5737 / RFC 6761 / RFC 2606).
ALLOWED_SINK_SUFFIXES = (
    ".example.com",
    ".example.net",
    ".example.org",
    ".invalid",
    ".test",
    ".localhost",
)
ALLOWED_SINK_HOSTS = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "::1",
        # RFC 5737 documentation address blocks - not routable.
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
    }
)


def assert_capabilities_allowed(capabilities: list[str], technique_id: str) -> None:
    """Validate a technique's declared capabilities against the scope policy.

    Raises ScopeViolation if the technique declares any forbidden capability
    or any capability outside the benign allow-list.
    """
    caps = set(capabilities or [])
    if not caps:
        raise ScopeViolation(
            f"{technique_id}: technique declares no capabilities; refusing to run"
        )
    forbidden = caps & FORBIDDEN_CAPABILITIES
    if forbidden:
        raise ScopeViolation(
            f"{technique_id}: declares forbidden capability(ies): "
            f"{sorted(forbidden)}"
        )
    unknown = caps - ALLOWED_CAPABILITIES
    if unknown:
        raise ScopeViolation(
            f"{technique_id}: declares capability(ies) not on the benign "
            f"allow-list: {sorted(unknown)}"
        )


def assert_command_benign(command: str, technique_id: str) -> None:
    """Static defense-in-depth check on any command string an emulation runs."""
    if not command:
        return
    for pattern in DESTRUCTIVE_PATTERNS:
        if pattern.search(command):
            raise ScopeViolation(
                f"{technique_id}: command matches a destructive pattern "
                f"({pattern.pattern!r}); refusing to run"
            )


def assert_path_sandboxed(path: os.PathLike | str, technique_id: str) -> Path:
    """Ensure an emulation only ever touches the sandbox; return resolved path."""
    if not is_within_sandbox(path):
        raise ScopeViolation(
            f"{technique_id}: path {path!r} is outside the advsim sandbox "
            f"({sandbox_root()}); refusing to touch it"
        )
    return Path(path).resolve()


def assert_sink_host(host: str, technique_id: str) -> None:
    """Ensure any network/DNS emulation only targets non-routable sink hosts."""
    h = (host or "").strip().lower().rstrip(".")
    if h in ALLOWED_SINK_HOSTS:
        return
    if any(h.endswith(suffix) for suffix in ALLOWED_SINK_SUFFIXES):
        return
    raise ScopeViolation(
        f"{technique_id}: host {host!r} is not an approved documentation/sink "
        f"host; refusing network activity to a real destination"
    )
