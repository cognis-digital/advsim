# Security scope & ethos

advsim is an **authorized-use-only, benign** adversary-emulation tool. This document is the binding statement of what advsim will and will not do. It is enforced in code ([`src/advsim/safety.py`](src/advsim/safety.py)) and in CI ([`tests/test_scope_guard.py`](tests/test_scope_guard.py)).

## Authorized use only

advsim is intended for defenders — blue teams, purple teams, detection engineers — validating their own telemetry and detection coverage on systems they own or are **explicitly, in writing, authorized to test**. Emulating adversary behavior on systems you do not have permission to test may be illegal.

advsim enforces this operationally: it will not execute any emulation until an authorization signal is present (`--authorized`, `ADVSIM_AUTHORIZED=1`, or `authorized: true` in `advsim.yaml`). This is a speed bump and an accountability marker, not a substitute for real authorization — that is your responsibility.

## What advsim does (benign, reversible, observable-only)

Every emulation produces only the *telemetry a detection should catch* and then reverts itself:

- **Files:** writes clearly-labeled marker files under a single temp sandbox directory (`<tempdir>/advsim-sandbox`). Never touches user data, system files, or config outside that tree.
- **Processes:** spawns short-lived, **read-only** discovery utilities from a fixed allow-list (`whoami`, `hostname`, `ver`/`uname`, `tasklist`/`ps`, and `echo`-only stand-ins). The *invocation* is the observable; the effect is nil.
- **Persistence:** writes a JSON *marker* describing the registry key / scheduled task / startup artifact an adversary would create. It never modifies the real registry, crontab, LaunchAgents, systemd, or Startup folder.
- **Network / C2:** issues DNS lookups and short TCP connect attempts to **non-routable** documentation/sink hosts only (RFC 5737 `192.0.2.0/24`, RFC 2606/6761 `.example`, `.invalid`, `.test`, localhost). It never contacts a real host, and it sends no data.
- **Credential access:** creates and reads a labeled *decoy* file containing no secret. It never touches real credential stores, keychains, browser data, or process memory (e.g. LSASS).
- **Cleanup:** every technique has a `cleanup()`; `advsim cleanup` removes the entire sandbox tree.

## What advsim will NEVER do (hard deny-list)

These capability categories are refused by `safety.FORBIDDEN_CAPABILITIES` and asserted un-shippable by the scope-guard test:

- real malware or malicious payloads
- destructive or irreversible actions (deletion of real data, wiping, encryption/ransomware, disabling recovery)
- data exfiltration to real endpoints
- denial of service
- mass targeting / scanning of third parties
- self-propagation / worming
- credential theft against real systems
- privilege-escalation, lateral-movement, or remote-code-execution *exploitation*
- anything kinetic or affecting physical/safety systems

If a technique cannot be represented benignly, it is documented as **out of scope and not implemented**, rather than shipped in a diluted-but-still-harmful form.

## Defense in depth

1. **Capability allow/deny lists** — a technique declaring anything off the benign allow-list is refused at load and again at run time.
2. **Destructive-command static gate** — any command string an action would run is matched against a deny-list of destructive patterns (`rm -rf /`, `mkfs`, `format`, `vssadmin delete`, fork bombs, pipe-to-shell, etc.).
3. **Sandbox containment** — all paths are resolved and asserted to live inside the sandbox; traversal/escape is refused.
4. **Sink-host containment** — all network targets are asserted to be non-routable documentation/sink hosts.
5. **No shell injection** — actions never use `subprocess(shell=True)`; the action vocabulary is a closed, audited set.
6. **CI enforcement** — the above are all asserted by tests that must pass for CI to be green.

## Reporting a concern

If you find a way to make advsim perform a harmful or irreversible action, or to bypass the authorization gate or sandbox, please open a **private** security advisory on the GitHub repository (Security → Advisories) rather than a public issue.
