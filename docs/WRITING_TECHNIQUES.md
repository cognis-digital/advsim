# Writing a technique

A technique is a YAML file in `src/advsim/techniques/`. It maps to exactly one
MITRE ATT&CK id and describes benign `simulate` steps, their `cleanup`, the
telemetry a defender should expect, the benign capabilities it uses, and the
platforms it runs on.

## Schema

```yaml
id: tactic.short_name            # advsim id, dot-namespaced by tactic
name: Human Readable Name
attack_id: T1234                 # or T1234.001 for a sub-technique
attack_name: MITRE ATT&CK name
tactic: Discovery                # ATT&CK tactic
description: >
  What real adversaries do, and exactly how advsim emulates it BENIGNLY.
platforms: [all]                 # or a subset: [windows, linux, macos]
capabilities:                    # MUST be a subset of the benign allow-list
  - benign_process_spawn
  - log_event
expected_telemetry:              # what a detection should observe
  - "Process creation event for ..."
simulate:                        # ordered benign steps
  - action: spawn_benign_process
    binary: whoami
  - action: log_event
    message: "emulated T1234 ..."
cleanup:                         # revert everything simulate created
  - action: delete_marker_file
    path: activity.log
references:
  - https://attack.mitre.org/techniques/T1234/
```

## The benign capability allow-list

Only these capability tokens are permitted (see `safety.ALLOWED_CAPABILITIES`):

`sandbox_file_write`, `sandbox_registry_write`, `benign_process_spawn`,
`dns_lookup_sink`, `local_enumeration`, `read_only_query`,
`network_connect_sink`, `sandbox_scheduled_task`, `log_event`,
`environment_read`.

Declaring anything on the forbidden list (real malware, destructive action, data
exfiltration, DoS, mass targeting, self-propagation, credential theft, kinetic,
ransomware, exploitation) — or anything not on the allow-list — makes the
technique refuse to load and fails the scope-guard test.

## The action vocabulary

Techniques compose these audited primitives (see `actions.py`):

| action | what it does (benignly) |
|---|---|
| `write_marker_file` | write a labeled file under the sandbox |
| `read_file` | read a sandbox file |
| `delete_marker_file` | delete a sandbox file (cleanup) |
| `spawn_benign_process` | run one read-only binary from the allow-list |
| `dns_lookup` | resolve a non-routable sink hostname |
| `network_connect_sink` | short TCP connect to a non-routable sink |
| `write_sandbox_registry_marker` | write a JSON marker for an emulated autostart key |
| `write_scheduled_task_marker` | write a JSON marker for an emulated task |
| `enumerate_environment` | read non-sensitive env/system metadata |
| `log_event` | append a line to the sandbox activity log |

If you need a genuinely new primitive, add it to `actions.py` **and** to
`AUDITED_ACTIONS` in `tests/test_scope_guard.py` after confirming it can only act
within the sandbox / against sink hosts and routes through `safety.assert_*`.

## Rules of thumb

- If it can't be emulated without real harm, it doesn't get built.
- Everything `simulate` creates, `cleanup` must remove.
- Prefer the smallest action set that still produces the target telemetry.
- Set accurate `platforms`; unsupported platforms are skipped, not errored.
- Run `pytest` — the parametrized library tests will pick up your new technique.
