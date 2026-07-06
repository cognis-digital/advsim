# advsim

**Benign, authorized-use-only adversary-emulation and detection-validation harness — mapped to MITRE ATT&CK.**

advsim is a purple-team tool in the same professional category as [MITRE Caldera](https://caldera.mitre.org/) and [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team): you *emulate adversary techniques so your blue team can confirm that its detections fire.* The difference in emphasis is right in the design — **advsim only ever emulates the observable telemetry of a technique using strictly benign, reversible, sandbox-scoped actions.** It never performs real harm, and it is architecturally incapable of doing so (see [the scope guard](#the-benignauthorized-guarantee)).

> ⚠️ **AUTHORIZED USE ONLY.** advsim is for defenders validating detections on systems they own or are explicitly authorized to test. It refuses to run until you assert that authorization with `--authorized` (or `ADVSIM_AUTHORIZED=1`, or `authorized: true` in `advsim.yaml`). Do not run it against systems you do not have written permission to test.

---

## The problem

Blue teams buy SIEMs, EDR, and write detection rules — but rarely get to answer the only question that matters: *if an adversary did X on this host right now, would we actually see it?* Waiting for a real incident is a terrible test. Full red-team engagements are expensive and infrequent. And running actual malware or destructive tooling to "test" detections is reckless.

advsim closes that gap. It reproduces the **telemetry footprint** of ATT&CK techniques — the process creations, DNS queries, file writes, and autostart artifacts your detections should key on — using actions that are provably benign: a marker file in a temp sandbox, a labeled read-only process, a DNS lookup to a non-routable documentation domain. You run it, then go check whether your detections lit up. It produces a **detection-validation report** (Markdown / JSON / **SARIF 2.1.0**) plus a **STIX 2.1** bundle of the emulated TTPs to feed your intel and detection pipelines.

## The benign/authorized guarantee

This is the heart of advsim, not a footnote:

1. **Authorized-use gate.** Nothing runs without an explicit authorization signal. No flag, no run.
2. **Benign, reversible, observable-only emulations.** Every technique's `simulate` step generates *telemetry* and nothing else. Every technique has a `cleanup()` that reverts it. Persistence "writes" a JSON marker describing the key it *would* set — it never touches the real registry, crontab, LaunchAgents, or Startup folder. C2 "beacons" resolve/connect to **non-routable** RFC 5737 / RFC 2606 sink addresses. Credential-access "reads" a labeled decoy file with no secret in it.
3. **A hard, tested scope boundary.** [`safety.py`](src/advsim/safety.py) declares a deny-list of forbidden capabilities — real malware, destructive actions, data exfiltration, DoS, mass-targeting, self-propagation, credential theft against real systems, anything kinetic — and an allow-list of benign ones. Every shipped technique is validated against it. Command strings are checked against a destructive-pattern deny-list. All file activity is confined to a temp sandbox; all network activity is confined to sink hosts.
4. **CI fails on any regression.** [`tests/test_scope_guard.py`](tests/test_scope_guard.py) asserts that no technique can declare a forbidden capability, no destructive command passes the gate, no path escapes the sandbox, no real host is reachable, the authorization gate cannot be bypassed, and the action vocabulary is a closed audited set. **If anyone adds a real-harm capability, CI goes red.**

If a technique cannot be emulated benignly, it is documented as out-of-scope and **not implemented**. See [SECURITY_SCOPE.md](SECURITY_SCOPE.md).

## Install

```bash
# from source
git clone https://github.com/cognis-digital/advsim
cd advsim
pip install .

# or the helper scripts
./install.sh        # Linux / macOS
./install.ps1       # Windows PowerShell
make install        # via Makefile
```

Docker:

```bash
docker build -t advsim .
docker run --rm advsim list
```

Requires Python 3.9+. The only runtime dependency is PyYAML.

## Usage

```bash
advsim list                                   # list techniques + scenarios
advsim run discovery.system_info --authorized # emulate one technique (T1082)
advsim run T1071.004 --authorized             # ...also addressable by ATT&CK id
advsim scenario recon_and_beacon --authorized # run a chained scenario
advsim report --format sarif                  # re-render the last run as SARIF
advsim cleanup                                # remove the sandbox tree
```

Report formats: `markdown` (default), `json`, `sarif`, `stix`.

```bash
# Emit SARIF for your code-scanning / detection pipeline and STIX for your TIP:
advsim scenario full_killchain --authorized --format sarif -o killchain.sarif
advsim scenario full_killchain --authorized --format stix  -o killchain.stix.json
```

Grant authorization once for a session instead of per-command:

```bash
export ADVSIM_AUTHORIZED=1          # or create ./advsim.yaml with `authorized: true`
advsim scenario recon_and_beacon
```

## What a run looks like

```
$ advsim run discovery.system_info --authorized
# advsim detection-validation report
> advsim emulates the observable telemetry of MITRE ATT&CK techniques using
> benign, reversible, sandbox-scoped actions. Nothing below performed real harm.

## What to verify in your SIEM / EDR
### System Information Discovery (T1082)
- Expected telemetry (confirm a detection fired):
  - Process creation event for a system-info discovery binary (ver / uname / systeminfo)
  - Short-lived read-only process spawned by the advsim runner
- Observed benign actions:
  - enumerate_environment: read non-sensitive environment/system metadata
  - spawn_benign_process: spawned benign process: cmd /c ver
```

## ATT&CK coverage

18 benign technique emulations spanning 8 ATT&CK tactics. Every emulation is cross-platform-guarded and reversible.

| ATT&CK ID | Technique | Tactic | advsim id |
|---|---|---|---|
| [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | Discovery | `discovery.system_info` |
| [T1033](https://attack.mitre.org/techniques/T1033/) | System Owner/User Discovery | Discovery | `discovery.account` |
| [T1016](https://attack.mitre.org/techniques/T1016/) | System Network Configuration Discovery | Discovery | `discovery.network_config` |
| [T1057](https://attack.mitre.org/techniques/T1057/) | Process Discovery | Discovery | `discovery.process` |
| [T1069](https://attack.mitre.org/techniques/T1069/) | Permission Groups Discovery | Discovery | `discovery.permission_groups` |
| [T1083](https://attack.mitre.org/techniques/T1083/) | File and Directory Discovery | Discovery | `discovery.file_and_directory` |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution | `execution.command_shell` |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys (Autostart) | Persistence | `persistence.registry_run_key` |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Startup Folder Artifact | Persistence | `persistence.startup_folder` |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task / Cron | Persistence | `persistence.scheduled_task` |
| [T1036.003](https://attack.mitre.org/techniques/T1036/003/) | Masquerading: Rename System Utilities | Defense Evasion | `defense_evasion.masquerading` |
| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | Indicator Removal: File Deletion | Defense Evasion | `defense_evasion.indicator_removal` |
| [T1070.006](https://attack.mitre.org/techniques/T1070/006/) | Indicator Removal: Timestomp | Defense Evasion | `defense_evasion.timestomp` |
| [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Unsecured Credentials in Files (decoy) | Credential Access | `credential_access.file_access_marker` |
| [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Local Data Staging | Collection | `collection.local_staging` |
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | Application Layer Protocol: DNS | Command and Control | `c2.dns_lookup` |
| [T1571](https://attack.mitre.org/techniques/T1571/) | Non-Standard Port Beacon | Command and Control | `c2.beacon_connect` |
| [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol (DNS pattern) | Exfiltration | `exfiltration.dns_pattern` |

Bundled scenarios: `recon_and_beacon`, `persistence_and_evasion`, `full_killchain`.

## How it works

Techniques are **declarative YAML** (`src/advsim/techniques/*.yaml`) mapping to one ATT&CK id, listing benign `simulate` + `cleanup` steps, the expected telemetry, capabilities, and platform guards. Steps are composed from a small, closed, audited [action vocabulary](src/advsim/actions.py) — there is no arbitrary code execution. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/WRITING_TECHNIQUES.md](docs/WRITING_TECHNIQUES.md).

## Development

```bash
pip install -e ".[dev]"
pytest                    # full suite incl. the scope guard
python demos/run_all_demos.py
```

## Not affiliated with MITRE

MITRE ATT&CK® and Caldera™ are trademarks of The MITRE Corporation. advsim references ATT&CK technique identifiers for interoperability and is not affiliated with or endorsed by MITRE.

## License

Cognis Open Community License (COCL-1.0). See [LICENSE](LICENSE).
