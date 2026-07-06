"""advsim - benign, authorized-use-only adversary-emulation harness.

advsim emulates the *observable telemetry* of MITRE ATT&CK techniques using
strictly benign, reversible, sandbox-scoped actions so that blue teams can
validate their detections fire. It never performs real harm.

See SECURITY_SCOPE.md for the hard scope and the authorized-use policy.
"""

__version__ = "1.0.0"

__all__ = ["__version__"]
