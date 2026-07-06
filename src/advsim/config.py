"""Authorization configuration.

advsim will not run any emulation unless it is explicitly authorized. There are
three ways to grant authorization, checked in order:

1. the ``--authorized`` CLI flag,
2. the ``ADVSIM_AUTHORIZED=1`` environment variable,
3. ``authorized: true`` in an ``advsim.yaml`` config file.

Absent all three, advsim refuses to run and prints the scope notice.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml


def config_authorized(config_path: str | Path | None = None) -> bool:
    path = Path(config_path) if config_path else Path.cwd() / "advsim.yaml"
    if not path.exists():
        return False
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return False
    return bool(data.get("authorized", False))


def env_authorized() -> bool:
    return os.environ.get("ADVSIM_AUTHORIZED", "").strip().lower() in ("1", "true", "yes")


def resolve_authorization(flag: bool, config_path: str | Path | None = None) -> bool:
    return bool(flag) or env_authorized() or config_authorized(config_path)
