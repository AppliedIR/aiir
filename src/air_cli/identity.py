"""Analyst identity resolution.

Always captures os_user. Explicit analyst identity resolved by priority:
1. --analyst flag (highest)
2. AIR_ANALYST env var
3. .air/config.yaml analyst field
4. Falls back to OS username
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import yaml


def get_analyst_identity(flag_override: str | None = None) -> dict:
    """Resolve analyst identity from all sources.

    Returns:
        {
            "os_user": "sansforensics",
            "analyst": "jane.doe",
            "analyst_source": "config" | "flag" | "env" | "os_user"
        }
    """
    os_user = os.environ.get("USER", os.environ.get("USERNAME", "unknown"))

    # Priority 1: --analyst flag
    if flag_override:
        return {"os_user": os_user, "analyst": flag_override, "analyst_source": "flag"}

    # Priority 2: AIR_ANALYST env var
    env_analyst = os.environ.get("AIR_ANALYST")
    if env_analyst:
        return {"os_user": os_user, "analyst": env_analyst, "analyst_source": "env"}

    # Priority 3: .air/config.yaml
    config_path = Path.home() / ".air" / "config.yaml"
    if config_path.exists():
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}
            analyst = config.get("analyst")
            if analyst:
                return {"os_user": os_user, "analyst": analyst, "analyst_source": "config"}
        except Exception:
            pass  # Config file unreadable, fall through

    # Priority 4: OS username
    return {"os_user": os_user, "analyst": os_user, "analyst_source": "os_user"}


def warn_if_unconfigured(identity: dict) -> None:
    """Warn if using OS username fallback."""
    if identity["analyst_source"] == "os_user":
        print(
            f"No analyst identity configured. Using OS user '{identity['os_user']}'.\n"
            f"Run 'air config --analyst <name>' to set your identity.\n"
            f"Tip: For audit accountability, use individual OS accounts rather than shared ones.\n",
            file=sys.stderr,
        )
