"""Configuration management."""

from __future__ import annotations

from pathlib import Path

import yaml

from aiir_cli.approval_auth import setup_pin, reset_pin


def cmd_config(args, identity: dict) -> None:
    """Configure AIIR settings."""
    config_path = Path.home() / ".aiir" / "config.yaml"

    if getattr(args, "setup_pin", False):
        setup_pin(config_path, identity["examiner"])
        return

    if getattr(args, "reset_pin", False):
        reset_pin(config_path, identity["examiner"])
        return

    if args.show:
        if config_path.exists():
            print(config_path.read_text())
        else:
            print("No configuration file found.")
            print(f"Current identity: {identity['examiner']} (source: {identity['examiner_source']})")
        return

    examiner_val = getattr(args, "examiner", None)
    if examiner_val:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config = {}
        if config_path.exists():
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}
        config["examiner"] = examiner_val
        # Remove deprecated 'analyst' key if present
        config.pop("analyst", None)
        with open(config_path, "w") as f:
            yaml.dump(config, f, default_flow_style=False)
        print(f"Examiner identity set to: {examiner_val}")
        return

    print("Use --examiner <name> to set identity, --show to view config, --setup-pin to configure PIN.")
