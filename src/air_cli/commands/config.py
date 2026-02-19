"""Configuration management."""

from __future__ import annotations

from pathlib import Path

import yaml

from air_cli.approval_auth import setup_pin, reset_pin


def cmd_config(args, identity: dict) -> None:
    """Configure AIR settings."""
    config_path = Path.home() / ".air" / "config.yaml"

    if getattr(args, "setup_pin", False):
        setup_pin(config_path, identity["analyst"])
        return

    if getattr(args, "reset_pin", False):
        reset_pin(config_path, identity["analyst"])
        return

    if args.show:
        if config_path.exists():
            print(config_path.read_text())
        else:
            print("No configuration file found.")
            print(f"Current identity: {identity['analyst']} (source: {identity['analyst_source']})")
        return

    if args.analyst:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config = {}
        if config_path.exists():
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}
        config["analyst"] = args.analyst
        with open(config_path, "w") as f:
            yaml.dump(config, f, default_flow_style=False)
        print(f"Analyst identity set to: {args.analyst}")
        return

    print("Use --analyst <name> to set identity, --show to view config, --setup-pin to configure PIN.")
