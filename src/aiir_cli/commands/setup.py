"""Interactive setup command for AIIR MCP servers.

Phases:
1. Detect installed MCP servers
2. Configure credentials (OpenCTI, REMnux)
3. Select AI client(s) to configure
4. Generate configuration files
"""

from __future__ import annotations

import sys
from pathlib import Path

from aiir_cli.setup.detect import detect_installed_mcps, detect_venv_mcps
from aiir_cli.setup.wizard import (
    wizard_opencti,
    wizard_remnux,
    wizard_clients,
    wizard_analyst,
)
from aiir_cli.setup.config_gen import (
    generate_mcp_json,
    generate_desktop_config,
    generate_gateway_yaml,
)


def cmd_setup(args, identity: dict) -> None:
    """Run interactive setup."""
    force = getattr(args, "force_reprompt", False)
    non_interactive = getattr(args, "non_interactive", False)

    print("=" * 60)
    print("  AIIR Setup — Forensic Investigation Platform")
    print("=" * 60)

    # Phase 1: Detect
    print("\n[1/4] Detecting installed MCP servers...")
    installed = detect_installed_mcps()
    venv_mcps = detect_venv_mcps()

    # Merge: prefer venv installs over system installs
    mcp_map: dict[str, dict] = {}
    for mcp in installed:
        if mcp["available"]:
            mcp_map[mcp["name"]] = mcp
    for mcp in venv_mcps:
        if mcp["available"]:
            mcp_map[mcp["name"]] = mcp

    available = list(mcp_map.values())

    if not available:
        print("  No MCP servers found. Install at least forensic-mcp first.")
        sys.exit(1)

    for mcp in available:
        marker = "venv" if "venv_path" in mcp else "system"
        print(f"  [OK] {mcp['name']} ({marker})")

    # Phase 2: Credentials
    print("\n[2/4] Configuring credentials...")
    opencti_config = None
    remnux_config = None

    has_opencti = any(m["name"] == "opencti-mcp" for m in available)
    if has_opencti:
        if non_interactive:
            print("  Skipping OpenCTI (non-interactive mode)")
        else:
            opencti_config = wizard_opencti()

    if not non_interactive:
        try:
            want_remnux = input("\nConfigure REMnux MCP (remote)? [y/N]: ").strip().lower()
        except EOFError:
            want_remnux = "n"
        if want_remnux == "y":
            remnux_config = wizard_remnux()

    # Phase 3: Client selection
    print("\n[3/4] Selecting AI clients...")
    if non_interactive:
        clients = ["claude_code"]
    else:
        clients = wizard_clients()

    # Phase 4: Generate configs
    print("\n[4/4] Generating configuration files...")

    for client_type in clients:
        if client_type == "claude_code":
            output = Path.cwd() / ".mcp.json"
            generate_mcp_json(available, output, opencti_config)
            print(f"  Generated: {output}")

        elif client_type == "claude_desktop":
            output = Path.home() / ".config" / "claude" / "claude_desktop_config.json"
            generate_desktop_config(available, output, opencti_config)
            print(f"  Generated: {output}")

        elif client_type == "openwebui":
            output = Path.cwd() / "gateway.yaml"
            generate_gateway_yaml(
                available, output, opencti_config, remnux_config,
            )
            print(f"  Generated: {output}")

    print("\nSetup complete.")
