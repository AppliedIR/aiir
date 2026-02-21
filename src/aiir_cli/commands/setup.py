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
)
from aiir_cli.setup.config_gen import (
    generate_mcp_json,
    generate_gateway_yaml,
)


def cmd_setup(args, identity: dict) -> None:
    """Run interactive setup or connectivity test."""
    action = getattr(args, "setup_action", None)

    if action == "test":
        _run_connectivity_test()
        return

    if action == "client":
        from aiir_cli.commands.client_setup import cmd_setup_client
        cmd_setup_client(args, identity)
        return

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
            generate_mcp_json(available, output, opencti_config)
            print(f"  Generated: {output}")

        elif client_type == "cursor":
            output = Path.cwd() / ".cursor" / "mcp.json"
            generate_mcp_json(available, output, opencti_config)
            print(f"  Generated: {output}")

        elif client_type == "openwebui":
            output = Path.cwd() / "gateway.yaml"
            generate_gateway_yaml(
                available, output, opencti_config, remnux_config,
            )
            print(f"  Generated: {output}")

    print("\nSetup complete.")


def _run_connectivity_test() -> None:
    """Test connectivity to all detected MCP servers."""
    import subprocess
    import time

    print("=" * 60)
    print("  AIIR Connectivity Test")
    print("=" * 60)

    mcps = detect_installed_mcps()
    venv_mcps = detect_venv_mcps()

    # Merge
    mcp_map: dict[str, dict] = {}
    for mcp in mcps:
        mcp_map[mcp["name"]] = mcp
    for mcp in venv_mcps:
        if mcp["available"]:
            mcp_map[mcp["name"]] = mcp

    if not mcp_map:
        print("\nNo MCP servers detected.")
        return

    ok_count = 0
    fail_count = 0

    # Track which python paths we've tested FK on (avoid duplicate checks)
    fk_checked: set[str] = set()

    for name, info in sorted(mcp_map.items()):
        python_path = info.get("python_path", "python")
        module = info.get("module", "")
        available = info.get("available", False)

        if not available:
            print(f"  {name:25s} NOT INSTALLED")
            fail_count += 1
            continue

        # Try importing and creating server
        start = time.time()
        try:
            result = subprocess.run(
                [python_path, "-c", f"import {module}; print('ok')"],
                capture_output=True, timeout=15, text=True,
            )
            elapsed = (time.time() - start) * 1000
            if result.returncode == 0:
                print(f"  {name:25s} OK ({elapsed:.0f}ms)")
                ok_count += 1
            else:
                err = result.stderr.strip().split("\n")[-1] if result.stderr else "unknown error"
                print(f"  {name:25s} FAIL ({err})")
                fail_count += 1
        except subprocess.TimeoutExpired:
            print(f"  {name:25s} TIMEOUT (import took >15s)")
            fail_count += 1
        except FileNotFoundError:
            print(f"  {name:25s} ERROR (Python not found at {python_path})")
            fail_count += 1
        except OSError as e:
            print(f"  {name:25s} ERROR (OS error: {e})")
            fail_count += 1

        # FK availability check for MCPs that use it
        if module in ("forensic_mcp", "sift_mcp") and python_path not in fk_checked:
            fk_checked.add(python_path)
            try:
                fk_result = subprocess.run(
                    [python_path, "-c",
                     "import forensic_knowledge; print(len(forensic_knowledge.loader.list_tools()))"],
                    capture_output=True, timeout=15, text=True,
                )
                if fk_result.returncode == 0:
                    tool_count = fk_result.stdout.strip()
                    print(f"  {'forensic-knowledge':25s} {tool_count} tools loaded")
                else:
                    print(f"  {'forensic-knowledge':25s} WARNING: not available in this venv")
            except subprocess.TimeoutExpired:
                print(f"  {'forensic-knowledge':25s} WARNING: import timed out")
            except OSError as e:
                print(f"  {'forensic-knowledge':25s} WARNING: check failed ({e})")

    print(f"\n{ok_count} of {ok_count + fail_count} MCPs operational.", end="")
    if fail_count:
        print(f" {fail_count} failed.")
    else:
        print()
