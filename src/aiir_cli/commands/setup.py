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

from aiir_cli.setup.config_gen import (
    generate_gateway_yaml,
    generate_mcp_json,
)
from aiir_cli.setup.detect import detect_installed_mcps, detect_venv_mcps
from aiir_cli.setup.wizard import (
    wizard_clients,
    wizard_opencti,
    wizard_remnux,
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

    if action == "join-code":
        from aiir_cli.commands.join import cmd_setup_join_code

        cmd_setup_join_code(args, identity)
        return

    print(
        "WARNING: 'aiir setup' is deprecated. Use 'aiir setup client' instead.",
        file=sys.stderr,
    )

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
            want_remnux = (
                input("\nConfigure REMnux MCP (remote)? [y/N]: ").strip().lower()
            )
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
                available,
                output,
                opencti_config,
                remnux_config,
            )
            print(f"  Generated: {output}")

    print("\nSetup complete.")


def _run_connectivity_test() -> None:
    """Test connectivity to the gateway and all MCP backends."""
    import json
    import time
    import urllib.error
    import urllib.request

    print("=" * 60)
    print("  AIIR Connectivity Test")
    print("=" * 60)

    # Resolve gateway URL
    gateway_url = "http://127.0.0.1:4508"
    config_path = Path.home() / ".aiir" / "gateway.yaml"
    if config_path.is_file():
        try:
            import yaml

            config = yaml.safe_load(config_path.read_text()) or {}
            host = config.get("host", "127.0.0.1")
            port = config.get("port", 4508)
            scheme = "https" if config.get("tls", {}).get("enabled") else "http"
            gateway_url = f"{scheme}://{host}:{port}"
        except Exception:
            pass

    health_url = f"{gateway_url}/health"
    print(f"\n  Gateway: {gateway_url}")

    # Fetch health with one retry for startup delay
    data = None
    for attempt in range(2):
        try:
            req = urllib.request.Request(health_url)
            start = time.time()
            with urllib.request.urlopen(req, timeout=15) as resp:
                elapsed = (time.time() - start) * 1000
                data = json.loads(resp.read())
            break
        except urllib.error.URLError:
            if attempt == 0:
                print("  Gateway not responding, retrying in 3s...")
                time.sleep(3)
            else:
                print("  Gateway: OFFLINE — is the gateway running?")
                print("    Start with: aiir service start")
                return
        except Exception as e:
            print(f"  Gateway: ERROR ({e})")
            return

    status = data.get("status", "unknown")
    tools_count = data.get("tools_count", 0)
    print(f"  Status: {status} ({tools_count} tools, {elapsed:.0f}ms)")

    backends = data.get("backends", {})
    if not backends:
        print("\n  No backends configured.")
        return

    ok_count = 0
    fail_count = 0

    print()
    for name, health in sorted(backends.items()):
        bstatus = health.get("status", "unknown")
        if bstatus == "ok":
            tools = health.get("tools", "?")
            print(f"  {name:25s} OK ({tools} tools)")
            ok_count += 1
        else:
            err = health.get("error", "unknown error")
            print(f"  {name:25s} FAIL ({err})")
            fail_count += 1

    print(f"\n{ok_count} of {ok_count + fail_count} backends operational.", end="")
    if fail_count:
        print(f" {fail_count} failed.")
    else:
        print()
