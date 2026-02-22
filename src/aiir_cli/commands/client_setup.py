"""Generate LLM client configuration pointing at AIIR API servers.

All entries use ``type: streamable-http`` — no stdio.  Runs on the
machine where the human sits; points at gateway / wintools / REMnux
endpoints wherever they are.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

from aiir_cli.setup.config_gen import _write_600

# ---------------------------------------------------------------------------
# External reference MCPs (optional, public, no auth)
# ---------------------------------------------------------------------------
_ZELTSER_MCP = {
    "name": "zeltser-ir-writing",
    "type": "streamable-http",
    "url": "https://website-mcp.zeltser.com/mcp",
}

_MSLEARN_MCP = {
    "name": "microsoft-learn",
    "type": "streamable-http",
    "url": "https://learn.microsoft.com/api/mcp",
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def cmd_setup_client(args, identity: dict) -> None:
    """Generate LLM client configuration for AIIR endpoints."""
    if getattr(args, "remote", False):
        _cmd_setup_client_remote(args, identity)
        return

    auto = getattr(args, "yes", False)

    # 1. Resolve parameters from switches (or interactive wizard)
    client = _resolve_client(args, auto)
    sift_url = _resolve_sift(args, auto)
    windows_url = _resolve_windows(args, auto)
    remnux_url = _resolve_remnux(args, auto)
    examiner = _resolve_examiner(args, identity)
    include_zeltser, include_mslearn = _resolve_internet_mcps(args, auto)

    # 2. Build endpoint list
    servers: dict[str, dict] = {}

    if sift_url:
        servers["aiir"] = {
            "type": "streamable-http",
            "url": _ensure_mcp_path(sift_url),
        }

    if windows_url:
        servers["wintools-mcp"] = {
            "type": "streamable-http",
            "url": _ensure_mcp_path(windows_url),
        }

    if remnux_url:
        servers["remnux-mcp"] = {
            "type": "streamable-http",
            "url": _ensure_mcp_path(remnux_url),
        }

    if include_zeltser:
        servers[_ZELTSER_MCP["name"]] = {
            "type": _ZELTSER_MCP["type"],
            "url": _ZELTSER_MCP["url"],
        }

    if include_mslearn:
        servers[_MSLEARN_MCP["name"]] = {
            "type": _MSLEARN_MCP["type"],
            "url": _MSLEARN_MCP["url"],
        }

    if not servers:
        print("No endpoints configured — nothing to write.", file=sys.stderr)
        return

    # 3. Generate config for selected client
    try:
        _generate_config(client, servers, examiner)
    except OSError as e:
        print(f"Failed to write client configuration: {e}", file=sys.stderr)
        sys.exit(1)

    # 4. Print internet MCP summary
    internet_mcps = []
    if include_zeltser:
        internet_mcps.append((_ZELTSER_MCP["name"], _ZELTSER_MCP["url"]))
    if include_mslearn:
        internet_mcps.append((_MSLEARN_MCP["name"], _MSLEARN_MCP["url"]))
    if internet_mcps:
        print("  Internet MCPs:")
        for name, url in internet_mcps:
            print(f"    {name:<25s}{url}")


# ---------------------------------------------------------------------------
# Parameter resolution
# ---------------------------------------------------------------------------

def _resolve_client(args, auto: bool) -> str:
    val = getattr(args, "client", None)
    if val:
        return val
    if auto:
        return "claude-code"
    return _wizard_client()


def _resolve_sift(args, auto: bool) -> str:
    val = getattr(args, "sift", None)
    if val is not None:
        return val  # explicit switch (even "" means "no sift")

    # Auto-detect local gateway
    default = "http://127.0.0.1:4508"
    if auto:
        return default

    detected = _probe_health(default)
    if detected:
        status = "detected running"
    else:
        status = "not detected, will use default"

    print("\n--- SIFT Workstation (Gateway) ---")
    print("The AIIR gateway runs on your SIFT workstation and provides")
    print("forensic tools (forensic-mcp, sift-mcp, forensic-rag, etc.).")
    print()
    print(f"  Default:  {default}  ({status})")
    print("  Format:   URL              Example: http://10.0.0.2:4508")
    print('  Enter "skip" to omit.')

    answer = _prompt("\nSIFT gateway URL", default)
    if answer.lower() == "skip":
        return ""
    return answer


def _resolve_windows(args, auto: bool) -> str:
    val = getattr(args, "windows", None)
    if val is not None:
        return _normalise_url(val, 4624) if val else ""
    if auto:
        return ""

    print("\n--- Windows Forensic Workstation ---")
    print("If you have a Windows workstation running wintools-mcp, enter its")
    print("IP address or hostname. The default port is 4624.")
    print()
    print("  Format:   IP or IP:PORT     Examples: 192.168.1.20, 10.0.0.5:4624")
    print("  Find it:  On the Windows box, run: ipconfig | findstr IPv4")

    answer = _prompt("\nWindows endpoint", "skip")
    if answer.lower() == "skip":
        return ""
    return _normalise_url(answer, 4624)


def _resolve_remnux(args, auto: bool) -> str:
    val = getattr(args, "remnux", None)
    if val is not None:
        return _normalise_url(val, 3000) if val else ""
    if auto:
        return ""

    print("\n--- REMnux Malware Analysis Workstation ---")
    print("If you have a REMnux VM running remnux-mcp, enter its IP address")
    print("or hostname. The default port is 3000.")
    print()
    print("  Format:   IP or IP:PORT     Examples: 192.168.1.30, 10.0.0.10:3000")
    print("  Find it:  On the REMnux box, run: ip addr show | grep inet")

    answer = _prompt("\nREMnux endpoint", "skip")
    if answer.lower() == "skip":
        return ""
    return _normalise_url(answer, 3000)


def _resolve_internet_mcps(args, auto: bool) -> tuple[bool, bool]:
    """Resolve which internet MCPs to include. Returns (zeltser, mslearn)."""
    no_zeltser = getattr(args, "no_zeltser", False)
    no_mslearn = getattr(args, "no_mslearn", False)

    if auto or (no_zeltser or no_mslearn):
        return (not no_zeltser, not no_mslearn)

    print("\n--- Internet MCPs (public, no auth required) ---")
    print("These connect your LLM client directly to public knowledge servers.")
    print()

    include_zeltser = _prompt_yn(
        "  Zeltser IR Writing   Helps write and improve IR reports",
        default=True,
    )
    include_mslearn = _prompt_yn(
        "  Microsoft Learn      Search Microsoft docs and code samples",
        default=True,
    )

    return (include_zeltser, include_mslearn)


def _resolve_examiner(args, identity: dict) -> str:
    val = getattr(args, "examiner", None)
    if val:
        return val
    return identity.get("examiner", "unknown")


# ---------------------------------------------------------------------------
# Interactive wizard
# ---------------------------------------------------------------------------

def _wizard_client() -> str:
    print("\n=== AIIR Client Configuration ===")
    print("Which LLM client will connect to your AIIR endpoints?\n")
    print("  1. Claude Code      CLI agent (writes .mcp.json + CLAUDE.md)")
    print("  2. Claude Desktop   Desktop app (writes claude_desktop_config.json)")
    print("  3. Cursor           IDE (writes .cursor/mcp.json + .cursorrules)")
    print("  4. LibreChat        Web UI (writes librechat_mcp.yaml)")
    print("  5. Other / manual   Raw JSON config for any MCP client")

    choice = _prompt("\nChoose", "1")
    return {
        "1": "claude-code",
        "2": "claude-desktop",
        "3": "cursor",
        "4": "librechat",
        "5": "other",
    }.get(choice, "other")


def _prompt(message: str, default: str = "") -> str:
    try:
        if default:
            answer = input(f"{message} [{default}]: ").strip()
            return answer or default
        return input(f"{message}: ").strip()
    except EOFError:
        return default


def _prompt_yn(message: str, default: bool = True) -> bool:
    """Prompt for a yes/no answer. Returns bool."""
    hint = "Y/n" if default else "y/N"
    try:
        answer = input(f"{message} [{hint}]: ").strip().lower()
    except EOFError:
        return default
    if not answer:
        return default
    return answer in ("y", "yes")


# ---------------------------------------------------------------------------
# Config generation
# ---------------------------------------------------------------------------

def _generate_config(client: str, servers: dict, examiner: str) -> None:
    config = {"mcpServers": servers}

    if client == "claude-code":
        output = Path.cwd() / ".mcp.json"
        _merge_and_write(output, config)
        _copy_agents_md(Path.cwd() / "CLAUDE.md")
        print(f"  Generated: {output}")
        print(f"  Examiner:  {examiner}")

    elif client == "claude-desktop":
        output = Path.home() / ".config" / "claude" / "claude_desktop_config.json"
        _merge_and_write(output, config)
        print(f"  Generated: {output}")

    elif client == "cursor":
        output = Path.cwd() / ".cursor" / "mcp.json"
        _merge_and_write(output, config)
        _copy_agents_md(Path.cwd() / ".cursorrules")
        print(f"  Generated: {output}")

    elif client == "librechat":
        output = Path.cwd() / "librechat_mcp.yaml"
        _write_librechat_yaml(output, servers)
        print(f"  Generated: {output}")
        print("  Merge into your librechat.yaml under the mcpServers key.")

    else:
        # Manual / other — just dump JSON
        output = Path.cwd() / "aiir-mcp-config.json"
        _merge_and_write(output, config)
        print(f"  Generated: {output}")


def _merge_and_write(path: Path, config: dict) -> None:
    """Write config, merging with existing file if present."""
    existing = {}
    if path.is_file():
        try:
            existing = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            print(f"Warning: existing config {path} has invalid JSON ({e}), overwriting.", file=sys.stderr)
        except OSError as e:
            print(f"Warning: could not read existing config {path}: {e}", file=sys.stderr)

    # Merge: existing servers are preserved, AIIR servers overwritten
    existing_servers = existing.get("mcpServers", {})
    existing_servers.update(config.get("mcpServers", {}))
    existing["mcpServers"] = existing_servers

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"Failed to create directory {path.parent}: {e}", file=sys.stderr)
        raise
    _write_600(path, json.dumps(existing, indent=2) + "\n")


def _write_librechat_yaml(path: Path, servers: dict) -> None:
    """Write LibreChat mcpServers YAML snippet."""
    lines = ["# AIIR MCP servers — merge into your librechat.yaml", "mcpServers:"]
    for name, info in servers.items():
        lines.append(f"  {name}:")
        lines.append(f"    type: \"{info['type']}\"")
        lines.append(f"    url: \"{info['url']}\"")
        lines.append("    timeout: 60000")
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_600(path, "\n".join(lines) + "\n")


def _copy_agents_md(target: Path) -> None:
    """Copy AGENTS.md from sift-mcp monorepo as the client instruction file."""
    # Search common locations for AGENTS.md
    candidates = [
        Path.cwd() / "AGENTS.md",
        Path.home() / "aiir" / "sift-mcp" / "AGENTS.md",
        Path.home() / "aiir" / "forensic-mcp" / "AGENTS.md",
        Path("/opt/aiir/sift-mcp") / "AGENTS.md",
        Path("/opt/aiir") / "AGENTS.md",
    ]
    for src in candidates:
        if src.is_file():
            try:
                shutil.copy2(src, target)
                print(f"  Copied:    {src.name} → {target.name}")
            except OSError as e:
                print(f"  Warning: failed to copy {src} to {target}: {e}", file=sys.stderr)
            return
    print("  Warning: AGENTS.md not found. Copy it manually from the sift-mcp repo.")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalise_url(raw: str, default_port: int) -> str:
    """Turn ``IP:port`` or bare ``IP`` into ``http://IP:port``."""
    raw = raw.strip()
    if not raw:
        return ""
    # Reject obviously invalid input
    if any(c in raw for c in (" ", "\t", "\n", "<", ">", '"', "'")):
        print(f"Warning: invalid characters in URL input: {raw!r}", file=sys.stderr)
        return ""
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw
    if ":" not in raw:
        raw = f"{raw}:{default_port}"
    return f"http://{raw}"


def _ensure_mcp_path(url: str) -> str:
    """Ensure URL ends with /mcp."""
    url = url.rstrip("/")
    if not url.endswith("/mcp"):
        url += "/mcp"
    return url


def _probe_health(base_url: str) -> bool:
    """Try to reach a /health endpoint."""
    try:
        import urllib.request
        url = f"{base_url.rstrip('/')}/health"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=2) as resp:
            return resp.status == 200
    except OSError as e:
        # Network/connection errors (includes URLError, socket.error)
        import logging
        logging.debug("Health probe failed for %s: %s", base_url, e)
        return False
    except Exception as e:
        import logging
        logging.debug("Health probe unexpected error for %s: %s", base_url, e)
        return False


# ---------------------------------------------------------------------------
# Remote setup mode
# ---------------------------------------------------------------------------

def _cmd_setup_client_remote(args, identity: dict) -> None:
    """Generate client config pointing at a remote AIIR gateway.

    Discovers running backends via the service management API, then builds
    per-backend MCP endpoint entries with bearer token auth.
    """
    import yaml

    auto = getattr(args, "yes", False)
    client = _resolve_client(args, auto)
    examiner = _resolve_examiner(args, identity)

    # 1. Resolve gateway URL
    gateway_url = getattr(args, "sift", None)
    if not gateway_url:
        if auto:
            print("ERROR: --sift is required with --remote -y", file=sys.stderr)
            sys.exit(1)
        gateway_url = _prompt("Gateway URL (e.g., https://sift.example.com:4508)", "")
    if not gateway_url:
        print("ERROR: Gateway URL is required for remote setup.", file=sys.stderr)
        sys.exit(1)
    gateway_url = gateway_url.rstrip("/")

    # 2. Resolve bearer token
    token = getattr(args, "token", None)
    if not token:
        if auto:
            print("ERROR: --token is required with --remote -y", file=sys.stderr)
            sys.exit(1)
        token = _prompt("Bearer token", "")

    # 3. Test connectivity
    print(f"\nConnecting to {gateway_url} ...")
    health = _probe_health_with_auth(gateway_url, token)
    if health is None:
        print(f"ERROR: Cannot reach gateway at {gateway_url}", file=sys.stderr)
        sys.exit(1)
    print(f"  Gateway status: {health.get('status', 'unknown')}")

    # 4. Discover backends via service management API
    services = _discover_services(gateway_url, token)
    if services is None:
        print("ERROR: Failed to discover services from gateway.", file=sys.stderr)
        sys.exit(1)

    running = [s for s in services if s.get("started")]
    if not running:
        print("WARNING: No running backends found on gateway.", file=sys.stderr)

    print(f"  Backends: {len(running)} running")
    for s in running:
        print(f"    {s['name']}")

    # 5. Build endpoint entries
    servers: dict[str, dict] = {}

    # Aggregate endpoint
    servers["aiir"] = _format_server_entry(
        client, f"{gateway_url}/mcp", token,
    )

    # Per-backend endpoints
    for s in running:
        name = s["name"]
        servers[name] = _format_server_entry(
            client, f"{gateway_url}/mcp/{name}", token,
        )

    # 6. Windows / internet MCPs (same as local)
    windows_url = _resolve_windows(args, auto)
    if windows_url:
        servers["wintools-mcp"] = {
            "type": "streamable-http",
            "url": _ensure_mcp_path(windows_url),
        }

    include_zeltser, include_mslearn = _resolve_internet_mcps(args, auto)
    if include_zeltser:
        servers[_ZELTSER_MCP["name"]] = {
            "type": _ZELTSER_MCP["type"],
            "url": _ZELTSER_MCP["url"],
        }
    if include_mslearn:
        servers[_MSLEARN_MCP["name"]] = {
            "type": _MSLEARN_MCP["type"],
            "url": _MSLEARN_MCP["url"],
        }

    if not servers:
        print("No endpoints configured — nothing to write.", file=sys.stderr)
        return

    # 7. Generate config
    try:
        _generate_config(client, servers, examiner)
    except OSError as e:
        print(f"Failed to write client configuration: {e}", file=sys.stderr)
        sys.exit(1)

    # 8. Save gateway config for `aiir service` commands
    _save_gateway_config(gateway_url, token)

    print(f"\n  Remote setup complete. Examiner: {examiner}")


def _format_server_entry(client: str, url: str, token: str | None) -> dict:
    """Format a server entry appropriate for the target client.

    Claude Desktop needs mcp-remote bridge (npx subprocess) because it
    doesn't support streamable-http natively. Other clients use native
    streamable-http with Authorization header.
    """
    if client == "claude-desktop" and token:
        return {
            "command": "npx",
            "args": ["-y", "mcp-remote", url,
                     "--header", "Authorization:${AUTH_HEADER}"],
            "env": {"AUTH_HEADER": f"Bearer {token}"},
        }

    entry: dict = {
        "type": "streamable-http",
        "url": url,
    }
    if token:
        entry["headers"] = {"Authorization": f"Bearer {token}"}
    return entry


def _probe_health_with_auth(base_url: str, token: str | None) -> dict | None:
    """Probe /health with optional bearer token. Returns parsed dict or None."""
    import urllib.request

    try:
        url = f"{base_url.rstrip('/')}/health"
        req = urllib.request.Request(url, method="GET")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                import json as _json
                return _json.loads(resp.read())
    except OSError:
        pass
    except Exception:
        pass
    return None


def _discover_services(base_url: str, token: str | None) -> list | None:
    """GET /api/v1/services and return the services list, or None on failure."""
    import urllib.request

    try:
        url = f"{base_url.rstrip('/')}/api/v1/services"
        req = urllib.request.Request(url, method="GET")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                import json as _json
                data = _json.loads(resp.read())
                return data.get("services", [])
    except OSError:
        pass
    except Exception:
        pass
    return None


def _save_gateway_config(url: str, token: str | None) -> None:
    """Save gateway URL and token to ~/.aiir/config.yaml."""
    import yaml

    config_dir = Path.home() / ".aiir"
    config_file = config_dir / "config.yaml"

    existing = {}
    if config_file.is_file():
        try:
            existing = yaml.safe_load(config_file.read_text()) or {}
        except Exception:
            pass

    existing["gateway_url"] = url
    if token:
        existing["gateway_token"] = token

    try:
        config_dir.mkdir(parents=True, exist_ok=True)
        config_file.write_text(yaml.dump(existing, default_flow_style=False))
    except OSError as e:
        print(f"Warning: could not save gateway config: {e}", file=sys.stderr)
