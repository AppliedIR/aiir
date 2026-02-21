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


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def cmd_setup_client(args, identity: dict) -> None:
    """Generate LLM client configuration for AIIR endpoints."""
    auto = getattr(args, "yes", False)

    # 1. Resolve parameters from switches (or interactive wizard)
    client = _resolve_client(args, auto)
    sift_url = _resolve_sift(args, auto)
    windows_url = _resolve_windows(args, auto)
    remnux_url = _resolve_remnux(args, auto)
    examiner = _resolve_examiner(args, identity)
    include_zeltser = not getattr(args, "no_zeltser", False)

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

    if not servers:
        print("No endpoints configured — nothing to write.", file=sys.stderr)
        return

    # 3. Generate config for selected client
    _generate_config(client, servers, examiner)


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
        hint = f" (detected at {default})"
    else:
        hint = ""

    answer = _prompt(f"SIFT gateway URL{hint}", default)
    if answer.lower() == "skip":
        return ""
    return answer


def _resolve_windows(args, auto: bool) -> str:
    val = getattr(args, "windows", None)
    if val is not None:
        return _normalise_url(val, 4624) if val else ""
    if auto:
        return ""
    answer = _prompt("Windows endpoint (skip if none)", "skip")
    if answer.lower() == "skip":
        return ""
    return _normalise_url(answer, 4624)


def _resolve_remnux(args, auto: bool) -> str:
    val = getattr(args, "remnux", None)
    if val is not None:
        return _normalise_url(val, 3000) if val else ""
    if auto:
        return ""
    answer = _prompt("REMnux endpoint (skip if none)", "skip")
    if answer.lower() == "skip":
        return ""
    return _normalise_url(answer, 3000)


def _resolve_examiner(args, identity: dict) -> str:
    val = getattr(args, "examiner", None)
    if val:
        return val
    return identity.get("examiner", "unknown")


# ---------------------------------------------------------------------------
# Interactive wizard
# ---------------------------------------------------------------------------

def _wizard_client() -> str:
    print("\n=== AIIR Client Configuration ===\n")
    print("Which LLM client?")
    print("  1. Claude Code")
    print("  2. Claude Desktop")
    print("  3. Cursor")
    print("  4. Other / manual")

    choice = _prompt("Choose", "1")
    return {
        "1": "claude-code",
        "2": "claude-desktop",
        "3": "cursor",
    }.get(choice, "claude-code")


def _prompt(message: str, default: str = "") -> str:
    try:
        if default:
            answer = input(f"{message} [{default}]: ").strip()
            return answer or default
        return input(f"{message}: ").strip()
    except EOFError:
        return default


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
        except (json.JSONDecodeError, OSError):
            pass

    # Merge: existing servers are preserved, AIIR servers overwritten
    existing_servers = existing.get("mcpServers", {})
    existing_servers.update(config.get("mcpServers", {}))
    existing["mcpServers"] = existing_servers

    path.parent.mkdir(parents=True, exist_ok=True)
    _write_600(path, json.dumps(existing, indent=2) + "\n")


def _copy_agents_md(target: Path) -> None:
    """Copy AGENTS.md from forensic-mcp as the client instruction file."""
    # Search common locations for AGENTS.md
    candidates = [
        Path.cwd() / "AGENTS.md",
        Path.home() / "aiir" / "forensic-mcp" / "AGENTS.md",
    ]
    for src in candidates:
        if src.is_file():
            try:
                shutil.copy2(src, target)
                print(f"  Copied:    {src.name} → {target.name}")
            except OSError:
                pass
            return


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalise_url(raw: str, default_port: int) -> str:
    """Turn ``IP:port`` or bare ``IP`` into ``http://IP:port``."""
    raw = raw.strip()
    if not raw:
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
    except Exception:
        return False
