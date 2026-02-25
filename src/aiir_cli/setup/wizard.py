"""Interactive setup wizards for credentials and client selection."""

from __future__ import annotations

import getpass


def wizard_opencti() -> dict:
    """Prompt for OpenCTI configuration via /dev/tty."""
    print("\n--- OpenCTI Configuration ---")
    print("OpenCTI requires a server URL and API token.")

    url = _prompt("OpenCTI URL (e.g., https://opencti.example.com): ")
    token = _prompt_secret("OpenCTI API Token: ")
    ssl_verify = _prompt("Verify SSL? [Y/n]: ").strip().lower() != "n"

    return {
        "url": url,
        "token": token,
        "ssl_verify": ssl_verify,
    }


def wizard_remnux() -> dict:
    """Prompt for REMnux MCP configuration."""
    print("\n--- REMnux MCP Configuration ---")
    print("REMnux MCP is a remote HTTP server.")

    host = _prompt("REMnux host (e.g., 192.168.1.100): ")
    port = _prompt("REMnux port [8080]: ").strip() or "8080"
    token = _prompt_secret("Bearer token (leave empty if none): ")

    return {
        "host": host,
        "port": int(port),
        "token": token,
    }


def wizard_clients() -> list[str]:
    """Ask which AI clients to configure."""
    print("\n--- Client Configuration ---")
    print("Which AI clients should be configured?")
    print("  1. Claude Code (.mcp.json)")
    print("  2. Claude Desktop (claude_desktop_config.json)")
    print("  3. Cursor (.cursor/mcp.json)")
    print("  4. OpenWebUI / gateway (gateway.yaml)")
    print("  5. All of the above")

    choice = _prompt("Choose [1-5]: ").strip()

    if choice == "5":
        return ["claude_code", "claude_desktop", "cursor", "openwebui"]
    clients = []
    if "1" in choice:
        clients.append("claude_code")
    if "2" in choice:
        clients.append("claude_desktop")
    if "3" in choice:
        clients.append("cursor")
    if "4" in choice:
        clients.append("openwebui")
    return clients or ["claude_code"]


def _prompt(message: str) -> str:
    """Prompt via stdin."""
    try:
        return input(message)
    except EOFError:
        return ""


def _prompt_secret(message: str) -> str:
    """Prompt for a secret value (no echo)."""
    try:
        return getpass.getpass(message)
    except EOFError:
        return ""
