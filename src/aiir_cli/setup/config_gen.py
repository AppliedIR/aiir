"""Generate configuration files for different AI clients."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path

import yaml


def generate_mcp_json(
    mcps: list[dict],
    output_path: Path,
    opencti_config: dict | None = None,
) -> Path:
    """Generate .mcp.json for Claude Code.

    Args:
        mcps: List of detected MCP server dicts with name, python_path, module.
        output_path: Where to write the file.
        opencti_config: Optional OpenCTI credentials.

    Returns:
        Path to the generated file.
    """
    servers = {}
    for mcp in mcps:
        name = mcp["name"]
        entry = {
            "command": mcp["python_path"],
            "args": ["-m", mcp["module"]],
        }
        # Add OpenCTI env vars
        if name == "opencti-mcp" and opencti_config:
            entry["env"] = {
                "OPENCTI_URL": opencti_config["url"],
                "OPENCTI_TOKEN": opencti_config["token"],
            }
            if not opencti_config.get("ssl_verify", True):
                entry["env"]["OPENCTI_SSL_VERIFY"] = "false"

        servers[name] = entry

    config = {"mcpServers": servers}
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _write_600(output_path, json.dumps(config, indent=2))
    return output_path


def generate_gateway_yaml(
    mcps: list[dict],
    output_path: Path,
    opencti_config: dict | None = None,
    remnux_config: dict | None = None,
    api_keys: dict | None = None,
) -> Path:
    """Generate gateway.yaml for aiir-gateway.

    Args:
        mcps: List of detected MCP server dicts.
        output_path: Where to write the file.
        opencti_config: Optional OpenCTI credentials.
        remnux_config: Optional REMnux MCP config.
        api_keys: Optional API key → analyst mapping.

    Returns:
        Path to the generated file.
    """
    config: dict = {
        "gateway": {
            "host": "127.0.0.1",
            "port": 4508,
            "log_level": "INFO",
        },
        "backends": {},
    }

    if api_keys:
        config["api_keys"] = api_keys

    # Local stdio backends
    for mcp in mcps:
        name = mcp["name"]
        backend = {
            "type": "stdio",
            "command": mcp["python_path"],
            "args": ["-m", mcp["module"]],
            "enabled": True,
        }
        if name == "opencti-mcp" and opencti_config:
            backend["env"] = {
                "OPENCTI_URL": opencti_config["url"],
                "OPENCTI_TOKEN": opencti_config["token"],
            }
        config["backends"][name] = backend

    # Remote HTTP backends
    if remnux_config and remnux_config.get("host"):
        config["backends"]["remnux-mcp"] = {
            "type": "http",
            "url": f"http://{remnux_config['host']}:{remnux_config.get('port', 8080)}/mcp",
            "enabled": True,
        }
        if remnux_config.get("token"):
            config["backends"]["remnux-mcp"]["headers"] = {
                "Authorization": f"Bearer {remnux_config['token']}"
            }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    _write_600(output_path, yaml.dump(config, default_flow_style=False, sort_keys=False))
    return output_path


def _write_600(path: Path, content: str) -> None:
    """Write file with 0o600 permissions from creation — no world-readable window."""
    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.replace(tmp_path, str(path))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
