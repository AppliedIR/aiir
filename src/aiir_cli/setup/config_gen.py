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
    remote_mcps: list[dict] | None = None,
) -> Path:
    """Generate .mcp.json for Claude Code.

    Args:
        mcps: List of detected MCP server dicts with name, python_path, module.
        output_path: Where to write the file.
        opencti_config: Optional OpenCTI credentials.
        remote_mcps: Optional remote MCP servers. Each dict has:
            name, url, type (http or streamable-http),
            optional headers dict (e.g., for bearer tokens).

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

    # Remote MCP servers (HTTP-based, no local install)
    for remote in remote_mcps or []:
        entry = {
            "type": remote.get("type", "http"),
            "url": remote["url"],
        }
        if remote.get("headers"):
            entry["headers"] = remote["headers"]
        servers[remote["name"]] = entry

    config = {"mcpServers": servers}
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise OSError(f"Failed to create directory {output_path.parent}: {e}") from e
    _write_600(output_path, json.dumps(config, indent=2))
    return output_path


def generate_gateway_yaml(
    mcps: list[dict],
    output_path: Path,
    opencti_config: dict | None = None,
    remnux_config: dict | None = None,
    api_keys: dict | None = None,
) -> Path:
    """Generate gateway.yaml for sift-gateway.

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

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise OSError(f"Failed to create directory {output_path.parent}: {e}") from e
    _write_600(output_path, yaml.dump(config, default_flow_style=False, sort_keys=False))
    return output_path


def _write_600(path: Path, content: str) -> None:
    """Write file with 0o600 permissions from creation — no world-readable window."""
    try:
        fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    except OSError as e:
        raise OSError(f"Failed to create temp file in {path.parent}: {e}") from e
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, str(path))
    except OSError as e:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise OSError(f"Failed to write config file {path}: {e}") from e
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
