"""Open the case review dashboard in a browser."""

from __future__ import annotations

import sys
import webbrowser
from pathlib import Path

import yaml


def cmd_dashboard(args, identity: dict) -> None:
    """Open the case review dashboard."""
    config_path = Path.home() / ".aiir" / "gateway.yaml"
    if not config_path.is_file():
        print(
            "Error: Gateway config not found (~/.aiir/gateway.yaml).\n"
            "Run `aiir setup` to configure the gateway.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        config = yaml.safe_load(config_path.read_text()) or {}
    except (yaml.YAMLError, OSError) as e:
        print(f"Error: Cannot read gateway config: {e}", file=sys.stderr)
        sys.exit(1)

    gw = config.get("gateway", {})
    host = gw.get("host", "127.0.0.1")
    port = gw.get("port", 4508)
    tls = gw.get("tls", {})
    scheme = "https" if tls.get("certfile") else "http"

    if host == "0.0.0.0":
        host = "127.0.0.1"

    url = f"{scheme}://{host}:{port}/dashboard/"

    # Append bearer token matching current examiner
    api_keys = config.get("api_keys", {})
    if isinstance(api_keys, dict) and api_keys:
        examiner = identity.get("examiner", "")
        token = None
        for key, info in api_keys.items():
            if isinstance(info, dict) and info.get("examiner") == examiner:
                token = key
                break
        if token is None:
            token = next(iter(api_keys))
        url += f"#token={token}"

    print(f"Dashboard: {url}")
    try:
        webbrowser.open(url)
    except Exception:
        print("Could not open browser. Use the URL above.", file=sys.stderr)
