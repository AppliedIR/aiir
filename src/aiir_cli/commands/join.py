"""aiir join — exchange a join code for gateway credentials from a remote machine."""

from __future__ import annotations

import json
import os
import socket
import sys
from pathlib import Path

import yaml


def cmd_join(args, identity: dict) -> None:
    """Join a SIFT gateway from a remote machine."""
    sift_url = args.sift
    code = args.code

    # Normalize URL
    if not sift_url.startswith("http"):
        sift_url = f"https://{sift_url}"
    # Add default port if not present
    parts = sift_url.split("//", 1)
    if len(parts) == 2 and ":" not in parts[1]:
        sift_url = f"{sift_url}:4508"

    # Detect if this is a wintools machine
    wintools_url = None
    wintools_token = None
    if getattr(args, "wintools", False) or _detect_wintools():
        wintools_url, wintools_token = _get_wintools_credentials()

    # TLS verification: use CA cert if available, otherwise skip (self-signed)
    ca_cert = getattr(args, "ca_cert", None) or _find_ca_cert()
    verify = ca_cert if ca_cert else False

    # POST to /api/v1/setup/join
    try:
        import requests
    except ImportError:
        # Fall back to urllib if requests is not available
        _join_urllib(sift_url, code, wintools_url, wintools_token, verify, args)
        return

    try:
        resp = requests.post(
            f"{sift_url}/api/v1/setup/join",
            json={
                "code": code,
                "machine_type": "wintools" if wintools_url else "examiner",
                "hostname": socket.gethostname(),
                "wintools_url": wintools_url,
                "wintools_token": wintools_token,
            },
            verify=verify,
            timeout=30,
        )
    except requests.exceptions.ConnectionError as e:
        print(f"Connection failed: {e}", file=sys.stderr)
        print(f"Verify that the gateway is running at {sift_url}", file=sys.stderr)
        sys.exit(1)
    except requests.exceptions.SSLError as e:
        print(f"TLS error: {e}", file=sys.stderr)
        print("Try --ca-cert to specify the CA certificate, or check the gateway's TLS config", file=sys.stderr)
        sys.exit(1)

    if resp.status_code != 200:
        try:
            error_msg = resp.json().get("error", "Unknown error")
        except (json.JSONDecodeError, ValueError):
            error_msg = resp.text
        print(f"Join failed: {error_msg}", file=sys.stderr)
        sys.exit(1)

    data = resp.json()
    _write_config(data["gateway_url"], data["gateway_token"])

    print(f"Joined gateway at {data['gateway_url']}")
    print(f"Backends available: {', '.join(data.get('backends', []))}")

    if data.get("wintools_registered"):
        print("Windows wintools-mcp registered with gateway")
        if data.get("restart_required"):
            print("Note: gateway restart may be needed to activate the wintools backend")

    # Run aiir setup client to generate MCP config
    if not getattr(args, "skip_setup", False):
        print()
        print("Run 'aiir setup client --remote' to configure your LLM client.")


def cmd_setup_join_code(args, identity: dict) -> None:
    """Generate a join code on this SIFT machine."""
    gateway_url = _get_local_gateway_url()
    token = _get_local_gateway_token()

    if not token:
        print("No gateway token found. Is the gateway configured?", file=sys.stderr)
        print("Check ~/.aiir/gateway.yaml for api_keys", file=sys.stderr)
        sys.exit(1)

    try:
        import requests
    except ImportError:
        _join_code_urllib(gateway_url, token, args)
        return

    expires = getattr(args, "expires", None) or 2
    try:
        resp = requests.post(
            f"{gateway_url}/api/v1/setup/join-code",
            headers={"Authorization": f"Bearer {token}"},
            json={"expires_hours": expires},
            verify=False,
            timeout=10,
        )
    except requests.exceptions.ConnectionError as e:
        print(f"Failed to connect to local gateway: {e}", file=sys.stderr)
        print(f"Is the gateway running at {gateway_url}?", file=sys.stderr)
        sys.exit(1)

    if resp.status_code != 200:
        print(f"Failed to generate join code: {resp.text}", file=sys.stderr)
        sys.exit(1)

    data = resp.json()
    print(f"Join code: {data['code']} (expires in {data['expires_hours']} hours)")
    print()
    print("On the remote machine, run:")
    print(f"  {data['instructions']}")


def _join_urllib(sift_url, code, wintools_url, wintools_token, verify, args):
    """Fallback join implementation using urllib (no requests dependency)."""
    import ssl
    import urllib.request

    payload = json.dumps({
        "code": code,
        "machine_type": "wintools" if wintools_url else "examiner",
        "hostname": socket.gethostname(),
        "wintools_url": wintools_url,
        "wintools_token": wintools_token,
    }).encode("utf-8")

    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif isinstance(verify, str):
        ctx.load_verify_locations(verify)

    req = urllib.request.Request(
        f"{sift_url}/api/v1/setup/join",
        data=payload,
        headers={"Content-Type": "application/json"},
    )

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            error_msg = json.loads(body).get("error", body)
        except (json.JSONDecodeError, ValueError):
            error_msg = body
        print(f"Join failed: {error_msg}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"Connection failed: {e}", file=sys.stderr)
        sys.exit(1)

    _write_config(data["gateway_url"], data["gateway_token"])
    print(f"Joined gateway at {data['gateway_url']}")
    print(f"Backends available: {', '.join(data.get('backends', []))}")

    if not getattr(args, "skip_setup", False):
        print()
        print("Run 'aiir setup client --remote' to configure your LLM client.")


def _join_code_urllib(gateway_url, token, args):
    """Fallback join-code implementation using urllib."""
    import ssl
    import urllib.request

    expires = getattr(args, "expires", None) or 2
    payload = json.dumps({"expires_hours": expires}).encode("utf-8")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        f"{gateway_url}/api/v1/setup/join-code",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            data = json.loads(resp.read())
    except (urllib.error.HTTPError, urllib.error.URLError) as e:
        print(f"Failed to generate join code: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Join code: {data['code']} (expires in {data['expires_hours']} hours)")
    print()
    print("On the remote machine, run:")
    print(f"  {data['instructions']}")


def _write_config(gateway_url: str, gateway_token: str) -> None:
    """Write gateway credentials to ~/.aiir/config.yaml."""
    config_dir = Path.home() / ".aiir"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "config.yaml"

    # Load existing config to preserve other fields
    config = {}
    if config_path.exists():
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}
        except (yaml.YAMLError, OSError):
            pass

    config["gateway_url"] = gateway_url
    config["gateway_token"] = gateway_token

    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False)


def _get_local_gateway_url() -> str:
    """Get the local gateway URL from config or default."""
    config_path = Path.home() / ".aiir" / "config.yaml"
    if config_path.exists():
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}
            url = config.get("gateway_url")
            if url:
                return url
        except (yaml.YAMLError, OSError):
            pass
    return "http://127.0.0.1:4508"


def _get_local_gateway_token() -> str | None:
    """Get the first API key from the local gateway config."""
    # Try gateway.yaml first
    for config_name in ("gateway.yaml", "config.yaml"):
        config_path = Path.home() / ".aiir" / config_name
        if config_path.exists():
            try:
                with open(config_path) as f:
                    config = yaml.safe_load(f) or {}
                # Check for api_keys dict
                api_keys = config.get("api_keys", {})
                if api_keys:
                    return next(iter(api_keys))
                # Check for gateway_token
                token = config.get("gateway_token")
                if token:
                    return token
            except (yaml.YAMLError, OSError):
                continue
    return None


def _detect_wintools() -> bool:
    """Detect if wintools-mcp is running on this machine."""
    # Check for wintools config or running process
    wintools_config = Path.home() / ".aiir" / "wintools.yaml"
    return wintools_config.exists()


def _get_wintools_credentials() -> tuple[str | None, str | None]:
    """Get wintools URL and token if available."""
    wintools_config = Path.home() / ".aiir" / "wintools.yaml"
    if wintools_config.exists():
        try:
            with open(wintools_config) as f:
                config = yaml.safe_load(f) or {}
            url = config.get("url", "http://127.0.0.1:4624/mcp")
            token = config.get("token")
            return url, token
        except (yaml.YAMLError, OSError):
            pass
    return None, None


def _find_ca_cert() -> str | None:
    """Find CA certificate for TLS verification."""
    ca_path = Path.home() / ".aiir" / "tls" / "ca-cert.pem"
    if ca_path.exists():
        return str(ca_path)
    return None
