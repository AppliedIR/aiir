"""Detect installed MCP servers."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

# Known MCP server modules and their pip package names
MCP_SERVERS = {
    "forensic-mcp": {"module": "forensic_mcp", "type": "stdio"},
    "sift-mcp": {"module": "sift_mcp", "type": "stdio"},
    "forensic-rag-mcp": {"module": "rag_mcp", "type": "stdio"},
    "windows-triage-mcp": {"module": "windows_triage", "type": "stdio"},
    "opencti-mcp": {"module": "opencti_mcp", "type": "stdio"},
}

REMOTE_SERVERS = {
    "remnux-mcp": {"type": "http", "default_port": 8080},
    "microsoft-learn": {
        "type": "http",
        "default_url": "https://learn.microsoft.com/api/mcp",
    },
    "zeltser-ir-writing": {"type": "http", "default_url": "https://zeltser.com/mcp"},
}


def detect_installed_mcps() -> list[dict]:
    """Detect locally installed MCP servers by checking if their modules are importable.

    Returns a list of dicts with name, module, type, python_path, available.
    """
    results = []
    python_path = shutil.which("python3") or shutil.which("python") or "python"

    for name, info in MCP_SERVERS.items():
        module = info["module"]
        available = _check_module(python_path, module)
        results.append(
            {
                "name": name,
                "module": module,
                "type": info["type"],
                "python_path": python_path,
                "available": available,
            }
        )

    return results


def _check_module(python_path: str, module: str) -> bool:
    """Check if a Python module is importable."""
    try:
        result = subprocess.run(
            [python_path, "-c", f"import {module}"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        import logging

        logging.debug("Module check timed out: %s (via %s)", module, python_path)
        return False
    except FileNotFoundError:
        import logging

        logging.debug("Python not found at %s when checking %s", python_path, module)
        return False
    except OSError as e:
        import logging

        logging.debug("OS error checking module %s via %s: %s", module, python_path, e)
        return False


def detect_venv_mcps(search_dirs: list[Path] | None = None) -> list[dict]:
    """Search for MCP servers installed in venvs under common directories.

    Checks (in priority order):
    1. Shared venv at ``<base_dir>/.venv/`` (direct monorepo root)
    2. Monorepo venv at ``<base_dir>/sift-mcp/.venv/`` (setup-sift.sh default)
    3. Per-repo venvs at ``<base_dir>/<name>/.venv/`` (legacy layout)

    Returns list of dicts with name, venv_path, python_path, available.
    """
    if search_dirs is None:
        search_dirs = []
        # Check manifest.json for custom venv path
        manifest_path = Path.home() / ".aiir" / "manifest.json"
        if manifest_path.is_file():
            try:
                import json

                manifest = json.loads(manifest_path.read_text())
                venv_path = manifest.get("venv")
                if venv_path:
                    venv_parent = Path(venv_path).parent
                    if venv_parent not in search_dirs:
                        search_dirs.append(venv_parent)
            except Exception:
                pass
        search_dirs.extend(
            [
                Path.home() / ".aiir",
                Path("/opt/aiir"),
                Path.home() / "air-design",
                Path.home() / "aiir",
            ]
        )

    results = []
    for base_dir in search_dirs:
        if not base_dir.exists():
            continue

        # Check for a shared venv (all MCPs installed in one place)
        shared_python = None
        shared_path = None
        for candidate in [
            base_dir / "venv" / "bin" / "python",  # ~/.aiir/venv/ (new installer)
            base_dir / ".venv" / "bin" / "python",  # direct monorepo root
            base_dir
            / "sift-mcp"
            / ".venv"
            / "bin"
            / "python",  # ~/aiir/sift-mcp/.venv/
        ]:
            if candidate.exists():
                shared_python = candidate
                shared_path = candidate.parent.parent
                break

        if shared_python:
            for name, info in MCP_SERVERS.items():
                available = _check_module(str(shared_python), info["module"])
                if available:
                    results.append(
                        {
                            "name": name,
                            "venv_path": str(shared_path),
                            "python_path": str(shared_python),
                            "available": True,
                        }
                    )
            continue

        # Fallback: per-repo venvs (legacy layout)
        for name, info in MCP_SERVERS.items():
            venv_python = base_dir / name / ".venv" / "bin" / "python"
            if venv_python.exists():
                available = _check_module(str(venv_python), info["module"])
                results.append(
                    {
                        "name": name,
                        "venv_path": str(base_dir / name),
                        "python_path": str(venv_python),
                        "available": available,
                    }
                )

    return results
