"""Shared case file I/O for CLI commands.

This module reads/writes the same files as forensic-mcp,
ensuring the CLI and MCP server share a common data format.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


def get_case_dir(case_id: str | None = None) -> Path:
    """Resolve the active case directory."""
    if case_id:
        cases_dir = Path(os.environ.get("AIR_CASES_DIR", "cases"))
        case_dir = cases_dir / case_id
        if not case_dir.exists():
            print(f"Case not found: {case_id}", file=sys.stderr)
            sys.exit(1)
        return case_dir

    # Check AIR_CASE_DIR env var
    env_dir = os.environ.get("AIR_CASE_DIR")
    if env_dir:
        return Path(env_dir)

    # Check .air/active_case pointer
    active_file = Path(".air") / "active_case"
    if active_file.exists():
        case_id = active_file.read_text().strip()
        cases_dir = Path(os.environ.get("AIR_CASES_DIR", "cases"))
        return cases_dir / case_id

    print("No active case. Use --case <id> or set AIR_CASE_DIR.", file=sys.stderr)
    sys.exit(1)


def load_findings(case_dir: Path) -> list[dict]:
    """Load findings from JSON store."""
    findings_file = case_dir / ".audit" / "findings.json"
    if not findings_file.exists():
        return []
    return json.loads(findings_file.read_text())


def save_findings(case_dir: Path, findings: list[dict]) -> None:
    """Save findings to JSON store and update FINDINGS.md."""
    with open(case_dir / ".audit" / "findings.json", "w") as f:
        json.dump(findings, f, indent=2, default=str)
    # TODO: regenerate FINDINGS.md from findings data


def load_timeline(case_dir: Path) -> list[dict]:
    """Load timeline events from JSON store."""
    timeline_file = case_dir / ".audit" / "timeline.json"
    if not timeline_file.exists():
        return []
    return json.loads(timeline_file.read_text())


def save_timeline(case_dir: Path, timeline: list[dict]) -> None:
    """Save timeline to JSON store."""
    with open(case_dir / ".audit" / "timeline.json", "w") as f:
        json.dump(timeline, f, indent=2, default=str)


def write_approval_log(case_dir: Path, item_id: str, action: str, identity: dict, reason: str = "") -> None:
    """Write approval/rejection record to approvals.jsonl."""
    log_file = case_dir / ".audit" / "approvals.jsonl"
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "item_id": item_id,
        "action": action,
        "os_user": identity["os_user"],
        "analyst": identity["analyst"],
        "analyst_source": identity["analyst_source"],
    }
    if reason:
        entry["reason"] = reason
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
