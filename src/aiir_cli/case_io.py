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
        cases_dir = Path(os.environ.get("AIIR_CASES_DIR", "cases"))
        case_dir = cases_dir / case_id
        if not case_dir.exists():
            print(f"Case not found: {case_id}", file=sys.stderr)
            sys.exit(1)
        return case_dir

    # Check AIIR_CASE_DIR env var
    env_dir = os.environ.get("AIIR_CASE_DIR")
    if env_dir:
        return Path(env_dir)

    # Check .aiir/active_case pointer
    active_file = Path(".aiir") / "active_case"
    if active_file.exists():
        case_id = active_file.read_text().strip()
        cases_dir = Path(os.environ.get("AIIR_CASES_DIR", "cases"))
        return cases_dir / case_id

    print("No active case. Use --case <id> or set AIIR_CASE_DIR.", file=sys.stderr)
    sys.exit(1)


def load_findings(case_dir: Path) -> list[dict]:
    """Load findings from JSON store."""
    findings_file = case_dir / ".audit" / "findings.json"
    if not findings_file.exists():
        return []
    return json.loads(findings_file.read_text())


def save_findings(case_dir: Path, findings: list[dict]) -> None:
    """Save findings to JSON store and regenerate FINDINGS.md."""
    with open(case_dir / ".audit" / "findings.json", "w") as f:
        json.dump(findings, f, indent=2, default=str)
    regenerate_findings_md(case_dir, findings)


def regenerate_findings_md(case_dir: Path, findings: list[dict]) -> None:
    """Rewrite FINDINGS.md from findings data with current statuses."""
    case_id = case_dir.name
    lines = [f"# Findings — {case_id}\n\n"]
    for f in findings:
        status = f.get("status", "DRAFT")
        title = f.get("title", "Untitled")
        lines.append(f"## {f['id']}: {title} [{status}]\n\n")
        if status == "DRAFT":
            lines.append("**Status:** DRAFT — awaiting human approval\n")
        elif status == "APPROVED":
            approved_at = f.get("approved_at", "")
            approved_by = f.get("approved_by", "")
            lines.append(f"**Status:** APPROVED by {approved_by} at {approved_at}\n")
        elif status == "REJECTED":
            rejected_at = f.get("rejected_at", "")
            rejected_by = f.get("rejected_by", "")
            reason = f.get("rejection_reason", "")
            lines.append(f"**Status:** REJECTED by {rejected_by} at {rejected_at}")
            if reason:
                lines.append(f", reason: {reason}")
            lines.append("\n")
        lines.append(f"**Confidence:** {f.get('confidence', 'UNSPECIFIED')}\n")
        lines.append(f"**Evidence:** {', '.join(f.get('evidence_ids', []))}\n\n")
        lines.append(f"### Observation\n{f.get('observation', '')}\n\n")
        lines.append(f"### Interpretation\n{f.get('interpretation', '')}\n\n")
        lines.append(f"### Confidence Justification\n{f.get('confidence_justification', '')}\n\n")
        lines.append(f"---\n*Staged: {f.get('staged', '')}*\n\n")
    with open(case_dir / "FINDINGS.md", "w") as fp:
        fp.write("".join(lines))


def load_timeline(case_dir: Path) -> list[dict]:
    """Load timeline events from JSON store."""
    timeline_file = case_dir / ".audit" / "timeline.json"
    if not timeline_file.exists():
        return []
    return json.loads(timeline_file.read_text())


def save_timeline(case_dir: Path, timeline: list[dict]) -> None:
    """Save timeline to JSON store and regenerate TIMELINE.md."""
    with open(case_dir / ".audit" / "timeline.json", "w") as f:
        json.dump(timeline, f, indent=2, default=str)
    regenerate_timeline_md(case_dir, timeline)


def regenerate_timeline_md(case_dir: Path, timeline: list[dict]) -> None:
    """Rewrite TIMELINE.md from timeline data with current statuses."""
    case_id = case_dir.name
    lines = [f"# Timeline — {case_id}\n\n"]
    for ev in timeline:
        status = ev.get("status", "DRAFT")
        lines.append(f"## {ev['id']}: {ev['timestamp']} [{status}]\n\n")
        lines.append(f"{ev.get('description', '')}\n\n")
        evidence = ", ".join(ev.get("evidence_ids", []))
        if evidence:
            lines.append(f"**Evidence:** {evidence}\n\n")
        if ev.get("source"):
            lines.append(f"**Source:** {ev['source']}\n\n")
        lines.append(f"---\n*Staged: {ev.get('staged', '')}*\n\n")
    with open(case_dir / "TIMELINE.md", "w") as fp:
        fp.write("".join(lines))


def write_approval_log(
    case_dir: Path,
    item_id: str,
    action: str,
    identity: dict,
    reason: str = "",
    mode: str = "interactive",
) -> None:
    """Write approval/rejection record to approvals.jsonl."""
    log_file = case_dir / ".audit" / "approvals.jsonl"
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "item_id": item_id,
        "action": action,
        "os_user": identity["os_user"],
        "analyst": identity["analyst"],
        "analyst_source": identity["analyst_source"],
        "mode": mode,
    }
    if reason:
        entry["reason"] = reason
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def load_approval_log(case_dir: Path) -> list[dict]:
    """Load all approval records from approvals.jsonl."""
    log_file = case_dir / ".audit" / "approvals.jsonl"
    if not log_file.exists():
        return []
    entries = []
    for line in log_file.read_text().strip().split("\n"):
        if line:
            entries.append(json.loads(line))
    return entries


def load_todos(case_dir: Path) -> list[dict]:
    """Load TODO items from JSON store."""
    todos_file = case_dir / ".audit" / "todos.json"
    if not todos_file.exists():
        return []
    return json.loads(todos_file.read_text())


def save_todos(case_dir: Path, todos: list[dict]) -> None:
    """Save TODO items to JSON store."""
    with open(case_dir / ".audit" / "todos.json", "w") as f:
        json.dump(todos, f, indent=2, default=str)


def find_draft_item(item_id: str, findings: list[dict], timeline: list[dict]) -> dict | None:
    """Find a DRAFT item by ID in findings or timeline."""
    for f in findings:
        if f["id"] == item_id and f["status"] == "DRAFT":
            return f
    for t in timeline:
        if t["id"] == item_id and t["status"] == "DRAFT":
            return t
    return None


def verify_approval_integrity(case_dir: Path) -> list[dict]:
    """Cross-reference findings.json against approvals.jsonl.

    Returns a list of finding dicts with an added 'verification' field:
    - 'confirmed': status matches an approval record
    - 'no approval record': APPROVED/REJECTED but no matching record
    - 'draft': still in DRAFT status (no check needed)
    """
    findings = load_findings(case_dir)
    approvals = load_approval_log(case_dir)

    # Build lookup: item_id -> last approval record
    last_approval = {}
    for record in approvals:
        last_approval[record["item_id"]] = record

    results = []
    for f in findings:
        result = dict(f)
        status = f.get("status", "DRAFT")
        if status == "DRAFT":
            result["verification"] = "draft"
        elif f["id"] in last_approval:
            record = last_approval[f["id"]]
            if record["action"] == status:
                result["verification"] = "confirmed"
            else:
                result["verification"] = "no approval record"
        else:
            result["verification"] = "no approval record"
        results.append(result)
    return results
