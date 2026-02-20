"""Shared case file I/O for CLI commands.

Multi-examiner aware: local data in .local/, team data in .team/{examiner}/.
Read operations can merge from all sources for unified views.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml


def _atomic_write(path: Path, content: str) -> None:
    """Write file atomically via temp file + rename to prevent data loss on crash."""
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


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


def get_examiner(case_dir: Path) -> str:
    """Get the examiner identity from CASE.yaml."""
    meta = load_case_meta(case_dir)
    return meta.get("examiner", os.environ.get("AIIR_EXAMINER", ""))


def load_case_meta(case_dir: Path) -> dict:
    """Load CASE.yaml metadata."""
    meta_file = case_dir / "CASE.yaml"
    if not meta_file.exists():
        return {}
    with open(meta_file) as f:
        return yaml.safe_load(f) or {}


# --- Local store I/O (this examiner only) ---

def load_findings(case_dir: Path) -> list[dict]:
    """Load findings from local .local/findings.json."""
    findings_file = case_dir / ".local" / "findings.json"
    if not findings_file.exists():
        return []
    return json.loads(findings_file.read_text())


def save_findings(case_dir: Path, findings: list[dict]) -> None:
    """Save findings to local store and regenerate merged FINDINGS.md."""
    local = case_dir / ".local"
    local.mkdir(parents=True, exist_ok=True)
    _atomic_write(
        local / "findings.json",
        json.dumps(findings, indent=2, default=str),
    )
    regenerate_findings_md(case_dir)


def load_timeline(case_dir: Path) -> list[dict]:
    """Load timeline events from local .local/timeline.json."""
    timeline_file = case_dir / ".local" / "timeline.json"
    if not timeline_file.exists():
        return []
    return json.loads(timeline_file.read_text())


def save_timeline(case_dir: Path, timeline: list[dict]) -> None:
    """Save timeline to local store and regenerate merged TIMELINE.md."""
    local = case_dir / ".local"
    local.mkdir(parents=True, exist_ok=True)
    _atomic_write(
        local / "timeline.json",
        json.dumps(timeline, indent=2, default=str),
    )
    regenerate_timeline_md(case_dir)


def load_todos(case_dir: Path) -> list[dict]:
    """Load TODO items from local .local/todos.json."""
    todos_file = case_dir / ".local" / "todos.json"
    if not todos_file.exists():
        return []
    return json.loads(todos_file.read_text())


def save_todos(case_dir: Path, todos: list[dict]) -> None:
    """Save TODO items to local store."""
    local = case_dir / ".local"
    local.mkdir(parents=True, exist_ok=True)
    _atomic_write(
        local / "todos.json",
        json.dumps(todos, indent=2, default=str),
    )


# --- Merged reads (local + team) ---

def load_all_findings(case_dir: Path) -> list[dict]:
    """Load findings from .local/ and all .team/*/, with scoped IDs."""
    examiner = get_examiner(case_dir)

    findings = load_findings(case_dir)
    for f in findings:
        f.setdefault("examiner", examiner)
        if examiner and "/" not in f.get("id", ""):
            f["id"] = f"{examiner}/{f['id']}"

    team_dir = case_dir / ".team"
    if team_dir.is_dir():
        for ex_dir in sorted(team_dir.iterdir()):
            if not ex_dir.is_dir():
                continue
            team_exam = ex_dir.name
            team_file = ex_dir / "findings.json"
            if team_file.exists():
                team_findings = json.loads(team_file.read_text())
                for f in team_findings:
                    f.setdefault("examiner", team_exam)
                    if "/" not in f.get("id", ""):
                        f["id"] = f"{team_exam}/{f['id']}"
                findings.extend(team_findings)

    return findings


def load_all_timeline(case_dir: Path) -> list[dict]:
    """Load timeline from .local/ and all .team/*/, sorted chronologically."""
    examiner = get_examiner(case_dir)

    timeline = load_timeline(case_dir)
    for t in timeline:
        t.setdefault("examiner", examiner)
        if examiner and "/" not in t.get("id", ""):
            t["id"] = f"{examiner}/{t['id']}"

    team_dir = case_dir / ".team"
    if team_dir.is_dir():
        for ex_dir in sorted(team_dir.iterdir()):
            if not ex_dir.is_dir():
                continue
            team_exam = ex_dir.name
            team_file = ex_dir / "timeline.json"
            if team_file.exists():
                team_timeline = json.loads(team_file.read_text())
                for t in team_timeline:
                    t.setdefault("examiner", team_exam)
                    if "/" not in t.get("id", ""):
                        t["id"] = f"{team_exam}/{t['id']}"
                timeline.extend(team_timeline)

    timeline.sort(key=lambda t: t.get("timestamp", ""))
    return timeline


def load_all_todos(case_dir: Path) -> list[dict]:
    """Load TODOs from .local/ and all .team/*/."""
    examiner = get_examiner(case_dir)

    todos = load_todos(case_dir)
    for t in todos:
        t.setdefault("examiner", examiner)
        if examiner and "/" not in t.get("todo_id", ""):
            t["todo_id"] = f"{examiner}/{t['todo_id']}"

    team_dir = case_dir / ".team"
    if team_dir.is_dir():
        for ex_dir in sorted(team_dir.iterdir()):
            if not ex_dir.is_dir():
                continue
            team_exam = ex_dir.name
            team_file = ex_dir / "todos.json"
            if team_file.exists():
                team_todos = json.loads(team_file.read_text())
                for t in team_todos:
                    t.setdefault("examiner", team_exam)
                    if "/" not in t.get("todo_id", ""):
                        t["todo_id"] = f"{team_exam}/{t['todo_id']}"
                todos.extend(team_todos)

    return todos


def load_all_approvals(case_dir: Path) -> list[dict]:
    """Load approvals from .local/ and all .team/*/."""
    approvals = load_approval_log(case_dir)

    team_dir = case_dir / ".team"
    if team_dir.is_dir():
        for ex_dir in sorted(team_dir.iterdir()):
            if not ex_dir.is_dir():
                continue
            approvals_file = ex_dir / "approvals.jsonl"
            if approvals_file.exists():
                for line in approvals_file.read_text().strip().split("\n"):
                    if line:
                        approvals.append(json.loads(line))

    approvals.sort(key=lambda a: a.get("ts", ""))
    return approvals


# --- Markdown generation (merged views) ---

def regenerate_findings_md(case_dir: Path) -> None:
    """Rewrite FINDINGS.md from all examiners' findings data."""
    findings = load_all_findings(case_dir)
    meta = load_case_meta(case_dir)
    case_id = meta.get("case_id", case_dir.name)

    lines = [f"# Findings — {case_id}\n\n"]
    for f in findings:
        status = f.get("status", "DRAFT")
        title = f.get("title", "Untitled")
        examiner = f.get("examiner", "")
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
        lines.append(f"**Examiner:** {examiner}\n")
        lines.append(f"**Confidence:** {f.get('confidence', 'UNSPECIFIED')}\n")
        lines.append(f"**Evidence:** {', '.join(f.get('evidence_ids', []))}\n\n")
        lines.append(f"### Observation\n{f.get('observation', '')}\n\n")
        lines.append(f"### Interpretation\n{f.get('interpretation', '')}\n\n")
        lines.append(f"### Confidence Justification\n{f.get('confidence_justification', '')}\n\n")
        lines.append(f"---\n*Staged: {f.get('staged', '')}*\n\n")
    _atomic_write(case_dir / "FINDINGS.md", "".join(lines))


def regenerate_timeline_md(case_dir: Path) -> None:
    """Rewrite TIMELINE.md from all examiners' timeline data."""
    timeline = load_all_timeline(case_dir)
    meta = load_case_meta(case_dir)
    case_id = meta.get("case_id", case_dir.name)

    lines = [f"# Timeline — {case_id}\n\n"]
    for ev in timeline:
        status = ev.get("status", "DRAFT")
        examiner = ev.get("examiner", "")
        lines.append(f"## {ev['id']}: {ev['timestamp']} [{status}]\n\n")
        lines.append(f"{ev.get('description', '')}\n\n")
        lines.append(f"**Examiner:** {examiner}\n")
        evidence = ", ".join(ev.get("evidence_ids", []))
        if evidence:
            lines.append(f"**Evidence:** {evidence}\n\n")
        if ev.get("source"):
            lines.append(f"**Source:** {ev['source']}\n\n")
        lines.append(f"---\n*Staged: {ev.get('staged', '')}*\n\n")
    _atomic_write(case_dir / "TIMELINE.md", "".join(lines))


# --- Approval I/O ---

def write_approval_log(
    case_dir: Path,
    item_id: str,
    action: str,
    identity: dict,
    reason: str = "",
    mode: str = "interactive",
) -> None:
    """Write approval/rejection record to .local/approvals.jsonl."""
    local = case_dir / ".local"
    local.mkdir(parents=True, exist_ok=True)
    log_file = local / "approvals.jsonl"
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
    """Load approval records from .local/approvals.jsonl."""
    log_file = case_dir / ".local" / "approvals.jsonl"
    if not log_file.exists():
        return []
    entries = []
    for line in log_file.read_text().strip().split("\n"):
        if line:
            entries.append(json.loads(line))
    return entries


# --- Item lookup ---

def find_draft_item(item_id: str, findings: list[dict], timeline: list[dict]) -> dict | None:
    """Find a DRAFT item by ID in findings or timeline.

    Supports both scoped (jane/F-001) and unscoped (F-001) IDs.
    """
    for f in findings:
        fid = f["id"]
        # Match exact ID or match the local part (after /)
        if (fid == item_id or fid.endswith(f"/{item_id}")) and f["status"] == "DRAFT":
            return f
    for t in timeline:
        tid = t["id"]
        if (tid == item_id or tid.endswith(f"/{item_id}")) and t["status"] == "DRAFT":
            return t
    return None


# --- Integrity verification ---

def verify_approval_integrity(case_dir: Path) -> list[dict]:
    """Cross-reference findings against approvals.

    Returns findings with an added 'verification' field:
    - 'confirmed': status matches an approval record
    - 'no approval record': APPROVED/REJECTED but no matching record
    - 'draft': still in DRAFT status
    """
    findings = load_all_findings(case_dir)
    approvals = load_all_approvals(case_dir)

    # Build lookup: item_id -> last approval record
    last_approval = {}
    for record in approvals:
        last_approval[record["item_id"]] = record

    results = []
    for f in findings:
        result = dict(f)
        status = f.get("status", "DRAFT")
        fid = f["id"]
        if status == "DRAFT":
            result["verification"] = "draft"
        elif fid in last_approval:
            record = last_approval[fid]
            if record["action"] == status:
                result["verification"] = "confirmed"
            else:
                result["verification"] = "no approval record"
        else:
            result["verification"] = "no approval record"
        results.append(result)
    return results


# --- Sync bundle I/O ---

def export_bundle(case_dir: Path) -> dict:
    """Export this examiner's contributions as a bundle dict."""
    meta = load_case_meta(case_dir)
    examiner = meta.get("examiner", "")
    local = case_dir / ".local"

    bundle = {
        "schema_version": 1,
        "case_id": meta.get("case_id", ""),
        "examiner": examiner,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "since": None,
    }

    bundle["findings"] = load_findings(case_dir)
    for f in bundle["findings"]:
        f.setdefault("examiner", examiner)

    bundle["timeline"] = load_timeline(case_dir)
    for t in bundle["timeline"]:
        t.setdefault("examiner", examiner)

    bundle["todos"] = load_todos(case_dir)

    actions_file = local / "actions.md"
    bundle["actions_md"] = actions_file.read_text() if actions_file.exists() else ""

    bundle["approvals"] = load_approval_log(case_dir)

    # Audit entries
    audit: dict[str, list] = {}
    audit_dir = local / "audit"
    if audit_dir.is_dir():
        for jsonl_file in audit_dir.glob("*.jsonl"):
            mcp_name = jsonl_file.stem
            entries = []
            for line in jsonl_file.read_text().strip().split("\n"):
                if line:
                    entries.append(json.loads(line))
            audit[mcp_name] = entries
    bundle["audit"] = audit

    # Evidence manifest
    evidence_file = local / "evidence.json"
    manifest = []
    if evidence_file.exists():
        registry = json.loads(evidence_file.read_text())
        for entry in registry.get("files", []):
            manifest.append({
                "sha256": entry["sha256"],
                "description": entry.get("description", ""),
                "examiner": examiner,
            })
    bundle["evidence_manifest"] = manifest

    return bundle


def import_bundle(case_dir: Path, bundle: dict) -> dict:
    """Import a contribution bundle from another examiner into .team/{examiner}/."""
    meta = load_case_meta(case_dir)
    bundle_examiner = bundle.get("examiner", "")

    if not bundle_examiner:
        return {"status": "error", "message": "Bundle missing examiner field"}
    if bundle_examiner == meta.get("examiner"):
        return {"status": "error", "message": "Cannot import your own contributions"}
    if bundle.get("case_id") != meta.get("case_id"):
        return {"status": "error", "message": "Case ID mismatch"}

    team_dir = case_dir / ".team" / bundle_examiner
    team_dir.mkdir(parents=True, exist_ok=True)
    (team_dir / "audit").mkdir(exist_ok=True)

    if "findings" in bundle:
        _atomic_write(team_dir / "findings.json", json.dumps(bundle["findings"], indent=2, default=str))
    if "timeline" in bundle:
        _atomic_write(team_dir / "timeline.json", json.dumps(bundle["timeline"], indent=2, default=str))
    if "todos" in bundle:
        _atomic_write(team_dir / "todos.json", json.dumps(bundle["todos"], indent=2, default=str))
    if bundle.get("actions_md"):
        (team_dir / "actions.md").write_text(bundle["actions_md"])
    if "approvals" in bundle:
        with open(team_dir / "approvals.jsonl", "w") as f:
            for entry in bundle["approvals"]:
                f.write(json.dumps(entry, default=str) + "\n")
    if "audit" in bundle:
        for mcp_name, entries in bundle["audit"].items():
            with open(team_dir / "audit" / f"{mcp_name}.jsonl", "w") as f:
                for entry in entries:
                    f.write(json.dumps(entry, default=str) + "\n")
    if "evidence_manifest" in bundle:
        _atomic_write(team_dir / "evidence_manifest.json", json.dumps(bundle["evidence_manifest"], indent=2, default=str))

    # Update team list
    if bundle_examiner not in meta.get("team", []):
        meta.setdefault("team", []).append(bundle_examiner)
        _atomic_write(case_dir / "CASE.yaml", yaml.dump(meta, default_flow_style=False))

    # Regenerate merged views
    regenerate_findings_md(case_dir)
    regenerate_timeline_md(case_dir)

    return {
        "status": "imported",
        "examiner": bundle_examiner,
        "findings": len(bundle.get("findings", [])),
        "timeline": len(bundle.get("timeline", [])),
    }
